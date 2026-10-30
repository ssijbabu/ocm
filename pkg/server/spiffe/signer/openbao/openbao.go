// Package openbao signs with a hub CA key held in the OpenBao transit engine.
//
// The transit key must be non-exportable and must not allow plaintext backup,
// so the hub CA key never leaves OpenBao. Transit does not store certificates,
// so the hub CA certificate is kept in a KV v2 secret; the signer pairs it with
// the transit key version whose public key matches.
package openbao

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/internal/rest"
)

// TokenSource returns an OpenBao client token.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Options configures the OpenBao signer.
type Options struct {
	// Address is the OpenBao server, for example https://openbao.example.com:8200.
	Address string
	// Namespace is the OpenBao namespace, if namespaces are used.
	Namespace string
	// TransitMount is where the transit engine is mounted. Defaults to "transit".
	TransitMount string
	// KeyName is the transit key holding the hub CA key.
	KeyName string
	// CertificatePath is the KV v2 API path of the secret holding the hub CA
	// certificate in its "certificate" field as PEM, for example
	// "secret/data/ocm/spiffe-ca".
	CertificatePath string
	// TokenSource authenticates to OpenBao, normally with the Kubernetes auth method.
	TokenSource TokenSource
	// HTTPClient defaults to a client with a 30 second timeout.
	HTTPClient *http.Client
}

// Signer reads the hub CA certificate from KV and signs with a transit key.
type Signer struct {
	address      string
	namespace    string
	transitMount string
	keyName      string
	certPath     string
	tokens       TokenSource
	client       *http.Client
}

var _ signer.Signer = &Signer{}

// New validates opts and returns a Signer.
func New(opts Options) (*Signer, error) {
	addr, err := validateAddress(opts.Address)
	if err != nil {
		return nil, err
	}
	if opts.KeyName == "" {
		return nil, fmt.Errorf("the transit key name of the hub CA is required")
	}
	if opts.CertificatePath == "" {
		return nil, fmt.Errorf("the KV path of the hub CA certificate is required")
	}
	if opts.TokenSource == nil {
		return nil, fmt.Errorf("a token source is required")
	}
	mount := strings.Trim(opts.TransitMount, "/")
	if mount == "" {
		mount = "transit"
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Signer{
		address:      addr,
		namespace:    opts.Namespace,
		transitMount: mount,
		keyName:      opts.KeyName,
		certPath:     strings.Trim(opts.CertificatePath, "/"),
		tokens:       opts.TokenSource,
		client:       client,
	}, nil
}

type kvResponse struct {
	Data struct {
		Data map[string]interface{} `json:"data"`
	} `json:"data"`
}

type transitKeyResponse struct {
	Data struct {
		Type                 string                       `json:"type"`
		Exportable           bool                         `json:"exportable"`
		AllowPlaintextBackup bool                         `json:"allow_plaintext_backup"`
		Keys                 map[string]transitKeyVersion `json:"keys"`
	} `json:"data"`
}

type transitKeyVersion struct {
	PublicKey string `json:"public_key"`
}

type signRequest struct {
	Input               string `json:"input"`
	Prehashed           bool   `json:"prehashed"`
	KeyVersion          int    `json:"key_version"`
	MarshalingAlgorithm string `json:"marshaling_algorithm"`
}

type signResponse struct {
	Data struct {
		Signature string `json:"signature"`
	} `json:"data"`
}

func (s *Signer) Current(ctx context.Context) (*signer.CA, error) {
	cert, err := s.readCertificate(ctx)
	if err != nil {
		return nil, err
	}

	var key transitKeyResponse
	if err := s.do(ctx, http.MethodGet, s.transitMount+"/keys/"+url.PathEscape(s.keyName), nil, &key); err != nil {
		return nil, fmt.Errorf("failed to read transit key %q: %w", s.keyName, err)
	}
	if key.Data.Exportable || key.Data.AllowPlaintextBackup {
		return nil, fmt.Errorf("transit key %q is exportable or allows plaintext backup; the hub CA key must never leave OpenBao", s.keyName)
	}
	if key.Data.Type != "ecdsa-p256" && key.Data.Type != "ecdsa-p384" {
		return nil, fmt.Errorf("transit key %q has type %q, use ecdsa-p256 or ecdsa-p384", s.keyName, key.Data.Type)
	}

	version, pub, err := matchingVersion(key.Data.Keys, cert)
	if err != nil {
		return nil, fmt.Errorf("transit key %q: %w", s.keyName, err)
	}
	hash, err := signer.HashForKey(pub)
	if err != nil {
		return nil, err
	}
	hashAlgorithm := map[crypto.Hash]string{crypto.SHA256: "sha2-256", crypto.SHA384: "sha2-384"}[hash]

	return signer.NewCA(cert, pub, func(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
		if err := signer.CheckDigest(pub, digest, opts); err != nil {
			return nil, err
		}
		body, err := rest.JSONBody(signRequest{
			Input:               base64.StdEncoding.EncodeToString(digest),
			Prehashed:           true,
			KeyVersion:          version,
			MarshalingAlgorithm: "asn1",
		})
		if err != nil {
			return nil, err
		}
		var resp signResponse
		if err := s.do(ctx, http.MethodPost, s.transitMount+"/sign/"+url.PathEscape(s.keyName)+"/"+hashAlgorithm, body, &resp); err != nil {
			return nil, fmt.Errorf("failed to sign with the hub CA transit key: %w", err)
		}
		return parseSignature(resp.Data.Signature, version)
	})
}

func (s *Signer) readCertificate(ctx context.Context) (*x509.Certificate, error) {
	var kv kvResponse
	if err := s.do(ctx, http.MethodGet, s.certPath, nil, &kv); err != nil {
		return nil, fmt.Errorf("failed to read the hub CA certificate from %q: %w", s.certPath, err)
	}
	certPEM, _ := kv.Data.Data["certificate"].(string)
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("secret %q has no PEM certificate in its \"certificate\" field", s.certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("hub CA certificate in %q cannot be parsed: %w", s.certPath, err)
	}
	return cert, nil
}

// matchingVersion finds the transit key version whose public key is in cert,
// preferring the newest if a key was somehow re-imported under two versions.
func matchingVersion(keys map[string]transitKeyVersion, cert *x509.Certificate) (int, crypto.PublicKey, error) {
	versions := make([]int, 0, len(keys))
	for v := range keys {
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, nil, fmt.Errorf("unexpected key version %q", v)
		}
		versions = append(versions, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(versions)))

	certPub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return 0, nil, fmt.Errorf("hub CA certificate has an unsupported key type %T", cert.PublicKey)
	}
	for _, v := range versions {
		block, _ := pem.Decode([]byte(keys[strconv.Itoa(v)].PublicKey))
		if block == nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		if certPub.Equal(pub) {
			return v, pub, nil
		}
	}
	return 0, nil, fmt.Errorf("no key version matches the hub CA certificate's public key")
}

// parseSignature decodes transit's "vault:v<N>:<base64>" format and checks the
// signature came from the expected key version.
func parseSignature(sig string, version int) ([]byte, error) {
	prefix := "vault:v" + strconv.Itoa(version) + ":"
	if !strings.HasPrefix(sig, prefix) {
		return nil, fmt.Errorf("transit signature %q is not from key version %d", truncate(sig), version)
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(sig, prefix))
	if err != nil {
		return nil, fmt.Errorf("transit signature is not valid base64: %w", err)
	}
	return der, nil
}

func (s *Signer) do(ctx context.Context, method, path string, body io.Reader, out interface{}) error {
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("failed to get an OpenBao token: %w", err)
	}
	headers := map[string]string{"X-Vault-Token": token}
	if s.namespace != "" {
		headers["X-Vault-Namespace"] = s.namespace
	}
	return rest.Do(ctx, s.client, method, s.address+"/v1/"+path, headers, body, out)
}

func validateAddress(address string) (string, error) {
	u, err := url.Parse(strings.TrimSuffix(address, "/"))
	// https only: the client token travels in every request.
	if err != nil || u.Host == "" || u.Scheme != "https" {
		return "", fmt.Errorf("address %q must be an https URL such as https://openbao.example.com:8200", address)
	}
	return u.String(), nil
}

func truncate(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}
