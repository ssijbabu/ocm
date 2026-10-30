// Package azurekeyvault signs with a hub CA key held in Azure Key Vault.
//
// The hub CA is a Key Vault certificate whose key is non-exportable (key type
// EC-HSM on Key Vault Premium). The signer reads the certificate, follows its
// key identifier to the exact key version, and calls keys/sign with digests
// only, so the key never leaves Key Vault.
package azurekeyvault

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/internal/rest"
)

const apiVersion = "7.5"

// TokenSource returns an access token for https://vault.azure.net.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Options configures the Azure Key Vault signer.
type Options struct {
	// VaultURL is the vault's URL, for example https://my-vault.vault.azure.net.
	VaultURL string
	// CertificateName is the Key Vault certificate holding the hub CA. Its key
	// has the same name.
	CertificateName string
	// TokenSource authenticates to Key Vault, normally through workload identity.
	TokenSource TokenSource
	// HTTPClient defaults to a client with a 30 second timeout.
	HTTPClient *http.Client
}

// Signer reads the hub CA certificate from Key Vault and signs with its key.
type Signer struct {
	vault  *url.URL
	name   string
	tokens TokenSource
	client *http.Client
}

var _ signer.Signer = &Signer{}

// New validates opts and returns a Signer.
func New(opts Options) (*Signer, error) {
	vault, err := url.Parse(strings.TrimSuffix(opts.VaultURL, "/"))
	if err != nil || vault.Scheme != "https" || vault.Host == "" {
		return nil, fmt.Errorf("vault URL %q must be an https URL such as https://my-vault.vault.azure.net", opts.VaultURL)
	}
	if opts.CertificateName == "" {
		return nil, fmt.Errorf("the Key Vault certificate name of the hub CA is required")
	}
	if opts.TokenSource == nil {
		return nil, fmt.Errorf("a token source is required")
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Signer{vault: vault, name: opts.CertificateName, tokens: opts.TokenSource, client: client}, nil
}

type certificateBundle struct {
	// Kid identifies the key version paired with this certificate version.
	Kid string `json:"kid"`
	// Cer is the DER certificate, standard base64.
	Cer string `json:"cer"`
}

type keyBundle struct {
	Key struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"key"`
}

type signRequest struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

type signResponse struct {
	Value string `json:"value"`
}

// certificateVersions is one page of a certificate's versions.
type certificateVersions struct {
	Value []struct {
		// ID is the certificate version's URL.
		ID string `json:"id"`
		// X5t is the certificate's SHA-1 thumbprint, base64url.
		X5t string `json:"x5t"`
	} `json:"value"`
	NextLink string `json:"nextLink"`
}

// maxVersionPages bounds the version listing.
const maxVersionPages = 20

func (s *Signer) Current(ctx context.Context) (*signer.CA, error) {
	var bundle certificateBundle
	if err := s.get(ctx, s.vault.String()+"/certificates/"+url.PathEscape(s.name), &bundle); err != nil {
		return nil, fmt.Errorf("failed to read hub CA certificate %q from Key Vault: %w", s.name, err)
	}
	return s.caFor(ctx, bundle)
}

// ForCertificate finds the version of the Key Vault certificate that holds
// cert and signs with its key version, which stays enabled after a new
// version is created.
func (s *Signer) ForCertificate(ctx context.Context, cert *x509.Certificate) (*signer.CA, error) {
	sum := sha1.Sum(cert.Raw) //nolint:gosec // Key Vault identifies certificates by SHA-1 thumbprint
	thumbprint := base64.RawURLEncoding.EncodeToString(sum[:])
	next := s.vault.String() + "/certificates/" + url.PathEscape(s.name) + "/versions?api-version=" + apiVersion
	for page := 0; next != "" && page < maxVersionPages; page++ {
		if err := s.inVault(next); err != nil {
			return nil, err
		}
		var versions certificateVersions
		if err := s.getURL(ctx, next, &versions); err != nil {
			return nil, fmt.Errorf("failed to list the versions of hub CA certificate %q in Key Vault: %w", s.name, err)
		}
		for _, v := range versions.Value {
			if strings.TrimRight(v.X5t, "=") != thumbprint {
				continue
			}
			if err := s.inVault(v.ID); err != nil {
				return nil, err
			}
			var bundle certificateBundle
			if err := s.get(ctx, v.ID, &bundle); err != nil {
				return nil, fmt.Errorf("failed to read hub CA certificate version %s from Key Vault: %w", v.ID, err)
			}
			ca, err := s.caFor(ctx, bundle)
			if err != nil {
				return nil, err
			}
			if !ca.Certificate.Equal(cert) {
				return nil, fmt.Errorf("hub CA certificate version %s does not hold the expected certificate", v.ID)
			}
			return ca, nil
		}
		next = versions.NextLink
	}
	return nil, fmt.Errorf("hub CA certificate %q is not a version of Key Vault certificate %q", cert.Subject.String(), s.name)
}

// inVault refuses URLs outside the vault, so the access token is never sent
// elsewhere.
func (s *Signer) inVault(resource string) error {
	u, err := url.Parse(resource)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, s.vault.Host) {
		return fmt.Errorf("Key Vault returned a URL outside %s: %q", s.vault.Host, resource)
	}
	return nil
}

// caFor pairs a certificate version with the key version it names.
func (s *Signer) caFor(ctx context.Context, bundle certificateBundle) (*signer.CA, error) {
	der, err := base64.StdEncoding.DecodeString(bundle.Cer)
	if err != nil {
		return nil, fmt.Errorf("hub CA certificate %q has invalid cer data: %w", s.name, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("hub CA certificate %q cannot be parsed: %w", s.name, err)
	}

	keyURL, err := s.keyVersionURL(bundle.Kid)
	if err != nil {
		return nil, err
	}

	var key keyBundle
	if err := s.get(ctx, keyURL, &key); err != nil {
		return nil, fmt.Errorf("failed to read hub CA key %s from Key Vault: %w", keyURL, err)
	}
	pub, alg, err := ecPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("hub CA key %s: %w", keyURL, err)
	}

	return signer.NewCA(cert, pub, func(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
		if err := signer.CheckDigest(pub, digest, opts); err != nil {
			return nil, err
		}
		body, err := rest.JSONBody(signRequest{Alg: alg, Value: base64.RawURLEncoding.EncodeToString(digest)})
		if err != nil {
			return nil, err
		}
		token, err := s.tokens.Token(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get a Key Vault access token: %w", err)
		}
		var resp signResponse
		if err := rest.Do(ctx, s.client, http.MethodPost, keyURL+"/sign?api-version="+apiVersion,
			map[string]string{"Authorization": "Bearer " + token}, body, &resp); err != nil {
			return nil, fmt.Errorf("failed to sign with the hub CA key in Key Vault: %w", err)
		}
		raw, err := decodeBase64URL(resp.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid signature from Key Vault: %w", err)
		}
		return signer.ECDSARawToASN1(raw)
	})
}

// keyVersionURL checks that kid points at a versioned key in this vault, so a
// tampered certificate cannot redirect signing requests elsewhere.
func (s *Signer) keyVersionURL(kid string) (string, error) {
	u, err := url.Parse(kid)
	if err != nil {
		return "", fmt.Errorf("hub CA certificate has an invalid key identifier %q: %w", kid, err)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if u.Scheme != "https" || !strings.EqualFold(u.Host, s.vault.Host) || len(parts) != 3 || parts[0] != "keys" || parts[1] == "" || parts[2] == "" {
		return "", fmt.Errorf("hub CA certificate key identifier %q must be a versioned key in %s", kid, s.vault.Host)
	}
	return s.vault.String() + "/keys/" + url.PathEscape(parts[1]) + "/" + url.PathEscape(parts[2]), nil
}

func (s *Signer) get(ctx context.Context, resource string, out interface{}) error {
	return s.getURL(ctx, resource+"?api-version="+apiVersion, out)
}

// getURL fetches a URL that already carries its query, such as a nextLink.
func (s *Signer) getURL(ctx context.Context, resource string, out interface{}) error {
	token, err := s.tokens.Token(ctx)
	if err != nil {
		return fmt.Errorf("failed to get a Key Vault access token: %w", err)
	}
	return rest.Do(ctx, s.client, http.MethodGet, resource,
		map[string]string{"Authorization": "Bearer " + token}, nil, out)
}

func ecPublicKey(key keyBundle) (*ecdsa.PublicKey, string, error) {
	if key.Key.Kty != "EC" && key.Key.Kty != "EC-HSM" {
		return nil, "", fmt.Errorf("key type %q is not supported, use EC-HSM", key.Key.Kty)
	}
	var curve elliptic.Curve
	var alg string
	switch key.Key.Crv {
	case "P-256":
		curve, alg = elliptic.P256(), "ES256"
	case "P-384":
		curve, alg = elliptic.P384(), "ES384"
	default:
		return nil, "", fmt.Errorf("curve %q is not supported, use P-256 or P-384", key.Key.Crv)
	}
	x, err := decodeBase64URL(key.Key.X)
	if err != nil {
		return nil, "", fmt.Errorf("invalid x coordinate: %w", err)
	}
	y, err := decodeBase64URL(key.Key.Y)
	if err != nil {
		return nil, "", fmt.Errorf("invalid y coordinate: %w", err)
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if _, err := pub.ECDH(); err != nil {
		return nil, "", fmt.Errorf("public key is not a valid %s point: %w", key.Key.Crv, err)
	}
	return pub, alg, nil
}

// decodeBase64URL accepts base64url with or without padding, as Key Vault
// documents the unpadded form but some responses include padding.
func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}
