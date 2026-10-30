// Package satoken verifies a spoke agent's projected ServiceAccount token
// against the spoke's token issuer, as recorded when the hub admin accepted
// the spoke.
//
// Only the JWS algorithms Kubernetes issuers use are accepted (RS256, ES256,
// ES384), and only pod-bound tokens with a short lifetime.
package satoken

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	// maxTokenSize bounds what is parsed from an unauthenticated caller.
	maxTokenSize = 16 * 1024
	// DefaultMaxLifetime rejects long-lived tokens: spoke agents use
	// 10-minute projected tokens.
	DefaultMaxLifetime = 15 * time.Minute
	leeway             = time.Minute
)

// KeySet returns the issuer's public key for a key ID.
type KeySet interface {
	Key(ctx context.Context, kid string) (crypto.PublicKey, error)
}

// Claims are the verified claims of a projected ServiceAccount token.
type Claims struct {
	Issuer             string
	Subject            string
	Audience           []string
	IssuedAt           time.Time
	Expiry             time.Time
	Namespace          string
	ServiceAccountName string
	ServiceAccountUID  string
	PodName            string
	PodUID             string
}

// VerifyOptions say what a valid token looks like.
type VerifyOptions struct {
	Issuer   string
	Audience string
	Keys     KeySet
	Now      time.Time
	// MaxLifetime defaults to DefaultMaxLifetime.
	MaxLifetime time.Duration
}

type header struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Crit []string `json:"crit"`
}

type payload struct {
	Iss        string          `json:"iss"`
	Sub        string          `json:"sub"`
	Aud        json.RawMessage `json:"aud"`
	Exp        *json.Number    `json:"exp"`
	Nbf        *json.Number    `json:"nbf"`
	Iat        *json.Number    `json:"iat"`
	Kubernetes *struct {
		Namespace      string `json:"namespace"`
		ServiceAccount *struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
		Pod *struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"pod"`
	} `json:"kubernetes.io"`
}

// Verify checks the token's signature, issuer, audience, validity, lifetime
// and that it is bound to a pod, and returns its claims.
func Verify(ctx context.Context, token string, opts VerifyOptions) (*Claims, error) {
	if len(token) > maxTokenSize {
		return nil, fmt.Errorf("token is larger than %d bytes", maxTokenSize)
	}
	if opts.Keys == nil || opts.Issuer == "" || opts.Audience == "" {
		return nil, fmt.Errorf("issuer, audience and keys are required to verify a token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token is not a compact JWS")
	}

	var h header
	if err := decodeSegment(parts[0], &h); err != nil {
		return nil, fmt.Errorf("invalid token header: %w", err)
	}
	if len(h.Crit) > 0 {
		return nil, fmt.Errorf("token uses unsupported critical header parameters %v", h.Crit)
	}
	key, err := opts.Keys.Key(ctx, h.Kid)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid token signature encoding: %w", err)
	}
	if err := verifySignature(h.Alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, err
	}

	var p payload
	if err := decodeSegment(parts[1], &p); err != nil {
		return nil, fmt.Errorf("invalid token payload: %w", err)
	}
	return checkClaims(&p, opts)
}

func checkClaims(p *payload, opts VerifyOptions) (*Claims, error) {
	if p.Iss != opts.Issuer {
		return nil, fmt.Errorf("token issuer %q is not the bound issuer %q", p.Iss, opts.Issuer)
	}
	aud, err := audiences(p.Aud)
	if err != nil {
		return nil, err
	}
	found := false
	for _, a := range aud {
		if a == opts.Audience {
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("token audience %v does not include %q", aud, opts.Audience)
	}

	exp, err := unixTime(p.Exp, "exp")
	if err != nil {
		return nil, err
	}
	iat, err := unixTime(p.Iat, "iat")
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if !now.Before(exp.Add(leeway)) {
		return nil, fmt.Errorf("token expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if now.Add(leeway).Before(iat) {
		return nil, fmt.Errorf("token issued in the future")
	}
	if p.Nbf != nil {
		nbf, err := unixTime(p.Nbf, "nbf")
		if err != nil {
			return nil, err
		}
		if now.Add(leeway).Before(nbf) {
			return nil, fmt.Errorf("token not valid before %s", nbf.UTC().Format(time.RFC3339))
		}
	}
	maxLifetime := opts.MaxLifetime
	if maxLifetime == 0 {
		maxLifetime = DefaultMaxLifetime
	}
	if exp.Sub(iat) > maxLifetime {
		return nil, fmt.Errorf("token lifetime %s exceeds %s; use a short-lived projected token", exp.Sub(iat), maxLifetime)
	}

	k := p.Kubernetes
	if k == nil || k.ServiceAccount == nil || k.Namespace == "" || k.ServiceAccount.Name == "" || k.ServiceAccount.UID == "" {
		return nil, fmt.Errorf("token is not a Kubernetes ServiceAccount token")
	}
	if k.Pod == nil || k.Pod.Name == "" || k.Pod.UID == "" {
		return nil, fmt.Errorf("token is not bound to a pod")
	}
	if want := "system:serviceaccount:" + k.Namespace + ":" + k.ServiceAccount.Name; p.Sub != want {
		return nil, fmt.Errorf("token subject %q does not match its ServiceAccount claims", p.Sub)
	}

	return &Claims{
		Issuer:             p.Iss,
		Subject:            p.Sub,
		Audience:           aud,
		IssuedAt:           iat,
		Expiry:             exp,
		Namespace:          k.Namespace,
		ServiceAccountName: k.ServiceAccount.Name,
		ServiceAccountUID:  k.ServiceAccount.UID,
		PodName:            k.Pod.Name,
		PodUID:             k.Pod.UID,
	}, nil
}

func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
	switch alg {
	case "RS256":
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("token algorithm RS256 does not match the issuer key type %T", key)
		}
		digest := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("token signature is invalid")
		}
		return nil
	case "ES256", "ES384":
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("token algorithm %s does not match the issuer key type %T", alg, key)
		}
		size, wantCurve := 32, "P-256"
		var digest []byte
		if alg == "ES256" {
			d := sha256.Sum256(signed)
			digest = d[:]
		} else {
			size, wantCurve = 48, "P-384"
			d := sha512.Sum384(signed)
			digest = d[:]
		}
		if pub.Curve.Params().Name != wantCurve || len(sig) != 2*size {
			return fmt.Errorf("token signature is invalid")
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return fmt.Errorf("token signature is invalid")
		}
		return nil
	default:
		return fmt.Errorf("token algorithm %q is not accepted", alg)
	}
}

func decodeSegment(seg string, out interface{}) error {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	return dec.Decode(out)
}

func audiences(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("token has no audience")
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("token audience is invalid")
	}
	return many, nil
}

func unixTime(n *json.Number, name string) (time.Time, error) {
	if n == nil {
		return time.Time{}, fmt.Errorf("token has no %s claim", name)
	}
	v, err := n.Int64()
	if err != nil {
		f, ferr := n.Float64()
		if ferr != nil {
			return time.Time{}, fmt.Errorf("token %s claim is not a number", name)
		}
		v = int64(f)
	}
	return time.Unix(v, 0), nil
}
