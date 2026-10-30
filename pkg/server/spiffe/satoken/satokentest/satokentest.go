// Package satokentest mints projected ServiceAccount tokens for tests, the way a
// spoke's token issuer would.
package satokentest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

// Issuer is a spoke token issuer with one ES256 key.
type Issuer struct {
	URL string
	Key *ecdsa.PrivateKey
	KID string
}

// New returns an issuer for url with a fresh key.
func New(url string) *Issuer {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Issuer{URL: url, Key: key, KID: "key-1"}
}

// JWKS returns the issuer's public key set.
func (i *Issuer) JWKS() []byte {
	x, y := make([]byte, 32), make([]byte, 32)
	i.Key.X.FillBytes(x)
	i.Key.Y.FillBytes(y)
	data, _ := json.Marshal(map[string]interface{}{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": i.KID, "use": "sig", "alg": "ES256",
		"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y),
	}}})
	return data
}

// Claims describe a token. Zero values get sensible defaults.
type Claims struct {
	Audience  []string
	Namespace string
	Name      string
	UID       string
	// NoPod leaves out the pod claim, like a token from the TokenRequest API
	// without a bound object.
	NoPod    bool
	IssuedAt time.Time
	Lifetime time.Duration
	// Mutate edits the payload before signing, for negative tests.
	Mutate func(map[string]interface{})
}

// Token returns a signed token.
func (i *Issuer) Token(c Claims) string {
	if c.Namespace == "" {
		c.Namespace = "open-cluster-management-agent"
	}
	if c.Name == "" {
		c.Name = "klusterlet-registration-sa"
	}
	if c.UID == "" {
		c.UID = "sa-uid-1"
	}
	if c.IssuedAt.IsZero() {
		c.IssuedAt = time.Now()
	}
	if c.Lifetime == 0 {
		c.Lifetime = 10 * time.Minute
	}
	k8s := map[string]interface{}{
		"namespace":      c.Namespace,
		"serviceaccount": map[string]string{"name": c.Name, "uid": c.UID},
	}
	if !c.NoPod {
		k8s["pod"] = map[string]string{"name": c.Name + "-pod", "uid": "pod-uid-1"}
	}
	payload := map[string]interface{}{
		"iss":           i.URL,
		"sub":           "system:serviceaccount:" + c.Namespace + ":" + c.Name,
		"aud":           c.Audience,
		"iat":           c.IssuedAt.Unix(),
		"nbf":           c.IssuedAt.Unix(),
		"exp":           c.IssuedAt.Add(c.Lifetime).Unix(),
		"kubernetes.io": k8s,
	}
	if c.Mutate != nil {
		c.Mutate(payload)
	}
	return i.Sign(map[string]interface{}{"alg": "ES256", "kid": i.KID, "typ": "JWT"}, payload)
}

// Sign signs any header and payload with the issuer's key using ES256.
func (i *Issuer) Sign(header, payload map[string]interface{}) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	signed := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, i.Key, digest[:])
	if err != nil {
		panic(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}
