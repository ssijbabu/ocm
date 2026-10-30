package satoken

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	testtoken "open-cluster-management.io/ocm/pkg/server/spiffe/satoken/satokentest"
)

const (
	issuerURL = "https://spoke1.example.org"
	audience  = "open-cluster-management.io/hub1"
)

func verify(t *testing.T, iss *testtoken.Issuer, token string) (*Claims, error) {
	t.Helper()
	keys, err := ParseJWKS(iss.JWKS())
	if err != nil {
		t.Fatal(err)
	}
	return Verify(context.Background(), token, VerifyOptions{Issuer: issuerURL, Audience: audience, Keys: keys, Now: time.Now()})
}

func TestVerify(t *testing.T) {
	iss := testtoken.New(issuerURL)
	other := testtoken.New(issuerURL)
	aud := []string{audience}

	claims, err := verify(t, iss, iss.Token(testtoken.Claims{Audience: aud}))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Namespace != "open-cluster-management-agent" || claims.ServiceAccountName != "klusterlet-registration-sa" ||
		claims.ServiceAccountUID != "sa-uid-1" || claims.PodName == "" || claims.PodUID == "" {
		t.Errorf("unexpected claims %+v", claims)
	}

	cases := map[string]string{
		"other hub audience":  iss.Token(testtoken.Claims{Audience: []string{"open-cluster-management.io/hub2"}}),
		"expired":             iss.Token(testtoken.Claims{Audience: aud, IssuedAt: time.Now().Add(-time.Hour)}),
		"too long-lived":      iss.Token(testtoken.Claims{Audience: aud, Lifetime: time.Hour}),
		"not pod-bound":       iss.Token(testtoken.Claims{Audience: aud, NoPod: true}),
		"issued in future":    iss.Token(testtoken.Claims{Audience: aud, IssuedAt: time.Now().Add(10 * time.Minute)}),
		"wrong issuer":        iss.Token(testtoken.Claims{Audience: aud, Mutate: func(p map[string]interface{}) { p["iss"] = "https://evil.example.org" }}),
		"subject mismatch":    iss.Token(testtoken.Claims{Audience: aud, Mutate: func(p map[string]interface{}) { p["sub"] = "system:serviceaccount:kube-system:admin" }}),
		"no exp":              iss.Token(testtoken.Claims{Audience: aud, Mutate: func(p map[string]interface{}) { delete(p, "exp") }}),
		"signed by other key": other.Token(testtoken.Claims{Audience: aud}),
		"alg none":            unsigned(iss, aud, "none"),
		"alg HS256":           iss.Sign(map[string]interface{}{"alg": "HS256", "kid": iss.KID}, testPayload(aud)),
		"critical header":     iss.Sign(map[string]interface{}{"alg": "ES256", "kid": iss.KID, "crit": []string{"exp"}}, testPayload(aud)),
		"unknown kid":         iss.Sign(map[string]interface{}{"alg": "ES256", "kid": "key-2"}, testPayload(aud)),
		"tampered payload":    tamper(iss.Token(testtoken.Claims{Audience: aud})),
		"not a JWS":           "abc.def",
		"oversized":           strings.Repeat("a", maxTokenSize+1),
	}
	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := verify(t, iss, token); err == nil {
				t.Fatal("expected the token to be rejected")
			}
		})
	}
}

func testPayload(aud []string) map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"iss": issuerURL, "sub": "system:serviceaccount:ns:sa", "aud": aud,
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		"kubernetes.io": map[string]interface{}{
			"namespace": "ns", "serviceaccount": map[string]string{"name": "sa", "uid": "u"},
			"pod": map[string]string{"name": "p", "uid": "pu"},
		},
	}
}

func unsigned(iss *testtoken.Issuer, aud []string, alg string) string {
	h, _ := json.Marshal(map[string]string{"alg": alg, "kid": iss.KID})
	p, _ := json.Marshal(testPayload(aud))
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p) + "."
}

func tamper(token string) string {
	parts := strings.Split(token, ".")
	p, _ := base64.RawURLEncoding.DecodeString(parts[1])
	p = []byte(strings.Replace(string(p), "klusterlet-registration-sa", "klusterlet-work-sa", -1))
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(p) + "." + parts[2]
}

func TestVerifyRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	set := &StaticKeySet{keys: map[string]crypto.PublicKey{"rsa": key.Public()}}
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "rsa"})
	p, _ := json.Marshal(testPayload([]string{audience}))
	signed := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	digest := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	token := signed + "." + base64.RawURLEncoding.EncodeToString(sig)
	if _, err := Verify(context.Background(), token, VerifyOptions{Issuer: issuerURL, Audience: audience, Keys: set}); err != nil {
		t.Fatalf("RS256 token rejected: %v", err)
	}

	// An ES256 header must not be accepted with an RSA key.
	h2, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "rsa"})
	if _, err := Verify(context.Background(), base64.RawURLEncoding.EncodeToString(h2)+"."+strings.SplitN(token, ".", 2)[1],
		VerifyOptions{Issuer: issuerURL, Audience: audience, Keys: set}); err == nil {
		t.Fatal("expected an algorithm and key type mismatch to be rejected")
	}
}

func TestParseJWKS(t *testing.T) {
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakJWKS, _ := json.Marshal(map[string]interface{}{"keys": []map[string]string{{
		"kty": "RSA", "kid": "weak", "n": base64.RawURLEncoding.EncodeToString(weak.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(weak.E)).Bytes()),
	}}})
	for name, data := range map[string][]byte{
		"not JSON":       []byte("{"),
		"no keys":        []byte(`{"keys":[]}`),
		"weak RSA":       weakJWKS,
		"encryption key": []byte(`{"keys":[{"kty":"EC","use":"enc","crv":"P-256","x":"AA","y":"AA"}]}`),
		"invalid point":  []byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}]}`),
	} {
		if _, err := ParseJWKS(data); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestDiscoveryKeySet(t *testing.T) {
	var fetches atomic.Int32
	var iss *testtoken.Issuer
	jwksURI := ""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss.URL, "jwks_uri": jwksURI})
		case "/openid/v1/jwks":
			fetches.Add(1)
			_, _ = w.Write(iss.JWKS())
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	iss = testtoken.New(server.URL)
	jwksURI = server.URL + "/openid/v1/jwks"

	clk := clocktesting.NewFakePassiveClock(time.Now())
	ks, err := NewDiscoveryKeySet(server.URL, server.Client(), clk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(context.Background(), "key-1"); err != nil {
		t.Fatal(err)
	}
	// Unknown key IDs refetch at most once a minute.
	for i := 0; i < 3; i++ {
		if _, err := ks.Key(context.Background(), "unknown"); err == nil {
			t.Fatal("expected an unknown key ID to fail")
		}
	}
	if fetches.Load() != 1 {
		t.Errorf("want 1 fetch within a minute, got %d", fetches.Load())
	}
	clk.SetTime(clk.Now().Add(time.Minute))
	_, _ = ks.Key(context.Background(), "unknown")
	if fetches.Load() != 2 {
		t.Errorf("want a refetch after a minute, got %d", fetches.Load())
	}

	// A jwks_uri on another host is refused.
	jwksURI = "https://evil.example.org/jwks"
	ks2, _ := NewDiscoveryKeySet(server.URL, server.Client(), clk)
	if _, err := ks2.Key(context.Background(), "key-1"); err == nil {
		t.Error("expected a jwks_uri off the issuer's host to be refused")
	}

	if _, err := NewDiscoveryKeySet("http://spoke1.example.org", nil, nil); err == nil {
		t.Error("expected a plain-http issuer to be refused")
	}
}
