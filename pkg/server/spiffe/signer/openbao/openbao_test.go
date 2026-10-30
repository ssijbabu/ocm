package openbao

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/memory"
	"open-cluster-management.io/ocm/pkg/server/spiffe/svid"
)

const trustDomain = "hub1.example.org"

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

// fakeBao serves KV v2 and transit the way OpenBao does. Key version 1 is an
// older key; version 2 belongs to the hub CA certificate.
type fakeBao struct {
	server     *httptest.Server
	keys       map[int]*ecdsa.PrivateKey
	cert       *x509.Certificate
	exportable bool
	signs      atomic.Int32
}

func newFakeBao(t *testing.T) *fakeBao {
	t.Helper()
	old, _, err := memory.NewSelfSignedCA(trustDomain, time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	k, cert, err := memory.NewSelfSignedCA(trustDomain, time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeBao{keys: map[int]*ecdsa.PrivateKey{1: old.(*ecdsa.PrivateKey), 2: k.(*ecdsa.PrivateKey)}, cert: cert}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeBao) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Vault-Token") != "bao-token" || r.Header.Get("X-Vault-Namespace") != "ocm" {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/secret/data/ocm/spiffe-ca":
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.cert.Raw})
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
			"data": map[string]string{"certificate": string(certPEM)},
		}})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/ocm-spiffe-ca":
		keys := map[string]interface{}{}
		for v, k := range f.keys {
			der, _ := x509.MarshalPKIXPublicKey(k.Public())
			keys[strconv.Itoa(v)] = map[string]string{"public_key": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{
			"type": "ecdsa-p256", "exportable": f.exportable, "allow_plaintext_backup": false, "keys": keys,
		}})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/sign/ocm-spiffe-ca/sha2-256":
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || !req.Prehashed || req.MarshalingAlgorithm != "asn1" {
			http.Error(w, `{"errors":["bad request"]}`, http.StatusBadRequest)
			return
		}
		key, ok := f.keys[req.KeyVersion]
		if !ok {
			http.Error(w, `{"errors":["no such version"]}`, http.StatusBadRequest)
			return
		}
		digest, _ := base64.StdEncoding.DecodeString(req.Input)
		sig, err := key.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		f.signs.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]string{
			"signature": "vault:v" + strconv.Itoa(req.KeyVersion) + ":" + base64.StdEncoding.EncodeToString(sig),
		}})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeBao) signer(t *testing.T) *Signer {
	t.Helper()
	s, err := New(Options{
		Address:         f.server.URL,
		Namespace:       "ocm",
		KeyName:         "ocm-spiffe-ca",
		CertificatePath: "secret/data/ocm/spiffe-ca",
		TokenSource:     staticToken("bao-token"),
		HTTPClient:      f.server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIssueServerSVIDThroughOpenBao(t *testing.T) {
	f := newFakeBao(t)
	ca, err := f.signer(t).Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert, err := svid.IssueServerSVID(context.Background(), ca, trustDomain, nil, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if f.signs.Load() != 1 {
		t.Errorf("want exactly one transit sign call, got %d", f.signs.Load())
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.cert)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now}); err != nil {
		t.Fatalf("hub server SVID signed through OpenBao does not verify: %v", err)
	}
}

func TestRejectsExportableKey(t *testing.T) {
	f := newFakeBao(t)
	f.exportable = true
	if _, err := f.signer(t).Current(context.Background()); err == nil {
		t.Fatal("expected an error for an exportable transit key")
	}
}

func TestRejectsCertificateWithoutMatchingKeyVersion(t *testing.T) {
	f := newFakeBao(t)
	_, other, _ := memory.NewSelfSignedCA(trustDomain, time.Now(), time.Hour)
	f.cert = other
	if _, err := f.signer(t).Current(context.Background()); err == nil {
		t.Fatal("expected an error when no key version matches the hub CA certificate")
	}
}

func TestParseSignatureChecksVersion(t *testing.T) {
	if _, err := parseSignature("vault:v1:AAAA", 2); err == nil {
		t.Error("expected an error for a signature from another key version")
	}
	if _, err := parseSignature("vault:v2:not base64!", 2); err == nil {
		t.Error("expected an error for invalid base64")
	}
	if got, err := parseSignature("vault:v2:AQI=", 2); err != nil || len(got) != 2 {
		t.Errorf("unexpected result %v, %v", got, err)
	}
}

func TestNewValidatesOptions(t *testing.T) {
	ok := Options{Address: "https://bao.example.com:8200", KeyName: "k", CertificatePath: "secret/data/ca", TokenSource: staticToken("t")}
	if _, err := New(ok); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i, mutate := range []func(*Options){
		func(o *Options) { o.Address = "http://bao.example.com:8200" },
		func(o *Options) { o.KeyName = "" },
		func(o *Options) { o.CertificatePath = "" },
		func(o *Options) { o.TokenSource = nil },
	} {
		o := ok
		mutate(&o)
		if _, err := New(o); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
}

func TestKubernetesAuthTokenSource(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.URL.Path != "/v1/auth/kubernetes/login" || req["role"] != "ocm-grpc-server" || req["jwt"] != "projected-jwt" {
			http.Error(w, `{"errors":["denied"]}`, http.StatusForbidden)
			return
		}
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"auth": map[string]interface{}{"client_token": "bao-token", "lease_duration": 600}})
	}))
	defer server.Close()

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("projected-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	clk := clocktesting.NewFakePassiveClock(time.Now())
	src := &KubernetesAuthTokenSource{Address: server.URL, Role: "ocm-grpc-server", TokenFile: tokenFile, HTTPClient: server.Client(), Clock: clk}

	for i := 0; i < 2; i++ {
		tok, err := src.Token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if tok != "bao-token" {
			t.Fatalf("unexpected token %q", tok)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("want the token cached, got %d logins", calls.Load())
	}
	clk.SetTime(clk.Now().Add(9 * time.Minute))
	if _, err := src.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Errorf("want a new login near lease end, got %d logins", calls.Load())
	}

	bad := &KubernetesAuthTokenSource{Address: server.URL, Role: "other", TokenFile: tokenFile, HTTPClient: server.Client()}
	if _, err := bad.Token(context.Background()); err == nil {
		t.Error("expected a refused login to fail")
	}
}
