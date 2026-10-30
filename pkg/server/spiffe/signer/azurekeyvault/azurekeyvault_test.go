package azurekeyvault

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// fakeVault serves the three Key Vault calls the signer makes, signing with an
// in-memory key the way Key Vault's HSM would.
type fakeVault struct {
	server *httptest.Server
	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	kid    string
	signs  atomic.Int32
}

func newFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	k, cert, err := memory.NewSelfSignedCA(trustDomain, time.Now(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeVault{key: k.(*ecdsa.PrivateKey), cert: cert}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	f.kid = f.server.URL + "/keys/ocm-spiffe-ca/v1"
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeVault) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer test-token" || r.URL.Query().Get("api-version") != apiVersion {
		http.Error(w, `{"error":{"code":"Unauthorized"}}`, http.StatusUnauthorized)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/certificates/ocm-spiffe-ca":
		_ = json.NewEncoder(w).Encode(map[string]string{"kid": f.kid, "cer": base64.StdEncoding.EncodeToString(f.cert.Raw)})
	case r.Method == http.MethodGet && r.URL.Path == "/keys/ocm-spiffe-ca/v1":
		pub := f.key.PublicKey
		x, y := make([]byte, 32), make([]byte, 32)
		pub.X.FillBytes(x)
		pub.Y.FillBytes(y)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"key": map[string]string{
			"kid": f.kid, "kty": "EC-HSM", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y),
		}})
	case r.Method == http.MethodPost && r.URL.Path == "/keys/ocm-spiffe-ca/v1/sign":
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Alg != "ES256" {
			http.Error(w, `{"error":{"code":"BadParameter"}}`, http.StatusBadRequest)
			return
		}
		digest, _ := base64.RawURLEncoding.DecodeString(req.Value)
		rr, s, err := ecdsa.Sign(rand.Reader, f.key, digest)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		raw := make([]byte, 64)
		rr.FillBytes(raw[:32])
		s.FillBytes(raw[32:])
		f.signs.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"kid": f.kid, "value": base64.RawURLEncoding.EncodeToString(raw)})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeVault) signer(t *testing.T) *Signer {
	t.Helper()
	s, err := New(Options{
		VaultURL:        f.server.URL,
		CertificateName: "ocm-spiffe-ca",
		TokenSource:     staticToken("test-token"),
		HTTPClient:      f.server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIssueServerSVIDThroughKeyVault(t *testing.T) {
	f := newFakeVault(t)
	ca, err := f.signer(t).Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Certificate.Equal(f.cert) {
		t.Fatal("unexpected hub CA certificate")
	}

	now := time.Now()
	cert, err := svid.IssueServerSVID(context.Background(), ca, trustDomain, nil, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if f.signs.Load() != 1 {
		t.Errorf("want exactly one Key Vault sign call, got %d", f.signs.Load())
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.cert)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now}); err != nil {
		t.Fatalf("hub server SVID signed through Key Vault does not verify: %v", err)
	}
}

func TestKeyIdentifierMustStayInVault(t *testing.T) {
	f := newFakeVault(t)
	s := f.signer(t)
	for _, kid := range []string{
		"https://evil.example.com/keys/ocm-spiffe-ca/v1",
		strings.Replace(f.kid, "https://", "http://", 1),
		f.server.URL + "/keys/ocm-spiffe-ca",
		f.server.URL + "/secrets/ocm-spiffe-ca/v1",
	} {
		f.kid = kid
		if _, err := s.Current(context.Background()); err == nil {
			t.Errorf("expected an error for key identifier %q", kid)
		}
	}
}

func TestNewValidatesOptions(t *testing.T) {
	cases := []Options{
		{VaultURL: "http://vault.example.com", CertificateName: "ca", TokenSource: staticToken("t")},
		{VaultURL: "https://vault.example.com", TokenSource: staticToken("t")},
		{VaultURL: "https://vault.example.com", CertificateName: "ca"},
	}
	for i, o := range cases {
		if _, err := New(o); err == nil {
			t.Errorf("case %d: expected an error", i)
		}
	}
}

func TestWorkloadIdentityTokenSource(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tenant-1/oauth2/v2.0/token" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("client_id") != "client-1" || r.Form.Get("client_assertion") != "projected-jwt" ||
			r.Form.Get("scope") != keyVaultScope || r.Form.Get("grant_type") != "client_credentials" {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "kv-token", "expires_in": 3600})
	}))
	defer server.Close()

	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("projected-jwt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clk := clocktesting.NewFakePassiveClock(time.Now())
	src := &WorkloadIdentityTokenSource{
		TenantID: "tenant-1", ClientID: "client-1", TokenFile: tokenFile,
		AuthorityHost: server.URL + "/", HTTPClient: server.Client(), Clock: clk,
	}

	for i := 0; i < 2; i++ {
		tok, err := src.Token(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if tok != "kv-token" {
			t.Fatalf("unexpected token %q", tok)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("want the token cached, got %d exchanges", calls.Load())
	}

	clk.SetTime(clk.Now().Add(56 * time.Minute))
	if _, err := src.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Errorf("want a refresh near expiry, got %d exchanges", calls.Load())
	}
}

func TestNewWorkloadIdentityTokenSourceFromEnv(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	if _, err := NewWorkloadIdentityTokenSourceFromEnv(); err == nil {
		t.Fatal("expected an error without workload identity environment variables")
	}
	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "client")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/var/run/secrets/azure/tokens/azure-identity-token")
	if _, err := NewWorkloadIdentityTokenSourceFromEnv(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
