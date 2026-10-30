package svid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/memory"
)

const trustDomain = "hub1.example.org"

func newCA(t *testing.T, now time.Time, ttl time.Duration) *signer.CA {
	t.Helper()
	key, cert, err := memory.NewSelfSignedCA(trustDomain, now, ttl)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := memory.New(key, cert).Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestValidateTrustDomain(t *testing.T) {
	for _, td := range []string{"example.org", "hub-1.example.org", "a_b"} {
		if err := ValidateTrustDomain(td); err != nil {
			t.Errorf("%q: unexpected error: %v", td, err)
		}
	}
	for _, td := range []string{"", "Example.org", "hub/1", "hub:443", strings.Repeat("a", 256)} {
		if err := ValidateTrustDomain(td); err == nil {
			t.Errorf("%q: expected an error", td)
		}
	}
}

func TestIssueServerSVID(t *testing.T) {
	now := time.Now()
	ca := newCA(t, now, 24*time.Hour)

	cert, err := IssueServerSVID(context.Background(), ca, trustDomain, []string{"hub.example.org"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	leaf := cert.Leaf

	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != "spiffe://"+trustDomain+ServerPath {
		t.Errorf("unexpected URIs %v", leaf.URIs)
	}
	if leaf.IsCA {
		t.Error("hub server SVID must not be a CA")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("hub server SVID must be server-only, got %v", leaf.ExtKeyUsage)
	}
	// Certificates store times at one-second precision.
	if got := leaf.NotAfter.Sub(now); got <= time.Hour-time.Second || got > time.Hour {
		t.Errorf("want 1h lifetime, got %s", got)
	}
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(cert.PrivateKey.(*ecdsa.PrivateKey).Public()) {
		t.Error("private key does not match the hub server SVID")
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		DNSName:     "hub.example.org",
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("hub server SVID does not verify against the hub CA: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Error("hub server SVID must not verify for client use")
	}
}

func TestIssueServerSVIDCappedAtCAExpiry(t *testing.T) {
	now := time.Now()
	ca := newCA(t, now, 30*time.Minute)

	cert, err := IssueServerSVID(context.Background(), ca, trustDomain, nil, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Leaf.NotAfter.Equal(ca.Certificate.NotAfter) {
		t.Errorf("want NotAfter capped at %s, got %s", ca.Certificate.NotAfter, cert.Leaf.NotAfter)
	}
}

func TestIssueServerSVIDRejectsOtherTrustDomain(t *testing.T) {
	now := time.Now()
	ca := newCA(t, now, time.Hour)
	if _, err := IssueServerSVID(context.Background(), ca, "other.example.org", nil, time.Hour, now); err == nil {
		t.Fatal("expected an error for a trust domain outside the hub CA's name constraint")
	}
}

// TestNameConstraintEnforced shows why ValidateCA insists on the name
// constraint: even a signature the hub CA key produces for another trust
// domain is rejected by standard verification.
func TestNameConstraintEnforced(t *testing.T) {
	now := time.Now()
	key, caCert, err := memory.NewSelfSignedCA(trustDomain, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		URIs:         []*url.URL{{Scheme: "spiffe", Host: "other.example.org", Path: ServerPath}},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, leafKey.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now}); err == nil {
		t.Fatal("a certificate for another trust domain must not verify")
	}
}

func TestValidateCA(t *testing.T) {
	now := time.Now()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk := func(mutate func(*x509.Certificate)) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber:                big.NewInt(1),
			Subject:                     pkix.Name{CommonName: "ca"},
			NotBefore:                   now.Add(-time.Hour),
			NotAfter:                    now.Add(time.Hour),
			IsCA:                        true,
			BasicConstraintsValid:       true,
			KeyUsage:                    x509.KeyUsageCertSign,
			PermittedURIDomains:         []string{trustDomain},
			PermittedDNSDomainsCritical: true,
		}
		mutate(tmpl)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}

	cases := []struct {
		name    string
		mutate  func(*x509.Certificate)
		wantErr bool
	}{
		{name: "valid", mutate: func(*x509.Certificate) {}},
		{name: "not a CA", mutate: func(c *x509.Certificate) { c.IsCA = false; c.KeyUsage = x509.KeyUsageDigitalSignature }, wantErr: true},
		{name: "no keyCertSign", mutate: func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageDigitalSignature }, wantErr: true},
		{name: "no name constraint", mutate: func(c *x509.Certificate) { c.PermittedURIDomains = nil }, wantErr: true},
		{name: "non-critical constraint", mutate: func(c *x509.Certificate) { c.PermittedDNSDomainsCritical = false }, wantErr: true},
		{name: "wrong trust domain", mutate: func(c *x509.Certificate) { c.PermittedURIDomains = []string{"other.org"} }, wantErr: true},
		{name: "extra trust domain", mutate: func(c *x509.Certificate) {
			c.PermittedURIDomains = []string{trustDomain, "other.org"}
		}, wantErr: true},
		{name: "expired", mutate: func(c *x509.Certificate) { c.NotAfter = now.Add(-time.Minute) }, wantErr: true},
		{name: "not yet valid", mutate: func(c *x509.Certificate) { c.NotBefore = now.Add(time.Minute) }, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateCA(mk(c.mutate), trustDomain, now)
			if c.wantErr != (err != nil) {
				t.Fatalf("wantErr %v, got %v", c.wantErr, err)
			}
		})
	}
}
