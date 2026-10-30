package svid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"net/url"
	"testing"
	"time"
)

func TestAgentIDRoundTrip(t *testing.T) {
	id := AgentIdentity{Cluster: "cluster1", Namespace: "open-cluster-management-agent", ServiceAccount: "klusterlet-work-sa"}
	u, err := AgentID(trustDomain, id)
	if err != nil {
		t.Fatal(err)
	}
	if want := "spiffe://hub1.example.org/ocm/cluster/cluster1/ns/open-cluster-management-agent/sa/klusterlet-work-sa"; u.String() != want {
		t.Fatalf("want %s, got %s", want, u)
	}
	got, err := ParseAgentID(trustDomain, u)
	if err != nil || got != id {
		t.Fatalf("round trip failed: %+v, %v", got, err)
	}

	for _, bad := range []AgentIdentity{
		{Cluster: "Cluster1", Namespace: "ns", ServiceAccount: "sa"},
		{Cluster: "c/1", Namespace: "ns", ServiceAccount: "sa"},
		{Cluster: "..", Namespace: "ns", ServiceAccount: "sa"},
		{Cluster: "c1", Namespace: "", ServiceAccount: "sa"},
	} {
		if _, err := AgentID(trustDomain, bad); err == nil {
			t.Errorf("%+v: expected an error", bad)
		}
	}
}

func TestParseAgentIDRejects(t *testing.T) {
	for _, raw := range []string{
		"spiffe://other.example.org/ocm/cluster/c1/ns/ns/sa/sa",
		"spiffe://hub1.example.org/ocm/hub/grpc-server",
		"spiffe://hub1.example.org/ocm/cluster/c1/ns/ns/sa/sa/extra",
		"spiffe://hub1.example.org/ocm/cluster/c1/sa/sa/ns/ns",
		"spiffe://hub1.example.org/ocm/cluster/c1/ns/ns/sa/sa?x=1",
		"spiffe://hub1.example.org/ocm/cluster/c1/ns/%2e%2e/sa/sa",
		"https://hub1.example.org/ocm/cluster/c1/ns/ns/sa/sa",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAgentID(trustDomain, u); err == nil {
			t.Errorf("%s: expected an error", raw)
		}
	}
	if _, err := ParseAgentID(trustDomain, nil); err == nil {
		t.Error("expected an error for a nil URL")
	}
}

func TestIssueAgentSVID(t *testing.T) {
	now := time.Now()
	ca := newCA(t, now, 24*time.Hour)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := AgentSVIDRequest{
		TrustDomain: trustDomain,
		Identity:    AgentIdentity{Cluster: "cluster1", Namespace: "open-cluster-management-agent", ServiceAccount: "klusterlet-registration-sa"},
		User:        "system:open-cluster-management:cluster1:registration",
		Groups:      []string{"system:open-cluster-management:cluster1", "system:open-cluster-management:managed-clusters"},
		PublicKey:   key.Public(),
		TTL:         time.Hour,
	}
	leaf, err := IssueAgentSVID(context.Background(), ca, req, now)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != req.User || len(leaf.Subject.Organization) != 2 {
		t.Errorf("unexpected subject %s", leaf.Subject)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("agent SVID does not verify for client use: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Error("agent SVID must never verify as a server certificate")
	}

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	bad := req
	bad.PublicKey = rsaKey.Public()
	if _, err := IssueAgentSVID(context.Background(), ca, bad, now); err == nil {
		t.Error("expected an error for an RSA agent key")
	}
	bad = req
	bad.User = ""
	if _, err := IssueAgentSVID(context.Background(), ca, bad, now); err == nil {
		t.Error("expected an error without a user")
	}
}
