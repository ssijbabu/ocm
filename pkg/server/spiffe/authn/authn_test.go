package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	sdkauthn "open-cluster-management.io/sdk-go/pkg/server/grpc/authn"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/memory"
	"open-cluster-management.io/ocm/pkg/server/spiffe/svid"
)

const trustDomain = "hub1.example.org"

func newCA(t *testing.T) *signer.CA {
	t.Helper()
	m, err := memory.NewSelfSigned(trustDomain, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := m.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func agentSVID(t *testing.T, ca *signer.CA, cluster, userName string, groups []string) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, err := svid.IssueAgentSVID(context.Background(), ca, svid.AgentSVIDRequest{
		TrustDomain: trustDomain,
		Identity:    svid.AgentIdentity{Cluster: cluster, Namespace: "open-cluster-management-agent", ServiceAccount: "klusterlet-work-sa"},
		User:        userName,
		Groups:      groups,
		PublicKey:   key.Public(),
		TTL:         time.Hour,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestIdentify(t *testing.T) {
	ca := newCA(t)
	other := newCA(t)
	a, err := NewSVIDAuthenticator(trustDomain, func() []*x509.Certificate { return []*x509.Certificate{ca.Certificate} })
	if err != nil {
		t.Fatal(err)
	}
	clusterGroups := []string{"system:open-cluster-management:cluster1", "system:open-cluster-management:managed-clusters"}

	userName, groups, err := a.Identify([]*x509.Certificate{agentSVID(t, ca, "cluster1", "system:open-cluster-management:cluster1:work", clusterGroups)})
	if err != nil {
		t.Fatal(err)
	}
	if userName != "system:open-cluster-management:cluster1:work" || len(groups) != 2 {
		t.Errorf("unexpected identity %s %v", userName, groups)
	}

	addonUser := "system:open-cluster-management:cluster:cluster1:addon:demo:agent:demo"
	addonGroups := []string{"system:open-cluster-management:cluster:cluster1:addon:demo", "system:open-cluster-management:addon:demo"}
	if _, _, err := a.Identify([]*x509.Certificate{agentSVID(t, ca, "cluster1", addonUser, addonGroups)}); err != nil {
		t.Errorf("addon agent SVID rejected: %v", err)
	}

	serverSVID, err := svid.IssueServerSVID(context.Background(), ca, trustDomain, nil, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]*x509.Certificate{
		"signed by another CA":        agentSVID(t, other, "cluster1", "system:open-cluster-management:cluster1:work", clusterGroups),
		"user of another spoke":       agentSVID(t, ca, "cluster1", "system:open-cluster-management:cluster2:work", clusterGroups),
		"group of another spoke":      agentSVID(t, ca, "cluster1", "system:open-cluster-management:cluster1:work", []string{"system:open-cluster-management:cluster2"}),
		"privileged group":            agentSVID(t, ca, "cluster1", "system:open-cluster-management:cluster1:work", []string{"system:masters"}),
		"hub server SVID as a client": serverSVID.Leaf,
	}
	for name, cert := range cases {
		if _, _, err := a.Identify([]*x509.Certificate{cert}); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

// TestAuthenticateOverTLS runs a real TLS 1.3 handshake with ServerTLSConfig
// and checks the authenticator sets the identity sdk-go's SubjectAccessReview
// authorizer reads.
func TestAuthenticateOverTLS(t *testing.T) {
	ca := newCA(t)
	bundle := func() []*x509.Certificate { return []*x509.Certificate{ca.Certificate} }
	server, err := svid.IssueServerSVID(context.Background(), ca, trustDomain, []string{"hub"}, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := ServerTLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return server, nil }, bundle)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf, err := svid.IssueAgentSVID(context.Background(), ca, svid.AgentSVIDRequest{
		TrustDomain: trustDomain,
		Identity:    svid.AgentIdentity{Cluster: "cluster1", Namespace: "ns", ServiceAccount: "sa"},
		User:        "system:open-cluster-management:cluster1:registration",
		Groups:      []string{"system:open-cluster-management:cluster1"},
		PublicKey:   key.Public(),
		TTL:         time.Hour,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	clientCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		ServerName:   "hub",
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}},
	}

	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	srv := tls.Server(s, serverCfg)
	errCh := make(chan error, 1)
	go func() { errCh <- tls.Client(c, clientCfg).Handshake() }()
	if err := srv.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}

	a, _ := NewSVIDAuthenticator(trustDomain, bundle)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: srv.ConnectionState()}})
	ctx, err = a.Authenticate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Value(sdkauthn.ContextUserKey) != "system:open-cluster-management:cluster1:registration" {
		t.Errorf("unexpected user %v", ctx.Value(sdkauthn.ContextUserKey))
	}
	if groups, ok := ctx.Value(sdkauthn.ContextGroupsKey).([]string); !ok || len(groups) != 1 {
		t.Errorf("unexpected groups %v", ctx.Value(sdkauthn.ContextGroupsKey))
	}

	if _, err := a.Authenticate(context.Background()); err == nil {
		t.Error("expected an error without a peer")
	}
}
