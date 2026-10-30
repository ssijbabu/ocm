package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	"open-cluster-management.io/ocm/pkg/server/spiffe/authn"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/memory"
	"open-cluster-management.io/ocm/pkg/server/spiffe/svid"
	"open-cluster-management.io/ocm/pkg/server/spiffe/trustbundle"
)

const (
	trustDomain = "hub1.example.org"
	cluster     = "cluster1"
)

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

// fakeHub signs the agent's request directly, standing in for the hub
// certificate service.
type fakeHub struct {
	ca       *signer.CA
	cluster  string
	err      error
	tokens   []string
	tamperFn func(*CertificateResponse)
}

func (h *fakeHub) CreateCertificate(ctx context.Context, req CertificateRequest) (*CertificateResponse, error) {
	h.tokens = append(h.tokens, req.Token)
	if h.err != nil {
		return nil, h.err
	}
	csr, err := x509.ParseCertificateRequest(req.CSR)
	if err != nil {
		return nil, err
	}
	cluster := h.cluster
	if cluster == "" {
		cluster = req.ClusterName
	}
	leaf, err := svid.IssueAgentSVID(ctx, h.ca, svid.AgentSVIDRequest{
		TrustDomain: trustDomain,
		Identity:    svid.AgentIdentity{Cluster: cluster, Namespace: "open-cluster-management-agent", ServiceAccount: "klusterlet-registration-sa"},
		User:        "system:open-cluster-management:" + cluster + ":registration",
		Groups:      []string{"system:open-cluster-management:" + cluster},
		PublicKey:   csr.PublicKey,
		TTL:         time.Hour,
	}, time.Now())
	if err != nil {
		return nil, err
	}
	resp := &CertificateResponse{Certificate: leaf, TrustBundle: []*x509.Certificate{h.ca.Certificate}}
	if h.tamperFn != nil {
		h.tamperFn(resp)
	}
	return resp, nil
}

func tokenFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestManagerRenews(t *testing.T) {
	hub := &fakeHub{ca: newCA(t)}
	var stored []*x509.Certificate
	clk := clocktesting.NewFakeClock(time.Now())
	m, err := NewManager(Options{
		TrustDomain: trustDomain, ClusterName: cluster, TokenFile: tokenFile(t, "jwt-1\n"), Client: hub, Clock: clk,
		OnTrustBundle: func(_ context.Context, b []*x509.Certificate) error { stored = b; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := m.GetClientCertificate(nil); len(c.Certificate) != 0 {
		t.Fatal("want an empty client certificate before the first SVID")
	}

	wait, err := m.Renew(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if wait > 30*time.Minute || wait < 27*time.Minute {
		t.Errorf("want renewal at half life minus up to 10%% jitter, got %s", wait)
	}
	if hub.tokens[0] != "jwt-1" {
		t.Errorf("want the projected token sent, got %q", hub.tokens[0])
	}
	if len(stored) != 1 {
		t.Error("hub trust bundle not stored")
	}
	first := m.Current()
	if first == nil || first.Leaf.URIs[0].String() != "spiffe://hub1.example.org/ocm/cluster/cluster1/ns/open-cluster-management-agent/sa/klusterlet-registration-sa" {
		t.Fatal("agent SVID not kept")
	}

	if _, err := m.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Current().Leaf.SerialNumber.Cmp(first.Leaf.SerialNumber) == 0 {
		t.Error("renewal did not replace the agent SVID")
	}
	if m.Current().PrivateKey == first.PrivateKey {
		t.Error("renewal must use a new private key")
	}
}

func TestManagerRejectsBadResponses(t *testing.T) {
	ca := newCA(t)
	otherCA := newCA(t)
	cases := map[string]*fakeHub{
		"SVID for another spoke": {ca: ca, cluster: "cluster2"},
		"SVID for another key": {ca: ca, tamperFn: func(r *CertificateResponse) {
			other, _ := (&fakeHub{ca: ca}).CreateCertificate(context.Background(), CertificateRequest{ClusterName: cluster, CSR: csrFor(t)})
			r.Certificate = other.Certificate
		}},
		"bundle from another CA": {ca: ca, tamperFn: func(r *CertificateResponse) { r.TrustBundle = []*x509.Certificate{otherCA.Certificate} }},
		"no bundle":              {ca: ca, tamperFn: func(r *CertificateResponse) { r.TrustBundle = nil }},
		"hub refuses":            {ca: ca, err: errors.New("not ready")},
	}
	for name, hub := range cases {
		t.Run(name, func(t *testing.T) {
			m, err := NewManager(Options{TrustDomain: trustDomain, ClusterName: cluster, TokenFile: tokenFile(t, "jwt"), Client: hub})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.Renew(context.Background()); err == nil {
				t.Fatal("expected the response to be rejected")
			}
			if m.Current() != nil {
				t.Fatal("a rejected response must not replace the agent SVID")
			}
		})
	}
}

// csrFor returns a certificate request for a fresh key that is not the agent's.
func csrFor(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// TestHandshakeWithHub runs the full mutual TLS handshake: the agent checks
// the hub server SVID's exact SPIFFE ID, then presents its agent SVID, which
// the hub authenticator maps to the agent's user.
func TestHandshakeWithHub(t *testing.T) {
	ca := newCA(t)
	hubSVID, err := svid.IssueServerSVID(context.Background(), ca, trustDomain, nil, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(bundlePath, []byte(trustbundle.EncodePEM([]*x509.Certificate{ca.Certificate})), 0o600); err != nil {
		t.Fatal(err)
	}

	m, _ := NewManager(Options{TrustDomain: trustDomain, ClusterName: cluster, TokenFile: tokenFile(t, "jwt"), Client: &fakeHub{ca: ca}})
	if _, err := m.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	clientCfg, err := HubTLSConfig(trustDomain, &FileTrustBundle{Path: bundlePath}, m.GetClientCertificate)
	if err != nil {
		t.Fatal(err)
	}
	bundle := func() []*x509.Certificate { return []*x509.Certificate{ca.Certificate} }
	serverCfg := authn.ServerTLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return hubSVID, nil }, bundle)

	state, err := handshake(clientCfg, serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := authn.NewSVIDAuthenticator(trustDomain, bundle)
	userName, _, err := a.Identify(state.PeerCertificates)
	if err != nil || userName != "system:open-cluster-management:cluster1:registration" {
		t.Fatalf("hub did not identify the agent: %s, %v", userName, err)
	}

	// A server presenting an agent SVID, signed by the same hub CA, is not the hub.
	fake := m.Current()
	fakeCfg := authn.ServerTLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return fake, nil }, bundle)
	if _, err := handshake(clientCfg, fakeCfg); err == nil {
		t.Fatal("agent accepted a server that is not the hub")
	}

	// A hub server SVID from another hub CA is refused.
	otherHub, _ := svid.IssueServerSVID(context.Background(), newCA(t), trustDomain, nil, time.Hour, time.Now())
	otherCfg := authn.ServerTLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return otherHub, nil }, bundle)
	if _, err := handshake(clientCfg, otherCfg); err == nil {
		t.Fatal("agent accepted a hub server SVID from another hub CA")
	}
}

// handshake returns the server's view of the connection.
func handshake(clientCfg, serverCfg *tls.Config) (tls.ConnectionState, error) {
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	srv := tls.Server(s, serverCfg)
	cli := tls.Client(c, clientCfg)
	errCh := make(chan error, 1)
	go func() {
		err := cli.Handshake()
		if err != nil {
			c.Close()
		}
		errCh <- err
	}()
	srvErr := srv.Handshake()
	if srvErr != nil {
		s.Close()
	}
	cliErr := <-errCh
	if cliErr != nil {
		return tls.ConnectionState{}, cliErr
	}
	if srvErr != nil {
		return tls.ConnectionState{}, srvErr
	}
	return srv.ConnectionState(), nil
}

func TestFileTrustBundle(t *testing.T) {
	ca1, ca2 := newCA(t), newCA(t)
	p := filepath.Join(t.TempDir(), "ca.crt")
	_ = os.WriteFile(p, []byte(trustbundle.EncodePEM([]*x509.Certificate{ca1.Certificate})), 0o600)
	f := &FileTrustBundle{Path: p}
	got, err := f.TrustBundle()
	if err != nil || len(got) != 1 {
		t.Fatalf("unexpected %v, %v", got, err)
	}
	// The kubelet rewrites the projected file during hub CA rotation.
	_ = os.WriteFile(p, []byte(trustbundle.EncodePEM([]*x509.Certificate{ca1.Certificate, ca2.Certificate})), 0o600)
	if got, _ := f.TrustBundle(); len(got) != 2 {
		t.Fatalf("want the updated bundle, got %d certificates", len(got))
	}
	_ = os.WriteFile(p, []byte("garbage"), 0o600)
	if _, err := f.TrustBundle(); err == nil {
		t.Fatal("expected an error for an empty bundle")
	}
}

func TestNewManagerValidates(t *testing.T) {
	for name, o := range map[string]Options{
		"bad trust domain": {TrustDomain: "Bad", ClusterName: cluster, TokenFile: "t", Client: &fakeHub{}},
		"no cluster":       {TrustDomain: trustDomain, TokenFile: "t", Client: &fakeHub{}},
		"no client":        {TrustDomain: trustDomain, ClusterName: cluster, TokenFile: "t"},
		"bad jitter":       {TrustDomain: trustDomain, ClusterName: cluster, TokenFile: "t", Client: &fakeHub{}, Jitter: 0.9},
	} {
		if _, err := NewManager(o); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
