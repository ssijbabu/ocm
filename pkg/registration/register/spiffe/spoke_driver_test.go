package spiffe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubefake "k8s.io/client-go/kubernetes/fake"

	certv1 "open-cluster-management.io/sdk-go/pkg/server/grpc/certificate/v1"

	"open-cluster-management.io/ocm/pkg/registration/register"
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

// fakeHub signs every request, standing in for the hub certificate service.
type fakeHub struct {
	certv1.UnimplementedCertificateServiceServer
	ca *signer.CA
}

func (h *fakeHub) CreateCertificate(ctx context.Context, req *certv1.CreateCertificateRequest) (*certv1.CreateCertificateResponse, error) {
	// Renewal must not depend on the current SVID: the real hub refuses an
	// expired one, or one from a hub CA it no longer trusts, in the handshake.
	if p, ok := peer.FromContext(ctx); ok {
		if info, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(info.State.PeerCertificates) > 0 {
			return nil, fmt.Errorf("the certificate connection must not present a client certificate")
		}
	}
	csr, err := x509.ParseCertificateRequest(req.GetCsr())
	if err != nil {
		return nil, err
	}
	leaf, err := svid.IssueAgentSVID(ctx, h.ca, svid.AgentSVIDRequest{
		TrustDomain: trustDomain,
		Identity:    svid.AgentIdentity{Cluster: req.GetClusterName(), Namespace: "open-cluster-management-agent", ServiceAccount: "klusterlet-agent"},
		User:        "system:open-cluster-management:" + req.GetClusterName() + ":registration",
		PublicKey:   csr.PublicKey,
		TTL:         time.Hour,
	}, time.Now())
	if err != nil {
		return nil, err
	}
	return &certv1.CreateCertificateResponse{CertificateChain: [][]byte{leaf.Raw}, TrustBundle: [][]byte{h.ca.Certificate.Raw}}, nil
}

// startHub returns the hub's address, its hub CA, and a function that restarts
// the hub on the same address, so agents must open new connections.
func startHub(t *testing.T) (string, *signer.CA, func()) {
	t.Helper()
	m, err := memory.NewSelfSigned(trustDomain, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := m.Current(context.Background())
	serverSVID, err := svid.IssueServerSVID(context.Background(), ca, trustDomain, nil, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := authn.ServerTLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return serverSVID, nil },
		func() []*x509.Certificate { return []*x509.Certificate{ca.Certificate} })
	var srv *grpc.Server
	serve := func(addr string) string {
		srv = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
		certv1.RegisterCertificateServiceServer(srv, &fakeHub{ca: ca})
		lis, err := net.Listen("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv.Serve(lis) }()
		return lis.Addr().String()
	}
	addr := serve("127.0.0.1:0")
	t.Cleanup(func() { srv.Stop() })
	return addr, ca, func() {
		srv.Stop()
		serve(addr)
	}
}

func newOption(t *testing.T, addr string, ca *signer.CA) *Option {
	t.Helper()
	dir := t.TempDir()
	o := &Option{
		TrustDomain:     trustDomain,
		GRPCServer:      addr,
		TokenFile:       filepath.Join(dir, "token"),
		TrustBundleFile: filepath.Join(dir, "ca.crt"),
	}
	if err := os.WriteFile(o.TokenFile, []byte("projected-jwt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.TrustBundleFile, []byte(trustbundle.EncodePEM([]*x509.Certificate{ca.Certificate})), 0o600); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestDriverObtainsSVIDAndStoresTrustBundle(t *testing.T) {
	addr, ca, restartHub := startHub(t)
	d, err := NewDriver(newOption(t, addr, ca), register.SecretOption{ClusterName: cluster})
	if err != nil {
		t.Fatal(err)
	}
	if valid, _ := d.IsHubKubeConfigValid(context.Background(), register.SecretOption{}); valid {
		t.Fatal("driver must not be valid before it starts")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	spokeClient := kubefake.NewSimpleClientset()
	disc := spokeClient.Discovery().(*discoveryfake.FakeDiscovery)
	disc.Resources = []*metav1.APIResourceList{{
		GroupVersion: "certificates.k8s.io/v1",
		APIResources: []metav1.APIResource{{Name: "clustertrustbundles", Kind: "ClusterTrustBundle"}},
	}}
	ctbGVR := schema.GroupVersionResource{Group: "certificates.k8s.io", Version: "v1", Resource: "clustertrustbundles"}
	spokeDynamic := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{ctbGVR: "ClusterTrustBundleList"})
	if err := d.Start(ctx, spokeClient, spokeDynamic); err != nil {
		t.Fatal(err)
	}
	if err := wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		return d.IsHubKubeConfigValid(ctx, register.SecretOption{})
	}); err != nil {
		t.Fatalf("driver never obtained its SVID: %v", err)
	}

	ctb, err := spokeDynamic.Resource(ctbGVR).Get(ctx, trustbundle.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("hub trust bundle not stored in the spoke ClusterTrustBundle: %v", err)
	}
	if signer, _, _ := unstructured.NestedString(ctb.Object, "spec", "signerName"); signer != trustbundle.SignerName {
		t.Errorf("unexpected signer %q", signer)
	}

	// Renew over a new connection now that the agent holds an SVID.
	restartHub()
	if err := wait.PollUntilContextTimeout(ctx, 50*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := d.manager.Renew(ctx)
		return err == nil, nil
	}); err != nil {
		t.Fatalf("renewal over a new connection failed: %v", err)
	}

	cert, err := d.ClientCertificate(nil)
	if err != nil || cert.Leaf == nil {
		t.Fatal("the singleton work agent cannot share the registration agent SVID")
	}

	if _, err := d.BuildClients(ctx, register.SecretOption{ClusterName: cluster}, true); err == nil {
		t.Error("SPIFFE agents must refuse the bootstrap flow")
	}
	if _, err := d.BuildClients(ctx, register.SecretOption{ClusterName: cluster}, false); err != nil {
		t.Errorf("building the hub clients failed: %v", err)
	}
}

func TestOption(t *testing.T) {
	var nilOpt *Option
	if nilOpt.Enabled() {
		t.Error("a nil option must be disabled")
	}
	if err := (&Option{}).Validate(); err != nil {
		t.Errorf("a disabled option must validate: %v", err)
	}
	if err := (&Option{TrustDomain: "Bad"}).Validate(); err == nil {
		t.Error("expected an invalid trust domain to be refused")
	}
	if err := (&Option{TrustDomain: trustDomain}).Validate(); err == nil {
		t.Error("expected missing server, token and bundle paths to be refused")
	}

	a := &Driver{opt: &Option{TrustDomain: trustDomain, GRPCServer: "hub:443"}}
	b := &Driver{opt: &Option{TrustDomain: "hub2.example.org", GRPCServer: "hub:443"}}
	if a.HubHash() == b.HubHash() || a.HubHash() != (&Driver{opt: a.opt}).HubHash() {
		t.Error("the hub hash must be stable and differ between hubs")
	}
}
