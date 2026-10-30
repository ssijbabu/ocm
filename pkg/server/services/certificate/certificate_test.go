package certificate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	addonv1alpha1 "open-cluster-management.io/api/addon/v1alpha1"
	addonfake "open-cluster-management.io/api/client/addon/clientset/versioned/fake"
	addoninformers "open-cluster-management.io/api/client/addon/informers/externalversions"
	clusterfake "open-cluster-management.io/api/client/cluster/clientset/versioned/fake"
	clusterinformers "open-cluster-management.io/api/client/cluster/informers/externalversions"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
	clusterv1alpha1 "open-cluster-management.io/api/cluster/v1alpha1"
	certv1 "open-cluster-management.io/sdk-go/pkg/server/grpc/certificate/v1"

	"open-cluster-management.io/ocm/pkg/common/spiffe/agent"
	"open-cluster-management.io/ocm/pkg/server/spiffe/authn"
	"open-cluster-management.io/ocm/pkg/server/spiffe/certservice"
	testtoken "open-cluster-management.io/ocm/pkg/server/spiffe/satoken/satokentest"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/memory"
	"open-cluster-management.io/ocm/pkg/server/spiffe/svid"
	"open-cluster-management.io/ocm/pkg/server/spiffe/trustbundle"
)

const (
	trustDomain = "hub1.example.org"
	audience    = "open-cluster-management.io/hub1"
	cluster     = "cluster1"
	agentNS     = "open-cluster-management-agent"
)

type fakeCA struct{ ca *signer.CA }

func (f fakeCA) ActiveCA() *signer.CA             { return f.ca }
func (f fakeCA) TrustBundle() []*x509.Certificate { return []*x509.Certificate{f.ca.Certificate} }

type hub struct {
	addr          string
	ca            *signer.CA
	issuer        *testtoken.Issuer
	clusterClient *clusterfake.Clientset
	bundlePath    string
}

// startHub serves the CertificateService over real TLS with the same
// authentication rules the sdk-go server applies in SPIFFE mode:
// CreateCertificate is open, everything else needs an agent SVID.
func startHub(t *testing.T, accepted bool) *hub {
	t.Helper()
	m, err := memory.NewSelfSigned(trustDomain, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := m.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	serverSVID, err := svid.IssueServerSVID(context.Background(), ca, trustDomain, nil, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	iss := testtoken.New("https://spoke1.example.org")

	mc := &clusterv1.ManagedCluster{ObjectMeta: metav1.ObjectMeta{Name: cluster}, Spec: clusterv1.ManagedClusterSpec{HubAcceptsClient: accepted}}
	mcid := &clusterv1alpha1.ManagedClusterIdentity{
		ObjectMeta: metav1.ObjectMeta{Name: cluster},
		Spec: clusterv1alpha1.ManagedClusterIdentitySpec{
			Issuer: iss.URL,
			JWKS:   string(iss.JWKS()),
			ServiceAccounts: []clusterv1alpha1.BoundServiceAccount{
				{Namespace: agentNS, Name: "klusterlet-registration-sa", UID: "sa-uid-1", Agent: RegistrationAgent},
				{Namespace: agentNS, Name: "klusterlet-work-sa", UID: "sa-uid-2", Agent: "work"},
			},
		},
	}
	clusterClient := clusterfake.NewSimpleClientset(mc, mcid)
	ci := clusterinformers.NewSharedInformerFactory(clusterClient, 0)
	_ = ci.Cluster().V1().ManagedClusters().Informer().GetIndexer().Add(mc)
	_ = ci.Cluster().V1alpha1().ManagedClusterIdentities().Informer().GetIndexer().Add(mcid)

	cma := &addonv1alpha1.ClusterManagementAddOn{
		ObjectMeta: metav1.ObjectMeta{Name: "demo"},
		Spec: addonv1alpha1.ClusterManagementAddOnSpec{
			SPIFFERegistration: &addonv1alpha1.SPIFFEAddOnRegistration{Namespace: "demo-agent", ServiceAccountName: "demo-sa"},
		},
	}
	mca := &addonv1alpha1.ManagedClusterAddOn{ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: cluster}}
	ai := addoninformers.NewSharedInformerFactory(addonfake.NewSimpleClientset(cma, mca), 0)
	_ = ai.Addon().V1alpha1().ClusterManagementAddOns().Informer().GetIndexer().Add(cma)
	_ = ai.Addon().V1alpha1().ManagedClusterAddOns().Informer().GetIndexer().Add(mca)

	issuer, err := certservice.New(certservice.Options{
		TrustDomain: trustDomain,
		Audience:    audience,
		CA:          fakeCA{ca: ca},
		Bindings: &Bindings{
			Clusters:   ci.Cluster().V1().ManagedClusters().Lister(),
			Identities: ci.Cluster().V1alpha1().ManagedClusterIdentities().Lister(),
		},
		Addons: &Addons{
			ClusterManagementAddOns: ai.Addon().V1alpha1().ClusterManagementAddOns().Lister(),
			ManagedClusterAddOns:    ai.Addon().V1alpha1().ManagedClusterAddOns().Lister(),
		},
		Recorder: certservice.NewEventRecorder(kubefake.NewSimpleClientset(), "grpc-server"),
	})
	if err != nil {
		t.Fatal(err)
	}

	bundle := func() []*x509.Certificate { return []*x509.Certificate{ca.Certificate} }
	authenticator, _ := authn.NewSVIDAuthenticator(trustDomain, bundle)
	tlsConfig := authn.ServerTLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return serverSVID, nil }, bundle)
	srv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
			if info.FullMethod == CreateCertificateMethod {
				return h(ctx, req)
			}
			ctx, err := authenticator.Authenticate(ctx)
			if err != nil {
				return nil, err
			}
			return h(ctx, req)
		}),
	)
	certv1.RegisterCertificateServiceServer(srv, NewServer(issuer, ci.Cluster().V1alpha1().ManagedClusterIdentities().Lister(), clusterClient))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	bundlePath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(bundlePath, []byte(trustbundle.EncodePEM(bundle())), 0o600); err != nil {
		t.Fatal(err)
	}
	return &hub{addr: lis.Addr().String(), ca: ca, issuer: iss, clusterClient: clusterClient, bundlePath: bundlePath}
}

// newAgent returns an SVID manager and a function that dials the hub. TLS
// sends the client certificate only during the handshake, so calls that need
// the agent SVID must use a connection dialed after the SVID was issued.
func (h *hub) newAgent(t *testing.T, claims testtoken.Claims, addon string) (*agent.Manager, func() *agent.GRPCCertificateClient) {
	t.Helper()
	claims.Audience = []string{audience}
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(h.issuer.Token(claims)), 0o600); err != nil {
		t.Fatal(err)
	}
	var m *agent.Manager
	tlsConfig, err := agent.HubTLSConfig(trustDomain, &agent.FileTrustBundle{Path: h.bundlePath},
		func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) { return m.GetClientCertificate(info) })
	if err != nil {
		t.Fatal(err)
	}
	dial := func() *agent.GRPCCertificateClient {
		conn, err := grpc.NewClient(h.addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return agent.NewGRPCCertificateClient(conn)
	}
	m, err = agent.NewManager(agent.Options{TrustDomain: trustDomain, ClusterName: cluster, AddonName: addon, TokenFile: tokenFile, Client: dial()})
	if err != nil {
		t.Fatal(err)
	}
	return m, dial
}

func TestRegistrationAgentEndToEnd(t *testing.T) {
	h := startHub(t, true)
	m, dial := h.newAgent(t, testtoken.Claims{Namespace: agentNS, Name: "klusterlet-registration-sa", UID: "sa-uid-1"}, "")

	if _, err := m.Renew(context.Background()); err != nil {
		t.Fatalf("first SVID over gRPC failed: %v", err)
	}
	if got := m.Current().Leaf.Subject.CommonName; got != "system:open-cluster-management:cluster1:registration" {
		t.Fatalf("unexpected user %s", got)
	}

	// A new connection now presents the registration agent SVID, which lets
	// the registration agent report rotated issuer keys.
	newKeys := testtoken.New("https://spoke1.example.org").JWKS()
	if err := dial().ReportIssuerKeys(context.Background(), cluster, newKeys); err != nil {
		t.Fatalf("ReportIssuerKeys failed: %v", err)
	}
	mcid, err := h.clusterClient.ClusterV1alpha1().ManagedClusterIdentities().Get(context.Background(), cluster, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if mcid.Status.PendingJWKS != string(newKeys) || mcid.Status.PendingSince == nil {
		t.Fatal("reported keys were not recorded as pending")
	}
	if mcid.Spec.JWKS == string(newKeys) {
		t.Fatal("reported keys must never be applied without a hub admin")
	}
}

func TestOnlyRegistrationAgentReportsKeys(t *testing.T) {
	h := startHub(t, true)
	m, dial := h.newAgent(t, testtoken.Claims{Namespace: agentNS, Name: "klusterlet-work-sa", UID: "sa-uid-2"}, "")
	if _, err := m.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := dial().ReportIssuerKeys(context.Background(), cluster, testtoken.New("x").JWKS())
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied for the work agent, got %v", err)
	}
}

func TestAddonAgentEndToEnd(t *testing.T) {
	h := startHub(t, true)
	m, _ := h.newAgent(t, testtoken.Claims{Namespace: "demo-agent", Name: "demo-sa", UID: "x"}, "demo")
	if _, err := m.Renew(context.Background()); err != nil {
		t.Fatalf("addon SVID over gRPC failed: %v", err)
	}
	if got := m.Current().Leaf.Subject.CommonName; got != "system:open-cluster-management:cluster:cluster1:addon:demo:agent:demo-sa" {
		t.Fatalf("unexpected addon user %s", got)
	}
}

func TestNotAcceptedIsNotReady(t *testing.T) {
	h := startHub(t, false)
	m, _ := h.newAgent(t, testtoken.Claims{Namespace: agentNS, Name: "klusterlet-registration-sa", UID: "sa-uid-1"}, "")
	_, err := m.Renew(context.Background())
	if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != certservice.ErrNotReady.Error() {
		t.Fatalf("want the uniform not-ready answer, got %v", err)
	}
}

type closer struct{ closed []string }

func (c *closer) CloseCluster(_ context.Context, name string) int {
	c.closed = append(c.closed, name)
	return 1
}

func TestCloseRevokedClusters(t *testing.T) {
	mc := &clusterv1.ManagedCluster{ObjectMeta: metav1.ObjectMeta{Name: cluster}, Spec: clusterv1.ManagedClusterSpec{HubAcceptsClient: true}}
	client := clusterfake.NewSimpleClientset(mc)
	ci := clusterinformers.NewSharedInformerFactory(client, 0)
	c := &closer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := CloseRevokedClusters(ctx, ci.Cluster().V1().ManagedClusters(), c); err != nil {
		t.Fatal(err)
	}
	ci.Start(ctx.Done())
	ci.WaitForCacheSync(ctx.Done())

	rejected := mc.DeepCopy()
	rejected.Spec.HubAcceptsClient = false
	if _, err := client.ClusterV1().ManagedClusters().Update(ctx, rejected, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(c.closed) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(c.closed) != 1 || c.closed[0] != cluster {
		t.Fatalf("want the rejected cluster's streams closed, got %v", c.closed)
	}
}
