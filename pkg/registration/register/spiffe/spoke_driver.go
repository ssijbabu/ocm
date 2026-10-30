// Package spiffe is the registration agent's driver for SPIFFE identities: the
// agent authenticates to the hub with its own projected ServiceAccount token
// and keeps its agent SVID in memory. There is no bootstrap kubeconfig and no
// hub kubeconfig Secret.
package spiffe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/spf13/pflag"
	grpcgo "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/klog/v2"

	clusterv1 "open-cluster-management.io/api/cluster/v1"
	"open-cluster-management.io/sdk-go/pkg/basecontroller/events"
	"open-cluster-management.io/sdk-go/pkg/basecontroller/factory"
	sdkgrpc "open-cluster-management.io/sdk-go/pkg/cloudevents/generic/options/grpc"

	"open-cluster-management.io/ocm/pkg/common/spiffe/agent"
	"open-cluster-management.io/ocm/pkg/registration/register"
	registergrpc "open-cluster-management.io/ocm/pkg/registration/register/grpc"
	"open-cluster-management.io/ocm/pkg/server/spiffe/svid"
	"open-cluster-management.io/ocm/pkg/server/spiffe/trustbundle"
)

const (
	// issuerKeysPath is the spoke kube-apiserver's ServiceAccount issuer JWKS.
	issuerKeysPath = "/openid/v1/jwks"
	// issuerKeysCheckInterval is how often rotated issuer keys are looked for.
	issuerKeysCheckInterval = 10 * time.Minute
)

// Option configures SPIFFE mode for an agent.
type Option struct {
	// TrustDomain is the hub's trust domain. Setting it enables SPIFFE mode.
	TrustDomain string
	// GRPCServer is the hub gRPC server's host:port.
	GRPCServer string
	// TokenFile is the agent's projected ServiceAccount token, with the hub's audience.
	TokenFile string
	// TrustBundleFile is the spoke's ClusterTrustBundle, mounted as a
	// clusterTrustBundle projected volume.
	TrustBundleFile string
}

// NewOption returns an Option with the paths the klusterlet operator mounts.
func NewOption() *Option {
	return &Option{
		TokenFile:       "/var/run/secrets/open-cluster-management.io/hub-token/token",
		TrustBundleFile: "/var/run/secrets/open-cluster-management.io/hub-trust-bundle/ca.crt",
	}
}

func (o *Option) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.TrustDomain, "spiffe-trust-domain", o.TrustDomain,
		"The hub's SPIFFE trust domain. Enables SPIFFE identities.")
	fs.StringVar(&o.GRPCServer, "spiffe-grpc-server", o.GRPCServer, "The hub gRPC server's host:port in SPIFFE mode.")
	fs.StringVar(&o.TokenFile, "spiffe-token-file", o.TokenFile, "The projected ServiceAccount token with the hub's audience.")
	fs.StringVar(&o.TrustBundleFile, "spiffe-trust-bundle-file", o.TrustBundleFile, "The hub trust bundle, from the spoke's ClusterTrustBundle.")
}

// Enabled reports whether SPIFFE mode is configured.
func (o *Option) Enabled() bool {
	return o != nil && o.TrustDomain != ""
}

func (o *Option) Validate() error {
	if !o.Enabled() {
		return nil
	}
	if err := svid.ValidateTrustDomain(o.TrustDomain); err != nil {
		return err
	}
	if o.GRPCServer == "" || o.TokenFile == "" || o.TrustBundleFile == "" {
		return fmt.Errorf("--spiffe-grpc-server, --spiffe-token-file and --spiffe-trust-bundle-file are required in SPIFFE mode")
	}
	return nil
}

// HubTLSConfig returns the TLS configuration agents use for the hub: the hub
// must present its exact SPIFFE ID, and the agent presents its SVID.
func (o *Option) HubTLSConfig(clientCert agent.ClientCertificateFunc) (*tls.Config, error) {
	return agent.HubTLSConfig(o.TrustDomain, &agent.FileTrustBundle{Path: o.TrustBundleFile}, clientCert)
}

// GRPCOptions returns CloudEvents gRPC client options for a connection that
// presents the agent SVID from clientCert.
func (o *Option) GRPCOptions(clientCert agent.ClientCertificateFunc) (*sdkgrpc.GRPCOptions, error) {
	tlsConfig, err := o.HubTLSConfig(clientCert)
	if err != nil {
		return nil, err
	}
	return &sdkgrpc.GRPCOptions{Dialer: &sdkgrpc.GRPCDialer{
		URL:       o.GRPCServer,
		TLSConfig: tlsConfig,
		KeepAliveOptions: sdkgrpc.KeepAliveOptions{
			Enable:              true,
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		},
	}}, nil
}

// StartManager dials the hub certificate service and starts an SVID manager
// for an agent of clusterName. onTrustBundle may be nil; only the registration
// agent stores the hub trust bundle.
func (o *Option) StartManager(ctx context.Context, clusterName string, onTrustBundle agent.TrustBundleFunc) (*agent.Manager, *tls.Config, error) {
	var manager *agent.Manager
	tlsConfig, err := o.HubTLSConfig(func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return manager.GetClientCertificate(info)
	})
	if err != nil {
		return nil, nil, err
	}
	// This connection carries CreateCertificate, which needs no client
	// certificate, so it can be dialed before the first SVID exists.
	conn, err := grpcgo.NewClient(o.GRPCServer, grpcgo.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to the hub gRPC server %s: %w", o.GRPCServer, err)
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	manager, err = agent.NewManager(agent.Options{
		TrustDomain:   o.TrustDomain,
		ClusterName:   clusterName,
		TokenFile:     o.TokenFile,
		Client:        agent.NewGRPCCertificateClient(conn),
		OnTrustBundle: onTrustBundle,
	})
	if err != nil {
		return nil, nil, err
	}
	go manager.Run(ctx)
	return manager, tlsConfig, nil
}

// Driver is the registration agent's RegisterDriver in SPIFFE mode.
type Driver struct {
	opt         *Option
	clusterName string
	manager     *agent.Manager
	tlsConfig   *tls.Config
}

var _ register.SelfManagedDriver = &Driver{}

// NewDriver returns a Driver for the cluster in secretOption.
func NewDriver(opt *Option, secretOption register.SecretOption) (*Driver, error) {
	if err := opt.Validate(); err != nil {
		return nil, err
	}
	return &Driver{opt: opt, clusterName: secretOption.ClusterName}, nil
}

// Start obtains and renews the registration agent SVID, stores the hub trust
// bundle in the spoke's ClusterTrustBundle, and reports rotated issuer keys.
func (d *Driver) Start(ctx context.Context, spokeKubeClient kubernetes.Interface) error {
	manager, tlsConfig, err := d.opt.StartManager(ctx, d.clusterName,
		trustbundle.NewPublisher(spokeKubeClient.CertificatesV1beta1()).Publish)
	if err != nil {
		return err
	}
	d.manager, d.tlsConfig = manager, tlsConfig
	go d.reportIssuerKeys(ctx, spokeKubeClient)
	return nil
}

// ClientCertificate returns the registration agent SVID. In the singleton
// klusterlet agent the work agent runs in the same pod, as the same
// ServiceAccount, and presents the same SVID.
func (d *Driver) ClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if d.manager == nil {
		return &tls.Certificate{}, nil
	}
	return d.manager.GetClientCertificate(info)
}

// reportIssuerKeys sends the spoke issuer's keys to the hub whenever they
// change. The hub only records them as pending: a hub admin must approve them.
func (d *Driver) reportIssuerKeys(ctx context.Context, spokeKubeClient kubernetes.Interface) {
	logger := klog.FromContext(ctx)
	var reported []byte
	ticker := time.NewTicker(issuerKeysCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if d.manager.Current() == nil {
			continue
		}
		jwks, err := spokeKubeClient.CoreV1().RESTClient().Get().AbsPath(issuerKeysPath).DoRaw(ctx)
		if err != nil {
			logger.V(2).Info("Failed to read the spoke issuer keys", "error", err.Error())
			continue
		}
		if bytes.Equal(jwks, reported) {
			continue
		}
		if err := d.sendIssuerKeys(ctx, jwks); err != nil {
			logger.Info("Failed to report the spoke issuer keys to the hub", "error", err.Error())
			continue
		}
		reported = jwks
	}
}

// sendIssuerKeys dials a new connection, which presents the current agent
// SVID; the long-lived certificate connection was dialed before it existed.
func (d *Driver) sendIssuerKeys(ctx context.Context, jwks []byte) error {
	conn, err := grpcgo.NewClient(d.opt.GRPCServer, grpcgo.WithTransportCredentials(credentials.NewTLS(d.tlsConfig)))
	if err != nil {
		return err
	}
	defer conn.Close()
	return agent.NewGRPCCertificateClient(conn).ReportIssuerKeys(ctx, d.clusterName, jwks)
}

// HubHash identifies the hub by its gRPC address and trust domain.
func (d *Driver) HubHash() string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(d.opt.GRPCServer+"|"+d.opt.TrustDomain)))
}

func (d *Driver) IsHubKubeConfigValid(_ context.Context, _ register.SecretOption) (bool, error) {
	if d.manager == nil {
		return false, nil
	}
	cert := d.manager.Current()
	return cert != nil && time.Now().Before(cert.Leaf.NotAfter), nil
}

// BuildClients builds the CloudEvents clients over connections that present
// the agent SVID. They must be built after the first SVID was issued, because
// TLS sends the client certificate only when a connection is opened.
func (d *Driver) BuildClients(ctx context.Context, secretOption register.SecretOption, bootstrap bool) (*register.Clients, error) {
	if bootstrap {
		return nil, fmt.Errorf("agents using SPIFFE identities do not bootstrap; the hub admin accepts the cluster")
	}
	if d.manager == nil {
		return nil, fmt.Errorf("the SPIFFE driver has not been started")
	}
	config, err := d.opt.GRPCOptions(d.manager.GetClientCertificate)
	if err != nil {
		return nil, err
	}
	clusterClient, clusterInformer, err := registergrpc.NewClusterClients(ctx, config, secretOption.ClusterName)
	if err != nil {
		return nil, err
	}
	return registergrpc.NewAgentClients(ctx, config, secretOption.ClusterName, clusterClient, clusterInformer)
}

func (d *Driver) BuildKubeConfigFromTemplate(kubeConfig *clientcmdapi.Config) *clientcmdapi.Config {
	return kubeConfig
}

// Process is never called: SPIFFE mode keeps no credentials in Secrets.
func (d *Driver) Process(_ context.Context, _ string, secret *corev1.Secret, _ map[string][]byte,
	_ events.Recorder) (*corev1.Secret, *metav1.Condition, error) {
	return secret, nil, nil
}

func (d *Driver) InformerHandler() (cache.SharedIndexInformer, factory.EventFilterFunc) {
	return nil, nil
}

func (d *Driver) ManagedClusterDecorator(cluster *clusterv1.ManagedCluster) *clusterv1.ManagedCluster {
	return cluster
}
