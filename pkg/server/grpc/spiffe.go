package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	sdkauthn "open-cluster-management.io/sdk-go/pkg/server/grpc/authn"

	"open-cluster-management.io/ocm/pkg/server/services/certificate"
	"open-cluster-management.io/ocm/pkg/server/spiffe"
	"open-cluster-management.io/ocm/pkg/server/spiffe/authn"
	"open-cluster-management.io/ocm/pkg/server/spiffe/certservice"
	"open-cluster-management.io/ocm/pkg/server/spiffe/svid"
	"open-cluster-management.io/ocm/pkg/server/spiffe/trustbundle"
)

// spiffeServer holds what SPIFFE mode adds to the gRPC server: the hub server
// SVID, signed through the KMS and kept only in memory, the agent SVID
// authenticator and the CertificateService.
type spiffeServer struct {
	source        *svid.ServerSVIDSource
	tlsConfig     *tls.Config
	authenticator sdkauthn.Authenticator
	certServer    *certificate.Server
}

// setupSPIFFE must run before the informer factories start, so the listers it
// requests are started with them.
func setupSPIFFE(ctx context.Context, configPath string, clients *Clients, closer certificate.StreamCloser) (*spiffeServer, error) {
	cfg, err := spiffe.LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	signer, err := spiffe.NewSigner(cfg.Signer)
	if err != nil {
		return nil, fmt.Errorf("failed to set up the hub CA signer: %w", err)
	}

	publisher := trustbundle.NewPublisher(clients.DynamicClient, clients.KubeClient.Discovery())
	sourceOpts := cfg.SourceOptions()
	sourceOpts.Store = publisher
	source, err := svid.NewServerSVIDSource(signer, sourceOpts)
	if err != nil {
		return nil, err
	}

	clusterInformers := clients.ClusterInformers.Cluster()
	addonInformers := clients.AddOnInformers.Addon().V1alpha1()
	issuer, err := certservice.New(certservice.Options{
		TrustDomain: cfg.TrustDomain,
		Audience:    cfg.TokenAudience,
		SVIDTTL:     cfg.AgentSVIDTTL(),
		CA:          source,
		Bindings: &certificate.Bindings{
			Clusters:   clusterInformers.V1().ManagedClusters().Lister(),
			Identities: clusterInformers.V1alpha1().ManagedClusterIdentities().Lister(),
		},
		Addons: &certificate.Addons{
			ClusterManagementAddOns: addonInformers.ClusterManagementAddOns().Lister(),
			ManagedClusterAddOns:    addonInformers.ManagedClusterAddOns().Lister(),
		},
		Recorder: certservice.NewEventRecorder(clients.KubeClient, "grpc-server"),
	})
	if err != nil {
		return nil, err
	}
	if err := certificate.CloseRevokedClusters(ctx, clusterInformers.V1().ManagedClusters(), closer); err != nil {
		return nil, err
	}

	authenticator, err := authn.NewSVIDAuthenticator(cfg.TrustDomain, source.TrustBundle)
	if err != nil {
		return nil, err
	}

	go source.Run(ctx)

	return &spiffeServer{
		source:        source,
		tlsConfig:     authn.ServerTLSConfig(source.GetCertificate, source.TrustBundle),
		authenticator: authenticator,
		certServer: certificate.NewServer(issuer,
			clusterInformers.V1alpha1().ManagedClusterIdentities().Lister(), clients.ClusterClient),
	}, nil
}

// waitForServerSVID blocks until the first hub server SVID is issued, so the
// server never accepts connections it cannot complete.
func (s *spiffeServer) waitForServerSVID(ctx context.Context) error {
	logger := klog.FromContext(ctx)
	return wait.PollUntilContextCancel(ctx, time.Second, true, func(context.Context) (bool, error) {
		if _, err := s.source.GetCertificate(nil); err != nil {
			logger.V(2).Info("Waiting for the hub server SVID", "reason", err.Error())
			return false, nil
		}
		return true, nil
	})
}
