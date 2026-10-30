package grpc

import (
	"context"
	"fmt"

	"github.com/openshift/library-go/pkg/controller/controllercmd"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"k8s.io/klog/v2"

	v1alpha1addonce "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/addon/v1alpha1"
	v1beta1addonce "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/addon/v1beta1"
	clusterce "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/cluster"
	csrce "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/csr"
	eventce "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/event"
	leasece "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/lease"
	sace "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/serviceaccount"
	"open-cluster-management.io/sdk-go/pkg/cloudevents/clients/work/payload"
	pbv1 "open-cluster-management.io/sdk-go/pkg/cloudevents/generic/options/grpc/protobuf/v1"
	cloudeventsgrpc "open-cluster-management.io/sdk-go/pkg/cloudevents/server/grpc"
	grpcauthz "open-cluster-management.io/sdk-go/pkg/cloudevents/server/grpc/authz/kube"
	cemetrics "open-cluster-management.io/sdk-go/pkg/cloudevents/server/grpc/metrics"
	sdkgrpc "open-cluster-management.io/sdk-go/pkg/server/grpc"
	grpcauthn "open-cluster-management.io/sdk-go/pkg/server/grpc/authn"
	certv1 "open-cluster-management.io/sdk-go/pkg/server/grpc/certificate/v1"

	"open-cluster-management.io/ocm/pkg/server/services/addon/v1alpha1"
	"open-cluster-management.io/ocm/pkg/server/services/addon/v1beta1"
	"open-cluster-management.io/ocm/pkg/server/services/certificate"
	"open-cluster-management.io/ocm/pkg/server/services/cluster"
	"open-cluster-management.io/ocm/pkg/server/services/csr"
	"open-cluster-management.io/ocm/pkg/server/services/event"
	"open-cluster-management.io/ocm/pkg/server/services/lease"
	"open-cluster-management.io/ocm/pkg/server/services/tokenrequest"
	"open-cluster-management.io/ocm/pkg/server/services/work"
)

type GRPCServerOptions struct {
	GRPCServerConfig  string
	grpcBrokerOptions *cloudeventsgrpc.BrokerOptions

	// TLS overrides from CLI flags (set by grpc_server.go from common options).
	// These take precedence over the YAML config file loaded by LoadGRPCServerOptions.
	TLSMinVersionOverride   string
	TLSCipherSuitesOverride string

	// SPIFFEConfig enables SPIFFE identities: the hub server SVID is signed by
	// a hub CA in an external KMS and kept in memory, and agents authenticate
	// with agent SVIDs. The serving certificate and client CA files are unused.
	SPIFFEConfig string
}

func NewGRPCServerOptions() *GRPCServerOptions {
	return &GRPCServerOptions{
		grpcBrokerOptions: cloudeventsgrpc.NewBrokerOptions(),
	}
}

func (o *GRPCServerOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.GRPCServerConfig, "server-config", o.GRPCServerConfig, "Location of the server configuration file.")
	fs.StringVar(&o.SPIFFEConfig, "spiffe-config", o.SPIFFEConfig, "Location of the SPIFFE configuration file. Enables SPIFFE identities.")
	o.grpcBrokerOptions.AddFlags(fs)
}

func (o *GRPCServerOptions) Run(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
	serverOptions, err := sdkgrpc.LoadGRPCServerOptions(o.GRPCServerConfig)
	if err != nil {
		return err
	}

	// Override gRPC server TLS settings from CLI flags if provided.
	// These flags are injected by the cluster-manager operator via the deployment manifest.
	if o.TLSMinVersionOverride != "" || o.TLSCipherSuitesOverride != "" {
		if err := serverOptions.ApplyTLSFlags(o.TLSMinVersionOverride, o.TLSCipherSuitesOverride); err != nil {
			return fmt.Errorf("failed to apply gRPC TLS overrides: %w", err)
		}
		klog.Infof("gRPC server TLS overridden: minVersion=%s, cipherSuites=%v",
			o.TLSMinVersionOverride, serverOptions.CipherSuites)
	}

	clients, err := NewClients(controllerContext)
	if err != nil {
		return err
	}

	// initialize grpc broker and register services
	grpcEventServer := cloudeventsgrpc.NewGRPCBroker(o.grpcBrokerOptions)
	grpcEventServer.RegisterService(ctx, clusterce.ManagedClusterEventDataType,
		cluster.NewClusterService(clients.ClusterClient, clients.ClusterInformers.Cluster().V1().ManagedClusters()))
	grpcEventServer.RegisterService(ctx, csrce.CSREventDataType,
		csr.NewCSRService(clients.KubeClient, clients.KubeInformers.Certificates().V1().CertificateSigningRequests()))
	grpcEventServer.RegisterService(ctx, v1alpha1addonce.ManagedClusterAddOnEventDataType,
		v1alpha1.NewAddonService(clients.AddOnClient, clients.AddOnInformers.Addon().V1alpha1().ManagedClusterAddOns()))
	grpcEventServer.RegisterService(ctx, v1beta1addonce.ManagedClusterAddOnEventDataType,
		v1beta1.NewAddonService(clients.AddOnClient, clients.AddOnInformers.Addon().V1beta1().ManagedClusterAddOns()))
	grpcEventServer.RegisterService(ctx, eventce.EventEventDataType,
		event.NewEventService(clients.KubeClient))
	grpcEventServer.RegisterService(ctx, leasece.LeaseEventDataType,
		lease.NewLeaseService(clients.KubeClient, clients.KubeInformers.Coordination().V1().Leases()))
	grpcEventServer.RegisterService(ctx, payload.ManifestBundleEventDataType,
		work.NewWorkService(clients.WorkClient, clients.WorkInformers.Work().V1().ManifestWorks()))
	grpcEventServer.RegisterService(ctx, sace.TokenRequestDataType,
		tokenrequest.NewTokenRequestService(
			clients.KubeClient,
			clients.AddOnInformers.Addon().V1beta1().ManagedClusterAddOns().Lister(),
		))

	var spiffeSrv *spiffeServer
	if o.SPIFFEConfig != "" {
		if spiffeSrv, err = setupSPIFFE(ctx, o.SPIFFEConfig, clients, grpcEventServer); err != nil {
			return err
		}
	}

	// start clients
	go clients.Run(ctx)

	// initialize and run grpc server
	authorizer := grpcauthz.NewSARAuthorizer(clients.KubeClient)
	server := sdkgrpc.NewGRPCServer(serverOptions)
	if spiffeSrv != nil {
		if err := spiffeSrv.waitForServerSVID(ctx); err != nil {
			return err
		}
		server = server.
			WithTLSConfig(spiffeSrv.tlsConfig).
			WithAuthenticator(spiffeSrv.authenticator).
			WithUnauthenticatedMethods(certificate.CreateCertificateMethod).
			WithSelfAuthorizedMethods(certificate.ReportIssuerKeysMethod)
	} else {
		server = server.
			WithAuthenticator(grpcauthn.NewTokenAuthenticator(clients.KubeClient)).
			WithAuthenticator(grpcauthn.NewMtlsAuthenticator())
	}
	return server.
		WithUnaryAuthorizer(authorizer).
		WithStreamAuthorizer(authorizer).
		WithRegisterFunc(func(s *grpc.Server) {
			pbv1.RegisterCloudEventServiceServer(s, grpcEventServer)
			if spiffeSrv != nil {
				certv1.RegisterCertificateServiceServer(s, spiffeSrv.certServer)
			}
		}).
		WithExtraMetrics(cemetrics.CloudEventsGRPCMetrics()...).
		Run(ctx)
}
