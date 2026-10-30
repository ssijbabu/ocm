// Package certificate serves the hub's SPIFFE CertificateService over gRPC and
// backs it with the ManagedClusterIdentity, ManagedCluster and add-on
// resources on the hub.
package certificate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"

	addonlisterv1alpha1 "open-cluster-management.io/api/client/addon/listers/addon/v1alpha1"
	clusterclient "open-cluster-management.io/api/client/cluster/clientset/versioned"
	clusterinformerv1 "open-cluster-management.io/api/client/cluster/informers/externalversions/cluster/v1"
	clusterlisterv1 "open-cluster-management.io/api/client/cluster/listers/cluster/v1"
	clusterlisterv1alpha1 "open-cluster-management.io/api/client/cluster/listers/cluster/v1alpha1"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
	sdkauthn "open-cluster-management.io/sdk-go/pkg/server/grpc/authn"
	certv1 "open-cluster-management.io/sdk-go/pkg/server/grpc/certificate/v1"

	"open-cluster-management.io/ocm/pkg/registration/hub/user"
	"open-cluster-management.io/ocm/pkg/server/spiffe/certservice"
	"open-cluster-management.io/ocm/pkg/server/spiffe/satoken"
)

const (
	// CreateCertificateMethod is reachable without a client certificate.
	CreateCertificateMethod = "/io.openclustermanagement.certificate.v1.CertificateService/CreateCertificate"
	// ReportIssuerKeysMethod authorizes its caller itself.
	ReportIssuerKeysMethod = "/io.openclustermanagement.certificate.v1.CertificateService/ReportIssuerKeys"

	// RegistrationAgent is the agent name the registration agent's
	// ServiceAccount is bound with in ManagedClusterIdentity.
	RegistrationAgent = "registration"
)

// Server implements the gRPC CertificateService.
type Server struct {
	certv1.UnimplementedCertificateServiceServer

	issuer        *certservice.Service
	identities    clusterlisterv1alpha1.ManagedClusterIdentityLister
	clusterClient clusterclient.Interface
}

// NewServer returns the gRPC CertificateService backed by issuer.
func NewServer(issuer *certservice.Service, identities clusterlisterv1alpha1.ManagedClusterIdentityLister, clusterClient clusterclient.Interface) *Server {
	return &Server{issuer: issuer, identities: identities, clusterClient: clusterClient}
}

func (s *Server) CreateCertificate(ctx context.Context, req *certv1.CreateCertificateRequest) (*certv1.CreateCertificateResponse, error) {
	source := ""
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		source = hostOf(p.Addr.String())
	}
	resp, err := s.issuer.CreateCertificate(ctx, certservice.Request{
		ClusterName: req.GetClusterName(),
		AddonName:   req.GetAddonName(),
		CSR:         req.GetCsr(),
		Token:       req.GetToken(),
		Source:      source,
	})
	switch {
	case errors.Is(err, certservice.ErrUnavailable):
		return nil, status.Error(codes.Unavailable, certservice.ErrUnavailable.Error())
	case err != nil:
		return nil, status.Error(codes.FailedPrecondition, certservice.ErrNotReady.Error())
	}
	out := &certv1.CreateCertificateResponse{CertificateChain: [][]byte{resp.Certificate.Raw}}
	for _, c := range resp.TrustBundle {
		out.TrustBundle = append(out.TrustBundle, c.Raw)
	}
	return out, nil
}

// ReportIssuerKeys records new issuer keys as pending on the cluster's
// ManagedClusterIdentity. Only the cluster's registration agent may call it,
// and the keys take effect only after a hub admin copies them into spec.jwks.
func (s *Server) ReportIssuerKeys(ctx context.Context, req *certv1.ReportIssuerKeysRequest) (*certv1.ReportIssuerKeysResponse, error) {
	cluster := req.GetClusterName()
	caller, _ := ctx.Value(sdkauthn.ContextUserKey).(string)
	if cluster == "" || caller != user.SubjectPrefix+cluster+":"+RegistrationAgent {
		return nil, status.Error(codes.PermissionDenied, "only the cluster's registration agent may report its issuer keys")
	}
	if len(req.GetJwks()) > 64*1024 {
		return nil, status.Error(codes.InvalidArgument, "JWKS is too large")
	}
	if _, err := satoken.ParseJWKS(req.GetJwks()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	mcid, err := s.identities.Get(cluster)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, certservice.ErrNotReady.Error())
	}
	jwks := string(req.GetJwks())
	if mcid.Spec.JWKS == "" || mcid.Spec.JWKS == jwks || mcid.Status.PendingJWKS == jwks {
		// Discovered keys refresh on their own; identical keys need nothing.
		return &certv1.ReportIssuerKeysResponse{}, nil
	}
	updated := mcid.DeepCopy()
	updated.Status.PendingJWKS = jwks
	now := metav1.NewTime(time.Now())
	updated.Status.PendingSince = &now
	if _, err := s.clusterClient.ClusterV1alpha1().ManagedClusterIdentities().UpdateStatus(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return nil, status.Error(codes.Unavailable, "failed to record the reported keys")
	}
	klog.FromContext(ctx).Info("Recorded new issuer keys for approval by a hub admin", "cluster", cluster)
	return &certv1.ReportIssuerKeysResponse{}, nil
}

func hostOf(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

// Bindings looks up a cluster's binding: the cluster must be accepted and have
// a ManagedClusterIdentity.
type Bindings struct {
	Clusters   clusterlisterv1.ManagedClusterLister
	Identities clusterlisterv1alpha1.ManagedClusterIdentityLister
}

func (b *Bindings) Lookup(_ context.Context, cluster string) (*certservice.Binding, error) {
	mc, err := b.Clusters.Get(cluster)
	if err != nil {
		return nil, err
	}
	if !mc.Spec.HubAcceptsClient || mc.DeletionTimestamp != nil {
		return nil, fmt.Errorf("cluster %s is not accepted", cluster)
	}
	mcid, err := b.Identities.Get(cluster)
	if err != nil {
		return nil, err
	}
	binding := &certservice.Binding{Issuer: mcid.Spec.Issuer, PinnedJWKS: []byte(mcid.Spec.JWKS)}
	for _, sa := range mcid.Spec.ServiceAccounts {
		binding.ServiceAccounts = append(binding.ServiceAccounts, certservice.AllowedServiceAccount{
			Namespace: sa.Namespace, Name: sa.Name, UID: sa.UID, Agent: sa.Agent,
		})
	}
	return binding, nil
}

// Addons looks up the ServiceAccount an add-on declares in its hub-side
// ClusterManagementAddOn, if the add-on is enabled for the cluster. The
// ManagedClusterAddOn status, which agents can write, is never used for it.
type Addons struct {
	ClusterManagementAddOns addonlisterv1alpha1.ClusterManagementAddOnLister
	ManagedClusterAddOns    addonlisterv1alpha1.ManagedClusterAddOnLister
}

func (a *Addons) Lookup(_ context.Context, cluster, addon string) (*certservice.AddonServiceAccount, error) {
	cma, err := a.ClusterManagementAddOns.Get(addon)
	if err != nil {
		return nil, err
	}
	if cma.Spec.SPIFFERegistration == nil {
		return nil, fmt.Errorf("add-on %s does not declare a SPIFFE registration", addon)
	}
	mca, err := a.ManagedClusterAddOns.ManagedClusterAddOns(cluster).Get(addon)
	if err != nil {
		return nil, err
	}
	if mca.DeletionTimestamp != nil {
		return nil, fmt.Errorf("add-on %s is being disabled for cluster %s", addon, cluster)
	}
	return &certservice.AddonServiceAccount{
		Namespace: cma.Spec.SPIFFERegistration.Namespace,
		Name:      cma.Spec.SPIFFERegistration.ServiceAccountName,
	}, nil
}

// StreamCloser ends every stream of a cluster. The gRPC broker implements it.
type StreamCloser interface {
	CloseCluster(ctx context.Context, clusterName string) int
}

// CloseRevokedClusters closes a cluster's open streams as soon as it is
// rejected or deleted, so the agents reconnect and are refused by the
// authorizer instead of keeping streams opened with still-valid SVIDs.
func CloseRevokedClusters(ctx context.Context, informer clusterinformerv1.ManagedClusterInformer, closer StreamCloser) error {
	logger := klog.FromContext(ctx)
	closeCluster := func(name, reason string) {
		if n := closer.CloseCluster(ctx, name); n > 0 {
			logger.Info("Closed streams of revoked cluster", "cluster", name, "reason", reason, "streams", n)
		}
	}
	_, err := informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldMC, ok1 := oldObj.(*clusterv1.ManagedCluster)
			newMC, ok2 := newObj.(*clusterv1.ManagedCluster)
			if ok1 && ok2 && oldMC.Spec.HubAcceptsClient && !newMC.Spec.HubAcceptsClient {
				closeCluster(newMC.Name, "rejected")
			}
		},
		DeleteFunc: func(obj interface{}) {
			if tombstone, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				obj = tombstone.Obj
			}
			if mc, ok := obj.(*clusterv1.ManagedCluster); ok {
				closeCluster(mc.Name, "deleted")
			}
		},
	})
	return err
}
