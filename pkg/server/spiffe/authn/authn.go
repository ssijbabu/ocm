// Package authn authenticates spoke agents to the hub gRPC server by their
// agent SVIDs, and builds the hub's TLS configuration.
package authn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	sdkauthn "open-cluster-management.io/sdk-go/pkg/server/grpc/authn"

	"open-cluster-management.io/ocm/pkg/registration/hub/user"
	"open-cluster-management.io/ocm/pkg/server/spiffe/svid"
)

// TrustBundleFunc returns the hub CA certificates agent SVIDs may chain to.
// svid.ServerSVIDSource.TrustBundle implements it.
type TrustBundleFunc func() []*x509.Certificate

// SVIDAuthenticator maps an agent SVID to the Kubernetes user and groups the
// agent has today, so SubjectAccessReview and hub RBAC stay unchanged.
type SVIDAuthenticator struct {
	trustDomain string
	trustBundle TrustBundleFunc
}

// NewSVIDAuthenticator returns an authenticator for trustDomain.
func NewSVIDAuthenticator(trustDomain string, trustBundle TrustBundleFunc) (*SVIDAuthenticator, error) {
	if err := svid.ValidateTrustDomain(trustDomain); err != nil {
		return nil, err
	}
	if trustBundle == nil {
		return nil, fmt.Errorf("a hub trust bundle source is required")
	}
	return &SVIDAuthenticator{trustDomain: trustDomain, trustBundle: trustBundle}, nil
}

// Authenticate implements the sdk-go gRPC authenticator interface.
func (a *SVIDAuthenticator) Authenticate(ctx context.Context) (context.Context, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ctx, status.Error(codes.Unauthenticated, "no peer found")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return ctx, status.Error(codes.Unauthenticated, "no agent SVID presented")
	}
	userName, groups, err := a.Identify(tlsInfo.State.PeerCertificates)
	if err != nil {
		return ctx, status.Error(codes.Unauthenticated, err.Error())
	}
	ctx = context.WithValue(ctx, sdkauthn.ContextUserKey, userName)
	ctx = context.WithValue(ctx, sdkauthn.ContextGroupsKey, groups)
	return ctx, nil
}

// Identify verifies an agent SVID chain against the hub trust bundle itself,
// rather than relying on whatever client CAs the TLS listener was given, and
// returns the agent's user and groups.
func (a *SVIDAuthenticator) Identify(chain []*x509.Certificate) (string, []string, error) {
	leaf := chain[0]
	roots := x509.NewCertPool()
	for _, c := range a.trustBundle() {
		roots.AddCert(c)
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return "", nil, fmt.Errorf("agent SVID is not signed by the hub CA: %v", err)
	}
	if len(leaf.URIs) != 1 {
		return "", nil, fmt.Errorf("agent SVID must carry exactly one SPIFFE ID")
	}
	id, err := svid.ParseAgentID(a.trustDomain, leaf.URIs[0])
	if err != nil {
		return "", nil, err
	}

	// The hub sets CN and O at issuance from verified data. Checking they
	// belong to the SPIFFE ID's spoke keeps one spoke's SVID from ever acting
	// for another, even if issuance had a bug.
	userName := leaf.Subject.CommonName
	clusterUser := user.SubjectPrefix + id.Cluster + ":"
	addonUser := user.SubjectPrefix + "cluster:" + id.Cluster + ":addon:"
	if !strings.HasPrefix(userName, clusterUser) && !strings.HasPrefix(userName, addonUser) {
		return "", nil, fmt.Errorf("agent SVID user %q does not belong to spoke %q", userName, id.Cluster)
	}
	for _, g := range leaf.Subject.Organization {
		if g != user.SubjectPrefix+id.Cluster && g != user.ManagedClustersGroup &&
			!strings.HasPrefix(g, user.SubjectPrefix+"cluster:"+id.Cluster+":addon:") &&
			!strings.HasPrefix(g, user.SubjectPrefix+"addon:") {
			return "", nil, fmt.Errorf("agent SVID group %q does not belong to spoke %q", g, id.Cluster)
		}
	}
	return userName, leaf.Subject.Organization, nil
}

// ServerSVIDFunc returns the current hub server SVID.
// svid.ServerSVIDSource.GetCertificate implements it.
type ServerSVIDFunc func(*tls.ClientHelloInfo) (*tls.Certificate, error)

// ServerTLSConfig returns the hub gRPC server's TLS configuration: TLS 1.3,
// the hub server SVID from memory, and agent SVIDs accepted only from the
// current hub trust bundle. Client certificates are optional at the TLS layer
// because new agents call the certificate service before they have an SVID;
// every other service requires one through SVIDAuthenticator.
func ServerTLSConfig(serverSVID ServerSVIDFunc, trustBundle TrustBundleFunc) *tls.Config {
	base := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: serverSVID,
		ClientAuth:     tls.VerifyClientCertIfGiven,
	}
	base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		cfg := base.Clone()
		cfg.GetConfigForClient = nil
		pool := x509.NewCertPool()
		for _, c := range trustBundle() {
			pool.AddCert(c)
		}
		cfg.ClientCAs = pool
		return cfg, nil
	}
	return base
}
