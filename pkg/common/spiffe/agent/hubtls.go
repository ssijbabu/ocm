// Package agent is the spoke side of SPIFFE mode, shared by the registration,
// work and addon agents: it verifies the hub server SVID, and obtains and
// renews the agent's own SVID in memory.
package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"

	"open-cluster-management.io/ocm/pkg/server/spiffe/svid"
)

// TrustBundleSource returns the hub CA certificates the agent trusts.
type TrustBundleSource interface {
	TrustBundle() ([]*x509.Certificate, error)
}

// FileTrustBundle reads the hub trust bundle from the spoke's ClusterTrustBundle,
// mounted into the agent pod as a clusterTrustBundle projected volume. The
// spoke kubelet keeps the file current, so it is re-read when it changes.
type FileTrustBundle struct {
	Path string

	mu    sync.Mutex
	raw   []byte
	certs []*x509.Certificate
}

func (f *FileTrustBundle) TrustBundle() ([]*x509.Certificate, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read the hub trust bundle from %s: %w", f.Path, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.certs != nil && string(data) == string(f.raw) {
		return f.certs, nil
	}
	certs, err := ParsePEMCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("hub trust bundle %s: %w", f.Path, err)
	}
	f.raw, f.certs = data, certs
	return certs, nil
}

// ParsePEMCertificates parses concatenated PEM CERTIFICATE blocks.
func ParsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	return certs, nil
}

// ClientCertificateFunc returns the agent SVID to present, or an empty
// certificate before the agent has one.
type ClientCertificateFunc func(*tls.CertificateRequestInfo) (*tls.Certificate, error)

// HubTLSConfig returns the agent's TLS configuration for the hub gRPC server.
// The hub must present a hub server SVID that chains to the hub trust bundle
// and carries exactly spiffe://<trustDomain>/ocm/hub/grpc-server; checking the
// hub CA alone is not enough, because agent SVIDs come from the same hub CA.
// Under TLS 1.3 this check completes before the agent sends its own SVID, so a
// fake hub never sees it.
func HubTLSConfig(trustDomain string, bundle TrustBundleSource, clientCert ClientCertificateFunc) (*tls.Config, error) {
	hubID, err := svid.ServerID(trustDomain)
	if err != nil {
		return nil, err
	}
	if bundle == nil {
		return nil, fmt.Errorf("a hub trust bundle source is required")
	}
	if clientCert == nil {
		clientCert = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	}
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		GetClientCertificate: clientCert,
		// Standard verification checks host names against the hub CA bundle
		// loaded once. VerifyConnection replaces it with a check against the
		// current hub trust bundle and the hub's exact SPIFFE ID.
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyHub(cs.PeerCertificates, hubID.String(), bundle)
		},
	}, nil
}

func verifyHub(chain []*x509.Certificate, hubID string, bundle TrustBundleSource) error {
	if len(chain) == 0 {
		return fmt.Errorf("the hub presented no certificate")
	}
	roots, err := bundle.TrustBundle()
	if err != nil {
		return err
	}
	rootPool := x509.NewCertPool()
	for _, c := range roots {
		rootPool.AddCert(c)
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	leaf := chain[0]
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("the hub server SVID is not signed by the hub CA: %w", err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != hubID {
		return fmt.Errorf("the hub presented SPIFFE ID %v, want exactly %s", leaf.URIs, hubID)
	}
	return nil
}
