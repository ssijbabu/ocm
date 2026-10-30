package agent

import (
	"context"
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc"

	certv1 "open-cluster-management.io/sdk-go/pkg/server/grpc/certificate/v1"
)

// GRPCCertificateClient calls the hub CertificateService over a connection
// dialed with HubTLSConfig.
type GRPCCertificateClient struct {
	client certv1.CertificateServiceClient
}

var _ CertificateClient = &GRPCCertificateClient{}

// NewGRPCCertificateClient returns a client using conn.
func NewGRPCCertificateClient(conn grpc.ClientConnInterface) *GRPCCertificateClient {
	return &GRPCCertificateClient{client: certv1.NewCertificateServiceClient(conn)}
}

func (c *GRPCCertificateClient) CreateCertificate(ctx context.Context, req CertificateRequest) (*CertificateResponse, error) {
	resp, err := c.client.CreateCertificate(ctx, &certv1.CreateCertificateRequest{
		ClusterName: req.ClusterName,
		AddonName:   req.AddonName,
		Csr:         req.CSR,
		Token:       req.Token,
	})
	if err != nil {
		return nil, err
	}
	if len(resp.GetCertificateChain()) == 0 {
		return nil, fmt.Errorf("the hub returned no certificate")
	}
	leaf, err := x509.ParseCertificate(resp.GetCertificateChain()[0])
	if err != nil {
		return nil, fmt.Errorf("the hub returned an invalid certificate: %w", err)
	}
	out := &CertificateResponse{Certificate: leaf}
	for _, der := range resp.GetTrustBundle() {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("the hub returned an invalid trust bundle: %w", err)
		}
		out.TrustBundle = append(out.TrustBundle, c)
	}
	return out, nil
}

// ReportIssuerKeys reports the spoke issuer's current signing keys. The
// connection must present the registration agent SVID.
func (c *GRPCCertificateClient) ReportIssuerKeys(ctx context.Context, clusterName string, jwks []byte) error {
	_, err := c.client.ReportIssuerKeys(ctx, &certv1.ReportIssuerKeysRequest{ClusterName: clusterName, Jwks: jwks})
	return err
}
