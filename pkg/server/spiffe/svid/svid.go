// Package svid issues the hub server SVID and spoke agent SVIDs through the
// hub CA signer.
package svid

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"regexp"
	"strings"
	"time"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
)

const (
	// ServerPath is the SPIFFE ID path of the hub gRPC server. Spoke agents
	// accept only this exact ID from the hub, not any certificate signed by the
	// hub CA.
	ServerPath = "/ocm/hub/grpc-server"
	// clusterPathPrefix starts every agent SVID path:
	// /ocm/cluster/{cluster}/ns/{namespace}/sa/{serviceaccount}.
	clusterPathPrefix = "/ocm/cluster/"
)

// clockSkew backdates NotBefore so peers with slightly slow clocks accept a
// fresh SVID.
const clockSkew = time.Minute

var (
	// trustDomainPattern follows the SPIFFE ID specification: lowercase
	// letters, digits, dots, dashes and underscores.
	trustDomainPattern = regexp.MustCompile(`^[a-z0-9._-]+$`)
	// segmentPattern accepts Kubernetes object names, which are also valid
	// SPIFFE path segments.
	segmentPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)
)

// ValidateTrustDomain checks a trust domain name against the SPIFFE ID spec.
func ValidateTrustDomain(trustDomain string) error {
	if trustDomain == "" || len(trustDomain) > 255 || !trustDomainPattern.MatchString(trustDomain) {
		return fmt.Errorf("trust domain %q is invalid: use lowercase letters, digits, dots, dashes and underscores", trustDomain)
	}
	return nil
}

// ServerID returns spiffe://<trustDomain>/ocm/hub/grpc-server.
func ServerID(trustDomain string) (*url.URL, error) {
	if err := ValidateTrustDomain(trustDomain); err != nil {
		return nil, err
	}
	return &url.URL{Scheme: "spiffe", Host: trustDomain, Path: ServerPath}, nil
}

// AgentIdentity is the verified identity an agent SVID carries: the spoke and
// the ServiceAccount the agent runs as there.
type AgentIdentity struct {
	Cluster        string
	Namespace      string
	ServiceAccount string
}

// AgentID returns spiffe://<trustDomain>/ocm/cluster/<cluster>/ns/<namespace>/sa/<serviceaccount>.
func AgentID(trustDomain string, id AgentIdentity) (*url.URL, error) {
	if err := ValidateTrustDomain(trustDomain); err != nil {
		return nil, err
	}
	for name, v := range map[string]string{"cluster": id.Cluster, "namespace": id.Namespace, "serviceaccount": id.ServiceAccount} {
		if len(v) > 253 || !segmentPattern.MatchString(v) {
			return nil, fmt.Errorf("%s name %q is not a valid Kubernetes name", name, v)
		}
	}
	return &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
		Path:   clusterPathPrefix + id.Cluster + "/ns/" + id.Namespace + "/sa/" + id.ServiceAccount,
	}, nil
}

// ParseAgentID extracts the agent identity from an agent SVID's SPIFFE ID and
// checks it belongs to trustDomain.
func ParseAgentID(trustDomain string, u *url.URL) (AgentIdentity, error) {
	if u == nil || u.Scheme != "spiffe" || u.Host != trustDomain || u.User != nil || u.Port() != "" ||
		u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, clusterPathPrefix) {
		return AgentIdentity{}, fmt.Errorf("%q is not an agent SPIFFE ID in trust domain %q", u, trustDomain)
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, clusterPathPrefix), "/")
	if len(parts) != 5 || parts[1] != "ns" || parts[3] != "sa" {
		return AgentIdentity{}, fmt.Errorf("%q is not an agent SPIFFE ID", u)
	}
	id := AgentIdentity{Cluster: parts[0], Namespace: parts[2], ServiceAccount: parts[4]}
	// Round-trip to apply the same name checks as AgentID.
	if want, err := AgentID(trustDomain, id); err != nil || want.String() != u.String() {
		return AgentIdentity{}, fmt.Errorf("%q is not a valid agent SPIFFE ID", u)
	}
	return id, nil
}

// ValidateCA checks that a hub CA certificate can sign SVIDs for trustDomain
// and nothing else: it must be a valid CA certificate whose critical name
// constraint permits URIs in exactly this trust domain.
func ValidateCA(ca *x509.Certificate, trustDomain string, now time.Time) error {
	if !ca.BasicConstraintsValid || !ca.IsCA {
		return fmt.Errorf("hub CA certificate %q is not a CA certificate", ca.Subject.String())
	}
	if ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("hub CA certificate %q lacks the keyCertSign key usage", ca.Subject.String())
	}
	if !ca.PermittedDNSDomainsCritical || len(ca.PermittedURIDomains) != 1 || ca.PermittedURIDomains[0] != trustDomain {
		return fmt.Errorf("hub CA certificate %q must carry a critical name constraint that permits only URIs in %q, found %v",
			ca.Subject.String(), trustDomain, ca.PermittedURIDomains)
	}
	if now.Before(ca.NotBefore) || !now.Before(ca.NotAfter) {
		return fmt.Errorf("hub CA certificate %q is valid from %s to %s, not now",
			ca.Subject.String(), ca.NotBefore.UTC().Format(time.RFC3339), ca.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// IssueServerSVID creates a new private key in memory and has the hub CA sign
// a hub server SVID for it. The SVID is valid for ttl, capped at the hub CA
// certificate's own expiry, and may only be used as a TLS server certificate.
func IssueServerSVID(ctx context.Context, ca *signer.CA, trustDomain string, dnsNames []string, ttl time.Duration, now time.Time) (*tls.Certificate, error) {
	id, err := ServerID(trustDomain)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leaf, err := sign(ctx, ca, trustDomain, &x509.Certificate{
		URIs:        []*url.URL{id},
		DNSNames:    dnsNames,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, key.Public(), ttl, now)
	if err != nil {
		return nil, fmt.Errorf("failed to sign the hub server SVID: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}, nil
}

// AgentSVIDRequest describes an agent SVID. Every field must come from data
// the hub verified, never from what the agent asked for.
type AgentSVIDRequest struct {
	TrustDomain string
	Identity    AgentIdentity
	// User and Groups become the subject's CN and O, which the hub maps to the
	// Kubernetes user and groups the agent has today.
	User   string
	Groups []string
	// PublicKey comes from the agent's certificate request, after its
	// signature was checked.
	PublicKey crypto.PublicKey
	TTL       time.Duration
}

// IssueAgentSVID has the hub CA sign a client-only agent SVID.
func IssueAgentSVID(ctx context.Context, ca *signer.CA, req AgentSVIDRequest, now time.Time) (*x509.Certificate, error) {
	id, err := AgentID(req.TrustDomain, req.Identity)
	if err != nil {
		return nil, err
	}
	if req.User == "" {
		return nil, fmt.Errorf("agent SVID user is required")
	}
	if err := CheckAgentKey(req.PublicKey); err != nil {
		return nil, err
	}
	leaf, err := sign(ctx, ca, req.TrustDomain, &x509.Certificate{
		Subject:     pkix.Name{CommonName: req.User, Organization: req.Groups},
		URIs:        []*url.URL{id},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, req.PublicKey, req.TTL, now)
	if err != nil {
		return nil, fmt.Errorf("failed to sign the agent SVID for %s: %w", id, err)
	}
	return leaf, nil
}

// CheckAgentKey accepts the key types agents generate.
func CheckAgentKey(pub crypto.PublicKey) error {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || (ecPub.Curve != elliptic.P256() && ecPub.Curve != elliptic.P384()) {
		return fmt.Errorf("agent key must be EC P-256 or P-384, got %T", pub)
	}
	return nil
}

// sign completes tmpl with a serial number, validity and SVID constraints, and
// has the hub CA sign it. The KMS signs only the digest; x509.CreateCertificate
// then verifies the signature against the hub CA certificate.
func sign(ctx context.Context, ca *signer.CA, trustDomain string, tmpl *x509.Certificate, pub crypto.PublicKey, ttl time.Duration, now time.Time) (*x509.Certificate, error) {
	if err := ValidateCA(ca.Certificate, trustDomain, now); err != nil {
		return nil, err
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("SVID lifetime must be positive, got %s", ttl)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serial
	tmpl.NotBefore = now.Add(-clockSkew)
	if tmpl.NotBefore.Before(ca.Certificate.NotBefore) {
		tmpl.NotBefore = ca.Certificate.NotBefore
	}
	tmpl.NotAfter = now.Add(ttl)
	if tmpl.NotAfter.After(ca.Certificate.NotAfter) {
		tmpl.NotAfter = ca.Certificate.NotAfter
	}
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	tmpl.BasicConstraintsValid = true
	tmpl.IsCA = false

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Certificate, pub, ca.CryptoSigner(ctx))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
