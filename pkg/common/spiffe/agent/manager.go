package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math"
	mathrand "math/rand/v2"
	"os"
	"strings"
	"sync"
	"time"

	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	"open-cluster-management.io/ocm/pkg/server/spiffe/svid"
)

// CertificateRequest is what an agent sends to the hub certificate service.
type CertificateRequest struct {
	ClusterName string
	AddonName   string
	CSR         []byte
	Token       string
}

// CertificateResponse is what the hub certificate service returns.
type CertificateResponse struct {
	Certificate *x509.Certificate
	TrustBundle []*x509.Certificate
}

// CertificateClient calls the hub certificate service over a connection
// configured with HubTLSConfig.
type CertificateClient interface {
	CreateCertificate(ctx context.Context, req CertificateRequest) (*CertificateResponse, error)
}

// TrustBundleFunc stores a hub trust bundle the hub returned, for example in
// the spoke's ClusterTrustBundle. Only the registration agent sets it.
type TrustBundleFunc func(ctx context.Context, bundle []*x509.Certificate) error

// Options configures a Manager.
type Options struct {
	TrustDomain string
	ClusterName string
	// AddonName is set for addon agents.
	AddonName string
	// TokenFile is the agent's projected ServiceAccount token, with the hub's
	// audience.
	TokenFile string
	Client    CertificateClient
	// OnTrustBundle receives the hub trust bundle from each renewal.
	OnTrustBundle TrustBundleFunc
	// Jitter spreads renewals by up to this fraction of half the lifetime, so
	// agents do not all renew together. Defaults to 0.1.
	Jitter float64
	// MinRetry and MaxRetry bound the exponential backoff after a failed
	// renewal. Defaults are 1 second and 5 minutes.
	MinRetry time.Duration
	MaxRetry time.Duration
	Clock    clock.WithTicker
}

// Manager keeps the agent's SVID and private key in memory and renews them at
// half the SVID's lifetime. Renewal authenticates with the projected token,
// not with the current SVID, so an agent whose SVID expired while it was
// offline renews the same way.
type Manager struct {
	opts Options

	mu      sync.RWMutex
	current *tls.Certificate
}

// NewManager validates opts and returns a Manager. Call Run to start it.
func NewManager(opts Options) (*Manager, error) {
	if err := svid.ValidateTrustDomain(opts.TrustDomain); err != nil {
		return nil, err
	}
	if opts.ClusterName == "" || opts.TokenFile == "" || opts.Client == nil {
		return nil, fmt.Errorf("cluster name, token file and certificate client are required")
	}
	if opts.Jitter == 0 {
		opts.Jitter = 0.1
	}
	if opts.Jitter < 0 || opts.Jitter > 0.5 {
		return nil, fmt.Errorf("jitter must be between 0 and 0.5")
	}
	if opts.MinRetry == 0 {
		opts.MinRetry = time.Second
	}
	if opts.MaxRetry == 0 {
		opts.MaxRetry = 5 * time.Minute
	}
	if opts.Clock == nil {
		opts.Clock = clock.RealClock{}
	}
	return &Manager{opts: opts}, nil
}

// GetClientCertificate returns the agent SVID for tls.Config, or an empty
// certificate before the first one is issued, which the certificate service
// accepts.
func (m *Manager) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.current == nil {
		return &tls.Certificate{}, nil
	}
	return m.current, nil
}

// Current returns the agent SVID, or nil before the first one is issued.
func (m *Manager) Current() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

// Run renews until ctx is done. Failures keep the current SVID and retry with
// exponential backoff; the hub answers "not ready" until the spoke is accepted.
func (m *Manager) Run(ctx context.Context) {
	logger := klog.FromContext(ctx)
	retry := m.opts.MinRetry
	for {
		wait, err := m.Renew(ctx)
		if err != nil {
			logger.Info("Agent SVID renewal failed, keeping the current one", "error", err.Error(), "retryIn", retry)
			wait = retry
			retry = time.Duration(math.Min(float64(retry*2), float64(m.opts.MaxRetry)))
		} else {
			retry = m.opts.MinRetry
		}
		timer := m.opts.Clock.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C():
		}
	}
}

// Renew gets a new agent SVID and returns when the next renewal is due.
func (m *Manager) Renew(ctx context.Context) (time.Duration, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return 0, err
	}
	// The hub ignores the request's subject; it only uses the public key.
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return 0, err
	}
	// Re-read every time: the kubelet rotates the projected token.
	token, err := os.ReadFile(m.opts.TokenFile)
	if err != nil {
		return 0, fmt.Errorf("failed to read the projected ServiceAccount token: %w", err)
	}

	resp, err := m.opts.Client.CreateCertificate(ctx, CertificateRequest{
		ClusterName: m.opts.ClusterName,
		AddonName:   m.opts.AddonName,
		CSR:         csr,
		Token:       strings.TrimSpace(string(token)),
	})
	if err != nil {
		return 0, err
	}
	if err := m.check(resp, key); err != nil {
		return 0, fmt.Errorf("the hub returned an unusable agent SVID: %w", err)
	}

	if m.opts.OnTrustBundle != nil {
		if err := m.opts.OnTrustBundle(ctx, resp.TrustBundle); err != nil {
			return 0, fmt.Errorf("failed to store the hub trust bundle: %w", err)
		}
	}

	cert := &tls.Certificate{Certificate: [][]byte{resp.Certificate.Raw}, PrivateKey: key, Leaf: resp.Certificate}
	m.mu.Lock()
	m.current = cert
	m.mu.Unlock()

	now := m.opts.Clock.Now()
	half := resp.Certificate.NotAfter.Sub(now) / 2
	jitter := time.Duration(mathrand.Float64() * m.opts.Jitter * float64(half))
	klog.FromContext(ctx).Info("Obtained agent SVID",
		"spiffeID", resp.Certificate.URIs[0].String(), "serial", resp.Certificate.SerialNumber.String(), "notAfter", resp.Certificate.NotAfter)
	if wait := half - jitter; wait > time.Second {
		return wait, nil
	}
	return time.Second, nil
}

// check makes sure the SVID is for this agent's key, is a client-only agent
// SVID for this spoke, and chains to the hub trust bundle that came with it.
func (m *Manager) check(resp *CertificateResponse, key *ecdsa.PrivateKey) error {
	if resp == nil || resp.Certificate == nil || len(resp.TrustBundle) == 0 {
		return fmt.Errorf("missing SVID or hub trust bundle")
	}
	leaf := resp.Certificate
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return fmt.Errorf("SVID is not for this agent's key")
	}
	if len(leaf.URIs) != 1 {
		return fmt.Errorf("SVID must carry exactly one SPIFFE ID")
	}
	id, err := svid.ParseAgentID(m.opts.TrustDomain, leaf.URIs[0])
	if err != nil {
		return err
	}
	if id.Cluster != m.opts.ClusterName {
		return fmt.Errorf("SVID is for spoke %q, not %q", id.Cluster, m.opts.ClusterName)
	}
	for _, u := range leaf.ExtKeyUsage {
		if u != x509.ExtKeyUsageClientAuth {
			return fmt.Errorf("SVID must be client-only")
		}
	}
	roots := x509.NewCertPool()
	for _, c := range resp.TrustBundle {
		roots.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: m.opts.Clock.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return err
	}
	return nil
}
