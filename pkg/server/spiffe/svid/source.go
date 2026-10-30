package svid

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
)

// RotationState is what a restarted hub gRPC server needs to resume a hub CA
// rotation where it left off. Certificates are named by Fingerprint.
type RotationState struct {
	Active       string      `json:"active"`
	Pending      string      `json:"pending,omitempty"`
	PendingSince *time.Time  `json:"pendingSince,omitempty"`
	Retired      []RetiredCA `json:"retired,omitempty"`
}

// RetiredCA is a retired hub CA certificate and when it leaves the bundle.
type RetiredCA struct {
	Certificate string    `json:"certificate"`
	RetireAt    time.Time `json:"retireAt"`
}

// Fingerprint names a certificate in a RotationState: the hex SHA-256 of its DER.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// RotationStateAnnotation holds the rotation state on the hub trust bundle.
const RotationStateAnnotation = "open-cluster-management.io/spiffe-hub-ca-rotation"

// TrustBundleStore publishes the hub trust bundle, active hub CA certificate
// first, together with the rotation state, and reads both back after a
// restart. Load returns no certificates and an empty state if nothing was
// published yet.
type TrustBundleStore interface {
	Load(ctx context.Context) ([]*x509.Certificate, string, error)
	Save(ctx context.Context, bundle []*x509.Certificate, state string) error
}

// Options configures a ServerSVIDSource.
type Options struct {
	TrustDomain string
	// DNSNames are added to the hub server SVID for clients that also check
	// host names. Spoke agents rely on the SPIFFE ID, not on these.
	DNSNames []string
	// TTL is the hub server SVID lifetime. Defaults to 1 hour.
	TTL time.Duration
	// MaxAgentSVIDLifetime is the longest lifetime of any agent SVID. A new hub
	// CA is published this long before it signs anything, so every spoke agent
	// renews and learns it first, and a retired hub CA stays in the hub trust
	// bundle this long, so SVIDs it signed keep verifying. Defaults to 1 hour.
	MaxAgentSVIDLifetime time.Duration
	// CACheckInterval is how often the KMS is checked for a rotated hub CA.
	// Defaults to 1 minute.
	CACheckInterval time.Duration
	// RetryInterval is the wait after a failed sync, for example while the KMS
	// is unavailable. Defaults to 10 seconds.
	RetryInterval time.Duration
	// Store publishes the hub trust bundle and keeps the rotation state, so a
	// restart does not cut a rotation short.
	Store TrustBundleStore
	Clock clock.WithTicker
}

type retiredCA struct {
	cert     *x509.Certificate
	retireAt time.Time
}

// ServerSVIDSource keeps a hub server SVID, signed through the KMS, in memory
// and renews it at half its lifetime. It also maintains the hub trust bundle
// and rolls hub CA rotations through it in three stages:
//
//  1. pending: the new hub CA certificate is published but signs nothing, so
//     spoke agents pick it up at their next renewal;
//  2. active: after MaxAgentSVIDLifetime the new hub CA signs the hub server
//     SVID, and the old one is retired;
//  3. retired: the old hub CA certificate stays published for another
//     MaxAgentSVIDLifetime, until every SVID it signed has expired.
//
// Signing the hub server SVID with a new hub CA straight away would lock out
// spoke agents that have not renewed yet: they could not verify the hub, so
// they could not renew. Nothing here is written to disk.
//
// The stages are saved with the hub trust bundle. After a restart the source
// resumes them, signing with the earlier hub CA key version through
// signer.ForCertificate until the new hub CA has been published for
// MaxAgentSVIDLifetime.
type ServerSVIDSource struct {
	signer signer.Signer
	opts   Options

	mu           sync.RWMutex
	active       *signer.CA
	pending      *signer.CA
	pendingSince time.Time
	retired      []retiredCA

	current  *tls.Certificate
	issuedBy []byte
	renewAt  time.Time

	restored       bool
	published      []*x509.Certificate
	publishedState string
}

// NewServerSVIDSource validates opts and returns a source. Call Run to start it.
func NewServerSVIDSource(s signer.Signer, opts Options) (*ServerSVIDSource, error) {
	if s == nil {
		return nil, fmt.Errorf("a hub CA signer is required")
	}
	if err := ValidateTrustDomain(opts.TrustDomain); err != nil {
		return nil, err
	}
	if opts.TTL == 0 {
		opts.TTL = time.Hour
	}
	if opts.MaxAgentSVIDLifetime == 0 {
		opts.MaxAgentSVIDLifetime = time.Hour
	}
	if opts.CACheckInterval == 0 {
		opts.CACheckInterval = time.Minute
	}
	if opts.RetryInterval == 0 {
		opts.RetryInterval = 10 * time.Second
	}
	if opts.TTL < 0 || opts.MaxAgentSVIDLifetime < 0 || opts.CACheckInterval < 0 || opts.RetryInterval < 0 {
		return nil, fmt.Errorf("lifetimes and intervals must be positive")
	}
	if opts.Clock == nil {
		opts.Clock = clock.RealClock{}
	}
	return &ServerSVIDSource{signer: s, opts: opts}, nil
}

// GetCertificate returns the current hub server SVID, for tls.Config.
func (s *ServerSVIDSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return nil, fmt.Errorf("the hub server SVID has not been issued yet")
	}
	return s.current, nil
}

// TrustBundle returns the hub CA certificates agent SVIDs may chain to: the
// active one first, then a pending one, then retired ones.
func (s *ServerSVIDSource) TrustBundle() []*x509.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bundleLocked()
}

// ActiveCA returns the hub CA that currently signs, or nil before the first sync.
func (s *ServerSVIDSource) ActiveCA() *signer.CA {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

// Run syncs until ctx is done. A failed sync, such as during a KMS outage,
// keeps the current hub server SVID in place and retries.
func (s *ServerSVIDSource) Run(ctx context.Context) {
	logger := klog.FromContext(ctx)
	for {
		wait, err := s.sync(ctx)
		if err != nil {
			logger.Error(err, "Failed to sync the hub server SVID, keeping the current one", "retryIn", s.opts.RetryInterval)
			wait = s.opts.RetryInterval
		}
		timer := s.opts.Clock.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C():
		}
	}
}

// sync reads the hub CA from the KMS, advances any rotation, publishes the hub
// trust bundle if it changed, renews the hub server SVID if due, and returns
// how long to wait before the next sync.
func (s *ServerSVIDSource) sync(ctx context.Context) (time.Duration, error) {
	logger := klog.FromContext(ctx)
	now := s.opts.Clock.Now()

	latest, err := s.signer.Current(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to read the hub CA from the KMS: %w", err)
	}
	if err := ValidateCA(latest.Certificate, s.opts.TrustDomain, now); err != nil {
		return 0, err
	}
	if !s.restored {
		if err := s.restore(ctx, latest, now); err != nil {
			return 0, err
		}
		s.restored = true
	}

	s.mu.Lock()
	s.advanceRotationLocked(ctx, latest, now)
	bundle := s.bundleLocked()
	state, err := s.stateLocked()
	publish := !sameCerts(bundle, s.published) || state != s.publishedState
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}

	if publish && s.opts.Store != nil {
		if err := s.opts.Store.Save(ctx, bundle, state); err != nil {
			return 0, fmt.Errorf("failed to publish the hub trust bundle: %w", err)
		}
		logger.Info("Published the hub trust bundle", "certificates", len(bundle))
	}

	s.mu.Lock()
	s.published, s.publishedState = bundle, state
	active := s.active
	due := s.current == nil || !bytes.Equal(s.issuedBy, active.Certificate.Raw) || !now.Before(s.renewAt)
	s.mu.Unlock()

	if due {
		cert, err := IssueServerSVID(ctx, active, s.opts.TrustDomain, s.opts.DNSNames, s.opts.TTL, now)
		if err != nil {
			return 0, err
		}
		s.mu.Lock()
		s.current = cert
		s.issuedBy = active.Certificate.Raw
		s.renewAt = now.Add(cert.Leaf.NotAfter.Sub(now) / 2)
		s.mu.Unlock()
		logger.Info("Issued the hub server SVID",
			"spiffeID", cert.Leaf.URIs[0].String(), "serial", cert.Leaf.SerialNumber.String(), "notAfter", cert.Leaf.NotAfter)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	wait := s.opts.CACheckInterval
	if d := s.renewAt.Sub(now); d < wait {
		wait = d
	}
	if s.pending != nil {
		if d := s.pendingSince.Add(s.opts.MaxAgentSVIDLifetime).Sub(now); d < wait {
			wait = d
		}
	}
	if wait < time.Second {
		wait = time.Second
	}
	return wait, nil
}

func (s *ServerSVIDSource) advanceRotationLocked(ctx context.Context, latest *signer.CA, now time.Time) {
	logger := klog.FromContext(ctx)
	switch {
	case s.active == nil:
		s.active = latest
	case bytes.Equal(latest.Certificate.Raw, s.active.Certificate.Raw):
		// Refresh the handle, and drop a pending hub CA the admin rolled back.
		s.active = latest
		if s.pending != nil {
			logger.Info("Hub CA rotation was rolled back, dropping the pending hub CA certificate",
				"subject", s.pending.Certificate.Subject.String())
			s.pending = nil
		}
	case s.pending != nil && bytes.Equal(latest.Certificate.Raw, s.pending.Certificate.Raw):
		s.pending = latest
		if !now.Before(s.pendingSince.Add(s.opts.MaxAgentSVIDLifetime)) {
			s.retired = append(s.retired, retiredCA{cert: s.active.Certificate, retireAt: now.Add(s.opts.MaxAgentSVIDLifetime)})
			s.active, s.pending = s.pending, nil
			logger.Info("Hub CA rotation: the new hub CA now signs", "subject", s.active.Certificate.Subject.String())
		}
	default:
		s.pending, s.pendingSince = latest, now
		logger.Info("Hub CA rotation: publishing the new hub CA certificate before it signs",
			"subject", latest.Certificate.Subject.String(), "activatesAt", now.Add(s.opts.MaxAgentSVIDLifetime))
	}

	kept := s.retired[:0]
	for _, r := range s.retired {
		if now.Before(r.retireAt) {
			kept = append(kept, r)
		}
	}
	s.retired = kept
}

// restore resumes the rotation saved with the published hub trust bundle. If
// the KMS now holds a newer hub CA than the saved active one, the saved one
// keeps signing until the newer one has been published long enough; signing
// with the newer one straight away would lock out every spoke agent that has
// not learned it yet.
func (s *ServerSVIDSource) restore(ctx context.Context, latest *signer.CA, now time.Time) error {
	if s.opts.Store == nil {
		return nil
	}
	logger := klog.FromContext(ctx)
	published, raw, err := s.opts.Store.Load(ctx)
	if err != nil {
		return fmt.Errorf("failed to read the published hub trust bundle: %w", err)
	}
	if raw == "" {
		return nil
	}
	state := &RotationState{}
	if err := json.Unmarshal([]byte(raw), state); err != nil {
		logger.Error(err, "Ignoring an unreadable hub CA rotation state")
		return nil
	}
	byFingerprint := map[string]*x509.Certificate{}
	for _, c := range published {
		byFingerprint[Fingerprint(c)] = c
	}
	activeCert := byFingerprint[state.Active]
	if activeCert == nil {
		logger.Info("The saved active hub CA is not in the published hub trust bundle, starting afresh")
		return nil
	}

	var retired []retiredCA
	for _, r := range state.Retired {
		if c := byFingerprint[r.Certificate]; c != nil && now.Before(r.RetireAt) {
			retired = append(retired, retiredCA{cert: c, retireAt: r.RetireAt})
		}
	}

	active := latest
	if !bytes.Equal(activeCert.Raw, latest.Certificate.Raw) {
		if active, err = s.signer.ForCertificate(ctx, activeCert); err != nil {
			return fmt.Errorf("a hub CA rotation is in progress, but the hub CA %q that spoke agents trust cannot sign: %w; "+
				"re-enable its key version in the KMS, or remove the annotation %s from the hub trust bundle "+
				"to sign with the new hub CA at once, which locks out spoke agents that have not learned it",
				activeCert.Subject.String(), err, RotationStateAnnotation)
		}
		if err := ValidateCA(active.Certificate, s.opts.TrustDomain, now); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.active, s.retired = active, retired
	if state.Pending == Fingerprint(latest.Certificate) && state.PendingSince != nil {
		s.pending, s.pendingSince = latest, *state.PendingSince
	}
	logger.Info("Resumed the hub CA rotation state", "active", active.Certificate.Subject.String(),
		"pending", s.pending != nil, "retired", len(s.retired))
	return nil
}

func (s *ServerSVIDSource) stateLocked() (string, error) {
	if s.active == nil {
		return "", nil
	}
	state := RotationState{Active: Fingerprint(s.active.Certificate)}
	if s.pending != nil {
		since := s.pendingSince.UTC()
		state.Pending, state.PendingSince = Fingerprint(s.pending.Certificate), &since
	}
	for _, r := range s.retired {
		state.Retired = append(state.Retired, RetiredCA{Certificate: Fingerprint(r.cert), RetireAt: r.retireAt.UTC()})
	}
	data, err := json.Marshal(state)
	return string(data), err
}

func (s *ServerSVIDSource) bundleLocked() []*x509.Certificate {
	var certs []*x509.Certificate
	add := func(c *x509.Certificate) {
		// A rotation back to a retired hub CA would otherwise list it twice.
		for _, existing := range certs {
			if bytes.Equal(existing.Raw, c.Raw) {
				return
			}
		}
		certs = append(certs, c)
	}
	if s.active != nil {
		add(s.active.Certificate)
	}
	if s.pending != nil {
		add(s.pending.Certificate)
	}
	for _, r := range s.retired {
		add(r.cert)
	}
	return certs
}

func sameCerts(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].Raw, b[i].Raw) {
			return false
		}
	}
	return true
}
