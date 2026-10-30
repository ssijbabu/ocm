// Package certservice is the hub's certificate service: a spoke agent sends
// its projected ServiceAccount token and a certificate request, and gets back
// an agent SVID signed by the hub CA through the KMS.
//
// The service is reachable before the caller has any certificate, so it
// applies rate and size limits first and gives the same answer for every
// refusal. Every identity field of the SVID comes from data the hub verified:
// the spoke's binding, the token's claims and, for addons, the hub-side addon
// definition. Nothing the agent asks for ends up in the SVID except its public
// key.
package certservice

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	addonagent "open-cluster-management.io/addon-framework/pkg/agent"

	"open-cluster-management.io/ocm/pkg/registration/hub/user"
	"open-cluster-management.io/ocm/pkg/server/spiffe/satoken"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
	"open-cluster-management.io/ocm/pkg/server/spiffe/svid"
)

var (
	// ErrNotReady is the single answer to every refused request: not accepted,
	// unknown, bad token, wrong ServiceAccount, rate limited. Callers retry
	// with backoff. The reason is logged on the hub, never returned.
	ErrNotReady = errors.New("not ready")
	// ErrUnavailable means the hub could not sign, for example during a KMS
	// outage. Agents keep their current SVID and retry.
	ErrUnavailable = errors.New("unavailable, retry later")
)

const (
	maxNameLength = 253
	maxCSRSize    = 4 * 1024
	maxTokenSize  = 16 * 1024
)

// AllowedServiceAccount is an agent ServiceAccount on the spoke, recorded by
// UID when the hub admin accepted the spoke.
type AllowedServiceAccount struct {
	Namespace string
	Name      string
	UID       string
	// Agent names the agent, such as "registration" or "work". It becomes part
	// of the agent's Kubernetes user name.
	Agent string
}

// Binding is the hub's record of which tokens may act for a spoke. It is
// backed by the admin-only ManagedClusterIdentity resource.
type Binding struct {
	// Issuer is the spoke's ServiceAccount token issuer.
	Issuer string
	// PinnedJWKS holds the issuer's keys when they were pinned at acceptance.
	// When empty, the keys are discovered from the issuer.
	PinnedJWKS      []byte
	ServiceAccounts []AllowedServiceAccount
}

// BindingLookup returns the binding of an accepted spoke, or an error if the
// spoke is unknown, not accepted or not bound.
type BindingLookup interface {
	Lookup(ctx context.Context, cluster string) (*Binding, error)
}

// AddonServiceAccount is the ServiceAccount an addon agent must run as on
// spokes, from the hub-side addon definition.
type AddonServiceAccount struct {
	Namespace string
	Name      string
}

// AddonLookup returns the ServiceAccount an addon is declared to run as, or
// an error if the addon is not enabled for the spoke.
type AddonLookup interface {
	Lookup(ctx context.Context, cluster, addon string) (*AddonServiceAccount, error)
}

// CA is the source of the active hub CA and the hub trust bundle.
// svid.ServerSVIDSource implements it.
type CA interface {
	ActiveCA() *signer.CA
	TrustBundle() []*x509.Certificate
}

// Issuance describes one issued agent SVID, for the audit record.
type Issuance struct {
	Cluster        string
	Addon          string
	Namespace      string
	ServiceAccount string
	Pod            string
	SPIFFEID       string
	Serial         string
	NotAfter       time.Time
}

// Recorder keeps an audit record of each issuance, such as an Event in the
// spoke's cluster namespace.
type Recorder interface {
	RecordIssuance(ctx context.Context, i Issuance)
}

// Request is a CreateCertificate call.
type Request struct {
	ClusterName string
	// AddonName is set when an addon agent asks for its SVID.
	AddonName string
	// CSR is a DER certificate request. Only its public key and signature are
	// used.
	CSR []byte
	// Token is the agent's projected ServiceAccount token.
	Token string
	// Source identifies the caller's network address for rate limiting.
	Source string
}

// Response carries the agent SVID and the current hub trust bundle.
type Response struct {
	Certificate *x509.Certificate
	TrustBundle []*x509.Certificate
}

// Options configures a Service.
type Options struct {
	TrustDomain string
	// Audience is the token audience unique to this hub.
	Audience string
	// SVIDTTL is the agent SVID lifetime. Defaults to 1 hour.
	SVIDTTL time.Duration
	// MaxTokenLifetime defaults to satoken.DefaultMaxLifetime.
	MaxTokenLifetime time.Duration
	CA               CA
	Bindings         BindingLookup
	// Addons may be nil when addon SVIDs are not served.
	Addons   AddonLookup
	Recorder Recorder
	// PerSourceRate and PerClusterRate limit requests per second, with a
	// burst of five. Defaults are 1 and 2.
	PerSourceRate  rate.Limit
	PerClusterRate rate.Limit
	// HTTPClient is used for OIDC discovery of spoke issuers.
	HTTPClient *http.Client
	Clock      clock.PassiveClock
}

// Service issues agent SVIDs.
type Service struct {
	opts Options

	mu        sync.Mutex
	keySets   map[string]*satoken.DiscoveryKeySet
	bySource  *limiters
	byCluster *limiters
}

// New validates opts and returns a Service.
func New(opts Options) (*Service, error) {
	if err := svid.ValidateTrustDomain(opts.TrustDomain); err != nil {
		return nil, err
	}
	if opts.Audience == "" {
		return nil, fmt.Errorf("a token audience unique to this hub is required")
	}
	if opts.CA == nil || opts.Bindings == nil {
		return nil, fmt.Errorf("the hub CA and the binding lookup are required")
	}
	if opts.SVIDTTL == 0 {
		opts.SVIDTTL = time.Hour
	}
	if opts.SVIDTTL < 0 {
		return nil, fmt.Errorf("agent SVID lifetime must be positive")
	}
	if opts.PerSourceRate == 0 {
		opts.PerSourceRate = 1
	}
	if opts.PerClusterRate == 0 {
		opts.PerClusterRate = 2
	}
	if opts.Clock == nil {
		opts.Clock = clock.RealClock{}
	}
	return &Service{
		opts:      opts,
		keySets:   map[string]*satoken.DiscoveryKeySet{},
		bySource:  newLimiters(opts.PerSourceRate, 5),
		byCluster: newLimiters(opts.PerClusterRate, 5),
	}, nil
}

// CreateCertificate verifies the request and issues an agent SVID. It returns
// ErrNotReady for every refusal and ErrUnavailable when the hub cannot sign.
func (s *Service) CreateCertificate(ctx context.Context, req Request) (*Response, error) {
	logger := klog.FromContext(ctx).WithValues("cluster", req.ClusterName, "addon", req.AddonName, "source", req.Source)
	now := s.opts.Clock.Now()

	// Limits run before anything that costs a lookup, a fetch or a signature.
	if len(req.ClusterName) == 0 || len(req.ClusterName) > maxNameLength || len(req.AddonName) > maxNameLength ||
		len(req.CSR) == 0 || len(req.CSR) > maxCSRSize || len(req.Token) == 0 || len(req.Token) > maxTokenSize {
		logger.V(4).Info("Refusing certificate request: size limits")
		return nil, ErrNotReady
	}
	if !s.bySource.allow(req.Source, now) || !s.byCluster.allow(req.ClusterName, now) {
		logger.V(4).Info("Refusing certificate request: rate limited")
		return nil, ErrNotReady
	}

	issued, err := s.issue(ctx, req, now)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			logger.Error(err, "Cannot issue agent SVID")
			return nil, ErrUnavailable
		}
		logger.V(2).Info("Refusing certificate request", "reason", err.Error())
		return nil, ErrNotReady
	}
	return issued, nil
}

func (s *Service) issue(ctx context.Context, req Request, now time.Time) (*Response, error) {
	binding, err := s.opts.Bindings.Lookup(ctx, req.ClusterName)
	if err != nil {
		return nil, fmt.Errorf("spoke is not accepted or not bound: %w", err)
	}
	keys, err := s.keySet(binding)
	if err != nil {
		return nil, err
	}
	claims, err := satoken.Verify(ctx, req.Token, satoken.VerifyOptions{
		Issuer:      binding.Issuer,
		Audience:    s.opts.Audience,
		Keys:        keys,
		Now:         now,
		MaxLifetime: s.opts.MaxTokenLifetime,
	})
	if err != nil {
		return nil, err
	}

	var userName string
	var groups []string
	if req.AddonName == "" {
		agent, err := matchAgent(binding, claims)
		if err != nil {
			return nil, err
		}
		userName = user.SubjectPrefix + req.ClusterName + ":" + agent
		groups = []string{user.SubjectPrefix + req.ClusterName, user.ManagedClustersGroup}
	} else {
		if s.opts.Addons == nil {
			return nil, fmt.Errorf("addon SVIDs are not served")
		}
		expected, err := s.opts.Addons.Lookup(ctx, req.ClusterName, req.AddonName)
		if err != nil {
			return nil, fmt.Errorf("addon is not enabled for the spoke: %w", err)
		}
		if claims.Namespace != expected.Namespace || claims.ServiceAccountName != expected.Name {
			return nil, fmt.Errorf("token is for %s/%s, the addon is declared to run as %s/%s",
				claims.Namespace, claims.ServiceAccountName, expected.Namespace, expected.Name)
		}
		userName = addonagent.DefaultUser(req.ClusterName, req.AddonName, claims.ServiceAccountName)
		groups = addonagent.DefaultGroups(req.ClusterName, req.AddonName)
	}

	csr, err := x509.ParseCertificateRequest(req.CSR)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("certificate request is not signed by its key: %w", err)
	}
	if err := svid.CheckAgentKey(csr.PublicKey); err != nil {
		return nil, err
	}

	ca := s.opts.CA.ActiveCA()
	if ca == nil {
		return nil, fmt.Errorf("%w: the hub CA has not been loaded yet", ErrUnavailable)
	}
	cert, err := svid.IssueAgentSVID(ctx, ca, svid.AgentSVIDRequest{
		TrustDomain: s.opts.TrustDomain,
		Identity: svid.AgentIdentity{
			Cluster:        req.ClusterName,
			Namespace:      claims.Namespace,
			ServiceAccount: claims.ServiceAccountName,
		},
		User:      userName,
		Groups:    groups,
		PublicKey: csr.PublicKey,
		TTL:       s.opts.SVIDTTL,
	}, now)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	if s.opts.Recorder != nil {
		s.opts.Recorder.RecordIssuance(ctx, Issuance{
			Cluster:        req.ClusterName,
			Addon:          req.AddonName,
			Namespace:      claims.Namespace,
			ServiceAccount: claims.ServiceAccountName,
			Pod:            claims.PodName,
			SPIFFEID:       cert.URIs[0].String(),
			Serial:         cert.SerialNumber.String(),
			NotAfter:       cert.NotAfter,
		})
	}
	return &Response{Certificate: cert, TrustBundle: s.opts.CA.TrustBundle()}, nil
}

// matchAgent finds the token's ServiceAccount among the spoke's bound agent
// ServiceAccounts, by namespace, name and UID, so a deleted and recreated
// ServiceAccount does not inherit the binding.
func matchAgent(b *Binding, c *satoken.Claims) (string, error) {
	for _, sa := range b.ServiceAccounts {
		if sa.Namespace == c.Namespace && sa.Name == c.ServiceAccountName && sa.UID == c.ServiceAccountUID {
			if sa.Agent == "" {
				return "", fmt.Errorf("bound ServiceAccount %s/%s has no agent name", sa.Namespace, sa.Name)
			}
			return sa.Agent, nil
		}
	}
	return "", fmt.Errorf("ServiceAccount %s/%s (UID %s) is not bound to the spoke", c.Namespace, c.ServiceAccountName, c.ServiceAccountUID)
}

// keySet returns pinned keys, or a cached discovery key set for the issuer so
// its refresh limits hold across requests.
func (s *Service) keySet(b *Binding) (satoken.KeySet, error) {
	if len(b.PinnedJWKS) > 0 {
		return satoken.ParseJWKS(b.PinnedJWKS)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ks, ok := s.keySets[b.Issuer]; ok {
		return ks, nil
	}
	ks, err := satoken.NewDiscoveryKeySet(b.Issuer, s.opts.HTTPClient, s.opts.Clock)
	if err != nil {
		return nil, err
	}
	s.keySets[b.Issuer] = ks
	return ks, nil
}

// limiters keeps one token bucket per key, dropping idle ones so a flood of
// distinct sources cannot grow memory without bound.
type limiters struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	entries map[string]*limiterEntry
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

const (
	maxLimiters  = 10000
	limiterIdle  = 10 * time.Minute
	sweepTrigger = maxLimiters / 2
)

func newLimiters(limit rate.Limit, burst int) *limiters {
	return &limiters{limit: limit, burst: burst, entries: map[string]*limiterEntry{}}
}

func (l *limiters) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) >= sweepTrigger {
		for k, e := range l.entries {
			if now.Sub(e.lastSeen) > limiterIdle {
				delete(l.entries, k)
			}
		}
	}
	e, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= maxLimiters {
			return false
		}
		e = &limiterEntry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.entries[key] = e
	}
	e.lastSeen = now
	return e.limiter.AllowN(now, 1)
}
