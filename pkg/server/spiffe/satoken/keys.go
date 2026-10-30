package satoken

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"k8s.io/utils/clock"
)

const (
	maxDocumentSize = 1 << 20
	// minRefreshInterval limits how often an unknown key ID can make the hub
	// fetch an issuer's keys.
	minRefreshInterval = time.Minute
	// maxKeyAge refetches keys even without an unknown key ID.
	maxKeyAge = time.Hour
)

type jwks struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// StaticKeySet holds keys pinned when the spoke was accepted. The hub never
// contacts the issuer.
type StaticKeySet struct {
	keys map[string]crypto.PublicKey
}

// ParseJWKS parses a JSON Web Key Set, keeping RSA (2048 bits or more) and EC
// P-256/P-384 signing keys.
func ParseJWKS(data []byte) (*StaticKeySet, error) {
	var set jwks
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("invalid JWKS: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			return nil, fmt.Errorf("JWKS key %q: %w", k.Kid, err)
		}
		if pub == nil {
			continue
		}
		if _, dup := keys[k.Kid]; dup {
			return nil, fmt.Errorf("JWKS has duplicate key ID %q", k.Kid)
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS has no usable signing keys")
	}
	return &StaticKeySet{keys: keys}, nil
}

func (s *StaticKeySet) Key(_ context.Context, kid string) (crypto.PublicKey, error) {
	return lookup(s.keys, kid)
}

func lookup(keys map[string]crypto.PublicKey, kid string) (crypto.PublicKey, error) {
	if k, ok := keys[kid]; ok {
		return k, nil
	}
	// Some issuers omit kid when they have a single key.
	if kid == "" && len(keys) == 1 {
		for _, k := range keys {
			return k, nil
		}
	}
	return nil, fmt.Errorf("token key ID %q is not among the issuer's keys", kid)
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("invalid modulus")
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, fmt.Errorf("invalid exponent")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 || pub.E < 3 {
			return nil, fmt.Errorf("RSA key is weaker than 2048 bits")
		}
		return pub, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return nil, nil
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("invalid x coordinate")
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("invalid y coordinate")
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if _, err := pub.ECDH(); err != nil {
			return nil, fmt.Errorf("invalid EC point")
		}
		return pub, nil
	default:
		return nil, nil
	}
}

// DiscoveryKeySet fetches an issuer's keys through OIDC discovery. It is used
// when the spoke's keys were not pinned. Only https is used, redirects must
// stay on the issuer's host, responses are size-limited, and an unknown key ID
// triggers at most one refresh per minute.
type DiscoveryKeySet struct {
	issuer *url.URL
	client *http.Client
	clock  clock.PassiveClock

	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

// NewDiscoveryKeySet returns a key set for issuer. client may be nil.
func NewDiscoveryKeySet(issuer string, client *http.Client, clk clock.PassiveClock) (*DiscoveryKeySet, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("issuer %q must be an https URL without query or fragment", issuer)
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	host := u.Host
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || req.URL.Scheme != "https" || req.URL.Host != host {
			return fmt.Errorf("redirect to %s is not allowed", req.URL.Redacted())
		}
		return nil
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	return &DiscoveryKeySet{issuer: u, client: &c, clock: clk}, nil
}

func (d *DiscoveryKeySet) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.clock.Now()
	stale := d.keys == nil || now.Sub(d.fetchedAt) > maxKeyAge
	if !stale {
		if k, err := lookup(d.keys, kid); err == nil {
			return k, nil
		}
		stale = now.Sub(d.fetchedAt) >= minRefreshInterval
	}
	if stale {
		keys, err := d.fetch(ctx)
		if err != nil {
			if d.keys == nil {
				return nil, err
			}
		} else {
			d.keys, d.fetchedAt = keys, now
		}
	}
	return lookup(d.keys, kid)
}

func (d *DiscoveryKeySet) fetch(ctx context.Context) (map[string]crypto.PublicKey, error) {
	var config struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	discovery := strings.TrimSuffix(d.issuer.String(), "/") + "/.well-known/openid-configuration"
	if err := d.get(ctx, discovery, &config); err != nil {
		return nil, fmt.Errorf("OIDC discovery for issuer %s failed: %w", d.issuer, err)
	}
	if config.Issuer != d.issuer.String() {
		return nil, fmt.Errorf("issuer %s advertises a different issuer %q", d.issuer, config.Issuer)
	}
	jwksURL, err := url.Parse(config.JWKSURI)
	if err != nil || jwksURL.Scheme != "https" || jwksURL.Host != d.issuer.Host {
		return nil, fmt.Errorf("issuer %s advertises jwks_uri %q off its own https host", d.issuer, config.JWKSURI)
	}
	var raw json.RawMessage
	if err := d.get(ctx, jwksURL.String(), &raw); err != nil {
		return nil, fmt.Errorf("fetching the keys of issuer %s failed: %w", d.issuer, err)
	}
	set, err := ParseJWKS(raw)
	if err != nil {
		return nil, err
	}
	return set.keys, nil
}

func (d *DiscoveryKeySet) get(ctx context.Context, u string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentSize+1))
	if err != nil {
		return err
	}
	if len(data) > maxDocumentSize {
		return fmt.Errorf("response is larger than %d bytes", maxDocumentSize)
	}
	return json.Unmarshal(data, out)
}
