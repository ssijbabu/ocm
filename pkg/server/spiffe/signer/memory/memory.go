// Package memory provides a hub CA signer that keeps the key in process memory.
// It is for tests and local development only: in production the hub CA key
// must stay in an external KMS or HSM.
package memory

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"time"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
)

// Signer holds a hub CA key and certificate in memory, and the earlier ones
// it was rotated from.
type Signer struct {
	mu      sync.RWMutex
	key     crypto.Signer
	cert    *x509.Certificate
	earlier map[string]crypto.Signer
}

var _ signer.Signer = &Signer{}

// New returns a Signer for an existing key and hub CA certificate.
func New(key crypto.Signer, cert *x509.Certificate) *Signer {
	return &Signer{key: key, cert: cert, earlier: map[string]crypto.Signer{}}
}

// NewSelfSigned creates a P-256 key and a self-signed hub CA certificate whose
// name constraint only permits SPIFFE IDs in trustDomain.
func NewSelfSigned(trustDomain string, ttl time.Duration) (*Signer, error) {
	key, cert, err := NewSelfSignedCA(trustDomain, time.Now(), ttl)
	if err != nil {
		return nil, err
	}
	return New(key, cert), nil
}

// NewSelfSignedCA creates a P-256 key and a self-signed hub CA certificate,
// name-constrained to trustDomain, valid from now for ttl.
func NewSelfSignedCA(trustDomain string, now time.Time, ttl time.Duration) (crypto.Signer, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:                serial,
		Subject:                     pkix.Name{CommonName: "ocm-spiffe-ca"},
		NotBefore:                   now.Add(-time.Minute),
		NotAfter:                    now.Add(ttl),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedURIDomains:         []string{trustDomain},
		PermittedDNSDomainsCritical: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create hub CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}

// Rotate replaces the key and hub CA certificate, as a platform admin does when
// creating a new key version in the KMS.
func (s *Signer) Rotate(key crypto.Signer, cert *x509.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.earlier[string(s.cert.Raw)] = s.key
	s.key, s.cert = key, cert
}

func (s *Signer) Current(_ context.Context) (*signer.CA, error) {
	s.mu.RLock()
	key, cert := s.key, s.cert
	s.mu.RUnlock()
	return newCA(key, cert)
}

func (s *Signer) ForCertificate(_ context.Context, cert *x509.Certificate) (*signer.CA, error) {
	s.mu.RLock()
	key, ok := s.earlier[string(cert.Raw)]
	if bytes.Equal(cert.Raw, s.cert.Raw) {
		key, ok = s.key, true
	}
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no key for hub CA certificate %q", cert.Subject.String())
	}
	return newCA(key, cert)
}

func newCA(key crypto.Signer, cert *x509.Certificate) (*signer.CA, error) {
	return signer.NewCA(cert, key.Public(), func(_ context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
		if err := signer.CheckDigest(key.Public(), digest, opts); err != nil {
			return nil, err
		}
		return key.Sign(rand.Reader, digest, opts)
	})
}
