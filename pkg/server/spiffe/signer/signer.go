// Package signer defines how the hub gRPC server signs with the hub CA key.
// The hub CA key lives in an external KMS or HSM and is never exported:
// implementations send only digests to it and get signatures back.
package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
)

// Signer gives access to the hub CA held in an external KMS or HSM.
type Signer interface {
	// Current returns the hub CA certificate together with a handle bound to the
	// KMS key version that certificate belongs to. Callers should call it again
	// periodically to pick up a rotated hub CA.
	Current(ctx context.Context) (*CA, error)
}

// SignFunc signs a digest with one KMS key version and returns an ASN.1 DER
// signature, the same format crypto.Signer returns.
type SignFunc func(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error)

// CA is a hub CA certificate paired with the KMS key version that signs for it.
type CA struct {
	Certificate *x509.Certificate
	public      crypto.PublicKey
	sign        SignFunc
}

// NewCA pairs a hub CA certificate with the public key the KMS reports for the
// key version and a function that signs with that version. It refuses a pair
// whose public keys differ, since every SVID signed with it would fail to verify.
func NewCA(cert *x509.Certificate, public crypto.PublicKey, sign SignFunc) (*CA, error) {
	if cert == nil {
		return nil, fmt.Errorf("hub CA certificate is missing")
	}
	if sign == nil {
		return nil, fmt.Errorf("sign function is missing")
	}
	certPub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !certPub.Equal(public) {
		return nil, fmt.Errorf("the KMS public key does not match the hub CA certificate %q", cert.Subject.String())
	}
	return &CA{Certificate: cert, public: public, sign: sign}, nil
}

// Public returns the public key of the KMS key version.
func (c *CA) Public() crypto.PublicKey {
	return c.public
}

// Sign signs a digest with the KMS key version.
func (c *CA) Sign(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return c.sign(ctx, digest, opts)
}

// CryptoSigner adapts the CA to crypto.Signer, bound to ctx, so it can be
// passed to x509.CreateCertificate.
func (c *CA) CryptoSigner(ctx context.Context) crypto.Signer {
	return &boundSigner{ctx: ctx, ca: c}
}

type boundSigner struct {
	ctx context.Context
	ca  *CA
}

func (b *boundSigner) Public() crypto.PublicKey {
	return b.ca.public
}

// Sign ignores rand: the KMS supplies its own randomness.
func (b *boundSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return b.ca.sign(b.ctx, digest, opts)
}

// HashForKey returns the hash x509.CreateCertificate uses with an ECDSA key on
// the given curve. Only P-256 and P-384 are supported for the hub CA.
func HashForKey(pub crypto.PublicKey) (crypto.Hash, error) {
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return 0, fmt.Errorf("unsupported hub CA key type %T, use an EC P-256 or P-384 key", pub)
	}
	switch ecPub.Curve {
	case elliptic.P256():
		return crypto.SHA256, nil
	case elliptic.P384():
		return crypto.SHA384, nil
	default:
		return 0, fmt.Errorf("unsupported hub CA curve %s, use P-256 or P-384", ecPub.Curve.Params().Name)
	}
}

// CheckDigest refuses a digest whose hash does not match what the key's curve
// requires, before it is sent to the KMS.
func CheckDigest(pub crypto.PublicKey, digest []byte, opts crypto.SignerOpts) error {
	want, err := HashForKey(pub)
	if err != nil {
		return err
	}
	if opts == nil || opts.HashFunc() != want {
		return fmt.Errorf("hub CA key requires %s digests", want)
	}
	if len(digest) != want.Size() {
		return fmt.Errorf("digest is %d bytes, %s requires %d", len(digest), want, want.Size())
	}
	return nil
}

// ECDSARawToASN1 converts an ECDSA signature in the raw R||S form that JOSE
// based KMS APIs return into the ASN.1 DER form x509 expects.
func ECDSARawToASN1(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, fmt.Errorf("raw ECDSA signature has invalid length %d", len(raw))
	}
	half := len(raw) / 2
	return asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(raw[:half]),
		S: new(big.Int).SetBytes(raw[half:]),
	})
}
