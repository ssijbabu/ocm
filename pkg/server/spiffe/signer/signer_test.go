package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

func TestNewCARejectsMismatchedKey(t *testing.T) {
	certKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{PublicKey: certKey.Public()}
	sign := func(context.Context, []byte, crypto.SignerOpts) ([]byte, error) { return nil, nil }

	if _, err := NewCA(cert, otherKey.Public(), sign); err == nil {
		t.Fatal("expected an error for a KMS key that does not match the hub CA certificate")
	}
	if _, err := NewCA(cert, certKey.Public(), sign); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := NewCA(nil, certKey.Public(), sign); err == nil {
		t.Fatal("expected an error for a missing certificate")
	}
	if _, err := NewCA(cert, certKey.Public(), nil); err == nil {
		t.Fatal("expected an error for a missing sign function")
	}
}

func TestHashForKey(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	cases := []struct {
		name    string
		pub     crypto.PublicKey
		want    crypto.Hash
		wantErr bool
	}{
		{name: "p256", pub: p256.Public(), want: crypto.SHA256},
		{name: "p384", pub: p384.Public(), want: crypto.SHA384},
		{name: "p521", pub: p521.Public(), wantErr: true},
		{name: "rsa", pub: rsaKey.Public(), wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := HashForKey(c.pub)
			if c.wantErr != (err != nil) {
				t.Fatalf("wantErr %v, got %v", c.wantErr, err)
			}
			if got != c.want {
				t.Errorf("want %v, got %v", c.want, got)
			}
		})
	}
}

func TestCheckDigest(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	digest := sha256.Sum256([]byte("hub server SVID"))

	if err := CheckDigest(key.Public(), digest[:], crypto.SHA256); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if err := CheckDigest(key.Public(), digest[:], crypto.SHA384); err == nil {
		t.Error("expected an error for the wrong hash")
	}
	if err := CheckDigest(key.Public(), digest[:10], crypto.SHA256); err == nil {
		t.Error("expected an error for a short digest")
	}
	if err := CheckDigest(key.Public(), digest[:], nil); err == nil {
		t.Error("expected an error for missing options")
	}
}

func TestECDSARawToASN1(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	digest := sha256.Sum256([]byte("hub server SVID"))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])

	der, err := ECDSARawToASN1(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], der) {
		t.Error("converted signature does not verify")
	}

	if _, err := ECDSARawToASN1(raw[:63]); err == nil {
		t.Error("expected an error for an odd-length signature")
	}
	if _, err := ECDSARawToASN1(nil); err == nil {
		t.Error("expected an error for an empty signature")
	}
}

func TestCryptoSignerUsesSignFunc(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := &x509.Certificate{PublicKey: key.Public()}
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "bound")

	var gotCtx context.Context
	ca, err := NewCA(cert, key.Public(), func(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
		gotCtx = ctx
		return key.Sign(rand.Reader, digest, opts)
	})
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("x"))
	cs := ca.CryptoSigner(ctx)
	sig, err := cs.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if gotCtx.Value(ctxKey{}) != "bound" {
		t.Error("sign function did not receive the bound context")
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		t.Error("signature does not verify")
	}
	if !key.PublicKey.Equal(cs.Public()) {
		t.Error("crypto.Signer reports the wrong public key")
	}
}
