package svid

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/memory"
)

type recorder struct {
	bundles [][]*x509.Certificate
	err     error
}

func (r *recorder) publish(_ context.Context, b []*x509.Certificate) error {
	if r.err != nil {
		return r.err
	}
	r.bundles = append(r.bundles, b)
	return nil
}

func (r *recorder) last() []*x509.Certificate {
	if len(r.bundles) == 0 {
		return nil
	}
	return r.bundles[len(r.bundles)-1]
}

type failingSigner struct{}

func (failingSigner) Current(context.Context) (*signer.CA, error) {
	return nil, errors.New("KMS unavailable")
}

func newSource(t *testing.T, s signer.Signer, clk *clocktesting.FakeClock, rec *recorder) *ServerSVIDSource {
	t.Helper()
	src, err := NewServerSVIDSource(s, Options{
		TrustDomain:          trustDomain,
		TTL:                  time.Hour,
		MaxAgentSVIDLifetime: time.Hour,
		CACheckInterval:      time.Minute,
		OnTrustBundleChange:  rec.publish,
		Clock:                clk,
	})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func mustSync(t *testing.T, src *ServerSVIDSource) time.Duration {
	t.Helper()
	wait, err := src.sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return wait
}

func serial(t *testing.T, src *ServerSVIDSource) string {
	t.Helper()
	c, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.Leaf.SerialNumber.String()
}

func issuer(t *testing.T, src *ServerSVIDSource) *x509.Certificate {
	t.Helper()
	c, _ := src.GetCertificate(nil)
	return c.Leaf
}

func signedBy(leaf, ca *x509.Certificate) bool {
	return leaf.CheckSignatureFrom(ca) == nil
}

func TestSourceIssuesAndRenewsAtHalfLife(t *testing.T) {
	start := time.Now()
	clk := clocktesting.NewFakeClock(start)
	key, cert, _ := memory.NewSelfSignedCA(trustDomain, start, 24*time.Hour)
	rec := &recorder{}
	src := newSource(t, memory.New(key, cert), clk, rec)

	if _, err := src.GetCertificate(nil); err == nil {
		t.Fatal("expected no hub server SVID before the first sync")
	}

	if wait := mustSync(t, src); wait != time.Minute {
		t.Errorf("want next sync in the CA check interval, got %s", wait)
	}
	first := serial(t, src)
	if len(rec.bundles) != 1 || len(rec.last()) != 1 || !bytes.Equal(rec.last()[0].Raw, cert.Raw) {
		t.Fatalf("want the hub CA certificate published once, got %d publishes", len(rec.bundles))
	}

	clk.Step(29 * time.Minute)
	mustSync(t, src)
	if serial(t, src) != first {
		t.Error("hub server SVID renewed before half its lifetime")
	}
	if len(rec.bundles) != 1 {
		t.Error("unchanged hub trust bundle was published again")
	}

	clk.Step(time.Minute)
	mustSync(t, src)
	if serial(t, src) == first {
		t.Error("hub server SVID not renewed at half its lifetime")
	}
}

func TestSourceRotatesHubCAInStages(t *testing.T) {
	start := time.Now()
	clk := clocktesting.NewFakeClock(start)
	oldKey, oldCert, _ := memory.NewSelfSignedCA(trustDomain, start, 24*time.Hour)
	kms := memory.New(oldKey, oldCert)
	rec := &recorder{}
	src := newSource(t, kms, clk, rec)
	mustSync(t, src)

	// The platform admin creates a new key version and hub CA certificate.
	newKey, newCert, _ := memory.NewSelfSignedCA(trustDomain, start, 24*time.Hour)
	kms.Rotate(newKey, newCert)
	clk.Step(time.Minute)
	mustSync(t, src)

	// Pending: both hub CA certificates published, active one first, and the
	// hub server SVID still signed by the old hub CA.
	if got := rec.last(); len(got) != 2 || !bytes.Equal(got[0].Raw, oldCert.Raw) || !bytes.Equal(got[1].Raw, newCert.Raw) {
		t.Fatalf("want [old, new] published while the new hub CA is pending, got %d certificates", len(got))
	}
	if !signedBy(issuer(t, src), oldCert) {
		t.Fatal("hub server SVID must stay signed by the old hub CA while the new one is pending")
	}
	if !bytes.Equal(src.ActiveCA().Certificate.Raw, oldCert.Raw) {
		t.Fatal("old hub CA must stay active while the new one is pending")
	}

	// Still pending just before one agent SVID lifetime has passed.
	clk.Step(59 * time.Minute)
	mustSync(t, src)
	if !bytes.Equal(src.ActiveCA().Certificate.Raw, oldCert.Raw) {
		t.Fatal("new hub CA activated too early")
	}

	// Active: the new hub CA signs, the old one is retired but still published.
	clk.Step(time.Minute)
	mustSync(t, src)
	if !bytes.Equal(src.ActiveCA().Certificate.Raw, newCert.Raw) {
		t.Fatal("new hub CA not active after one agent SVID lifetime")
	}
	if !signedBy(issuer(t, src), newCert) {
		t.Fatal("hub server SVID not re-issued by the new hub CA")
	}
	if got := rec.last(); len(got) != 2 || !bytes.Equal(got[0].Raw, newCert.Raw) || !bytes.Equal(got[1].Raw, oldCert.Raw) {
		t.Fatalf("want [new, old] published after activation, got %d certificates", len(got))
	}

	// Retired hub CA dropped once every SVID it signed has expired.
	clk.Step(time.Hour)
	mustSync(t, src)
	if got := rec.last(); len(got) != 1 || !bytes.Equal(got[0].Raw, newCert.Raw) {
		t.Fatalf("want only the new hub CA published, got %d certificates", len(got))
	}
}

func TestSourceDropsRolledBackRotation(t *testing.T) {
	start := time.Now()
	clk := clocktesting.NewFakeClock(start)
	oldKey, oldCert, _ := memory.NewSelfSignedCA(trustDomain, start, 24*time.Hour)
	kms := memory.New(oldKey, oldCert)
	rec := &recorder{}
	src := newSource(t, kms, clk, rec)
	mustSync(t, src)

	newKey, newCert, _ := memory.NewSelfSignedCA(trustDomain, start, 24*time.Hour)
	kms.Rotate(newKey, newCert)
	mustSync(t, src)
	kms.Rotate(oldKey, oldCert)
	mustSync(t, src)

	if got := rec.last(); len(got) != 1 || !bytes.Equal(got[0].Raw, oldCert.Raw) {
		t.Fatalf("want the pending hub CA dropped after a rollback, got %d certificates", len(got))
	}
}

func TestSourceRetriesPublishAndKeepsSVIDDuringKMSOutage(t *testing.T) {
	start := time.Now()
	clk := clocktesting.NewFakeClock(start)
	key, cert, _ := memory.NewSelfSignedCA(trustDomain, start, 24*time.Hour)
	rec := &recorder{err: errors.New("apiserver unavailable")}
	src := newSource(t, memory.New(key, cert), clk, rec)

	if _, err := src.sync(context.Background()); err == nil {
		t.Fatal("expected a publish failure to fail the sync")
	}
	rec.err = nil
	mustSync(t, src)
	if len(rec.bundles) != 1 {
		t.Fatal("hub trust bundle not published after the failure cleared")
	}
	before := serial(t, src)

	outage := newSource(t, failingSigner{}, clk, rec)
	outage.current, outage.renewAt = src.current, src.renewAt
	if _, err := outage.sync(context.Background()); err == nil {
		t.Fatal("expected a KMS outage to fail the sync")
	}
	if serial(t, outage) != before {
		t.Error("hub server SVID must be kept during a KMS outage")
	}
}

func TestSourceRunStopsOnCancel(t *testing.T) {
	key, cert, _ := memory.NewSelfSignedCA(trustDomain, time.Now(), time.Hour)
	src, err := NewServerSVIDSource(memory.New(key, cert), Options{TrustDomain: trustDomain})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		src.Run(ctx)
		close(done)
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := src.GetCertificate(nil); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("hub server SVID not issued by Run")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestNewServerSVIDSourceValidates(t *testing.T) {
	key, cert, _ := memory.NewSelfSignedCA(trustDomain, time.Now(), time.Hour)
	if _, err := NewServerSVIDSource(nil, Options{TrustDomain: trustDomain}); err == nil {
		t.Error("expected an error without a signer")
	}
	if _, err := NewServerSVIDSource(memory.New(key, cert), Options{TrustDomain: "Bad"}); err == nil {
		t.Error("expected an error for an invalid trust domain")
	}
	if _, err := NewServerSVIDSource(memory.New(key, cert), Options{TrustDomain: trustDomain, TTL: -time.Second}); err == nil {
		t.Error("expected an error for a negative lifetime")
	}
}
