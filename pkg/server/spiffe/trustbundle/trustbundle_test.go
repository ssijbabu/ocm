package trustbundle

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/memory"
)

func newCert(t *testing.T) *x509.Certificate {
	t.Helper()
	_, cert, err := memory.NewSelfSignedCA("hub1.example.org", time.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestPublishCreatesUpdatesAndSkips(t *testing.T) {
	ctx := context.Background()
	client := kubefake.NewSimpleClientset()
	p := NewPublisher(client.CertificatesV1beta1())
	a, b := newCert(t), newCert(t)

	if err := p.Publish(ctx, []*x509.Certificate{a}); err != nil {
		t.Fatal(err)
	}
	got, err := client.CertificatesV1beta1().ClusterTrustBundles().Get(ctx, Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.SignerName != SignerName {
		t.Errorf("want signer %q, got %q", SignerName, got.Spec.SignerName)
	}
	if got.Spec.TrustBundle != EncodePEM([]*x509.Certificate{a}) {
		t.Error("unexpected trust bundle after create")
	}

	if err := p.Publish(ctx, []*x509.Certificate{b, a}); err != nil {
		t.Fatal(err)
	}
	got, _ = client.CertificatesV1beta1().ClusterTrustBundles().Get(ctx, Name, metav1.GetOptions{})
	if got.Spec.TrustBundle != EncodePEM([]*x509.Certificate{b, a}) {
		t.Error("unexpected trust bundle after update")
	}

	client.ClearActions()
	if err := p.Publish(ctx, []*x509.Certificate{b, a}); err != nil {
		t.Fatal(err)
	}
	for _, action := range client.Actions() {
		if action.GetVerb() == "update" || action.GetVerb() == "create" {
			t.Errorf("unchanged trust bundle must not be written, got %s", action.GetVerb())
		}
	}
}

func TestPublishRefusesForeignSigner(t *testing.T) {
	client := kubefake.NewSimpleClientset(&certificatesv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{Name: Name},
		Spec:       certificatesv1beta1.ClusterTrustBundleSpec{SignerName: "example.com/other"},
	})
	if err := NewPublisher(client.CertificatesV1beta1()).Publish(context.Background(), []*x509.Certificate{newCert(t)}); err == nil {
		t.Fatal("expected an error for a bundle owned by another signer")
	}
}

func TestPublishRefusesEmptyBundle(t *testing.T) {
	client := kubefake.NewSimpleClientset()
	if err := NewPublisher(client.CertificatesV1beta1()).Publish(context.Background(), nil); err == nil {
		t.Fatal("expected an error for an empty bundle")
	}
}

func TestEncodePEM(t *testing.T) {
	a, b := newCert(t), newCert(t)
	rest := []byte(EncodePEM([]*x509.Certificate{a, b}))
	var got []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			t.Fatalf("unexpected block %q", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, c)
	}
	if len(got) != 2 || !got[0].Equal(a) || !got[1].Equal(b) {
		t.Fatal("PEM does not round-trip in order")
	}
}
