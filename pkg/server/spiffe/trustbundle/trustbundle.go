// Package trustbundle publishes the hub trust bundle as a signer-linked
// ClusterTrustBundle on the hub. Spokes copy it at join and later receive
// updates with their agent SVIDs.
package trustbundle

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	certificatesv1beta1client "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
)

const (
	// SignerName links the hub trust bundle to the OCM SPIFFE signer. The
	// kube-apiserver accepts writes to the bundle only from callers allowed to
	// attest for this signer, which on the hub is only grpc-server-sa.
	SignerName = "open-cluster-management.io/spiffe-hub"
	// Name is the ClusterTrustBundle name. Signer-linked bundles must be named
	// after their signer, with "/" replaced by ":", plus a suffix.
	Name = "open-cluster-management.io:spiffe-hub:ca"
)

// Publisher writes the hub trust bundle to the hub ClusterTrustBundle.
type Publisher struct {
	client certificatesv1beta1client.ClusterTrustBundlesGetter
}

// NewPublisher returns a Publisher using the given client.
func NewPublisher(client certificatesv1beta1client.ClusterTrustBundlesGetter) *Publisher {
	return &Publisher{client: client}
}

// Publish creates or updates the ClusterTrustBundle so it holds exactly certs.
// It matches svid.TrustBundleFunc.
func (p *Publisher) Publish(ctx context.Context, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return fmt.Errorf("refusing to publish an empty hub trust bundle")
	}
	bundle := EncodePEM(certs)

	existing, err := p.client.ClusterTrustBundles().Get(ctx, Name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		_, err = p.client.ClusterTrustBundles().Create(ctx, &certificatesv1beta1.ClusterTrustBundle{
			ObjectMeta: metav1.ObjectMeta{Name: Name},
			Spec: certificatesv1beta1.ClusterTrustBundleSpec{
				SignerName:  SignerName,
				TrustBundle: bundle,
			},
		}, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create ClusterTrustBundle %s: %w", Name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get ClusterTrustBundle %s: %w", Name, err)
	}

	if existing.Spec.SignerName != SignerName {
		return fmt.Errorf("ClusterTrustBundle %s belongs to signer %q, not %q; delete it so the hub can recreate it",
			Name, existing.Spec.SignerName, SignerName)
	}
	if existing.Spec.TrustBundle == bundle {
		return nil
	}
	updated := existing.DeepCopy()
	updated.Spec.TrustBundle = bundle
	if _, err := p.client.ClusterTrustBundles().Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update ClusterTrustBundle %s: %w", Name, err)
	}
	return nil
}

// EncodePEM concatenates certs as PEM CERTIFICATE blocks, the format
// ClusterTrustBundle requires.
func EncodePEM(certs []*x509.Certificate) string {
	var buf bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return buf.String()
}
