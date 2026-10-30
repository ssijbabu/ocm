// Package trustbundle publishes the hub trust bundle as a signer-linked
// ClusterTrustBundle. The hub publishes it for clusters that join; spokes keep
// their copy current from the bundle returned with each agent SVID.
//
// ClusterTrustBundle is served as certificates.k8s.io/v1 from Kubernetes 1.37
// and as v1beta1 before, where it may have to be enabled. The publisher uses
// whichever version the API server serves; the fields are the same.
package trustbundle

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"

	"open-cluster-management.io/ocm/pkg/server/spiffe/svid"
)

const (
	// SignerName links the hub trust bundle to the OCM SPIFFE signer. The
	// kube-apiserver accepts writes to the bundle only from callers allowed to
	// attest for this signer.
	SignerName = "open-cluster-management.io/spiffe-hub"
	// Name is the ClusterTrustBundle name. Signer-linked bundles must be named
	// after their signer, with "/" replaced by ":", plus a suffix.
	Name = "open-cluster-management.io:spiffe-hub:ca"

	group    = "certificates.k8s.io"
	resource = "clustertrustbundles"
)

// served lists the versions to look for, preferred first.
var served = []string{"v1", "v1beta1"}

// Publisher writes the hub trust bundle to a ClusterTrustBundle.
type Publisher struct {
	client    dynamic.Interface
	discovery discovery.DiscoveryInterface

	mu  sync.Mutex
	gvr *schema.GroupVersionResource
}

// NewPublisher returns a Publisher. discovery picks the served
// ClusterTrustBundle version on first use.
func NewPublisher(client dynamic.Interface, discovery discovery.DiscoveryInterface) *Publisher {
	return &Publisher{client: client, discovery: discovery}
}

func (p *Publisher) resource() (schema.GroupVersionResource, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gvr != nil {
		return *p.gvr, nil
	}
	for _, version := range served {
		list, err := p.discovery.ServerResourcesForGroupVersion(group + "/" + version)
		if err != nil {
			continue
		}
		for _, r := range list.APIResources {
			if r.Name == resource {
				gvr := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
				p.gvr = &gvr
				return gvr, nil
			}
		}
	}
	return schema.GroupVersionResource{}, fmt.Errorf("the API server does not serve ClusterTrustBundles; " +
		"SPIFFE identities need Kubernetes 1.37, or 1.33 or later with the certificates.k8s.io/v1beta1 ClusterTrustBundle API enabled")
}

var _ svid.TrustBundleStore = &Publisher{}

// Publish creates or updates the ClusterTrustBundle so it holds exactly certs.
// Spoke registration agents use it to store the hub trust bundle.
func (p *Publisher) Publish(ctx context.Context, certs []*x509.Certificate) error {
	return p.write(ctx, certs, nil)
}

// Save publishes the hub trust bundle with the hub CA rotation state, which
// the hub gRPC server keeps in an annotation so a restart can resume it.
func (p *Publisher) Save(ctx context.Context, certs []*x509.Certificate, state string) error {
	return p.write(ctx, certs, &state)
}

// Load returns the published hub trust bundle and the rotation state, or
// nothing if the ClusterTrustBundle does not exist yet.
func (p *Publisher) Load(ctx context.Context) ([]*x509.Certificate, string, error) {
	gvr, err := p.resource()
	if err != nil {
		return nil, "", err
	}
	obj, err := p.client.Resource(gvr).Get(ctx, Name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed to get ClusterTrustBundle %s: %w", Name, err)
	}
	if signer, _, _ := unstructured.NestedString(obj.Object, "spec", "signerName"); signer != SignerName {
		return nil, "", fmt.Errorf("ClusterTrustBundle %s belongs to signer %q, not %q", Name, signer, SignerName)
	}
	bundle, _, _ := unstructured.NestedString(obj.Object, "spec", "trustBundle")
	var certs []*x509.Certificate
	for rest := []byte(bundle); ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "", fmt.Errorf("ClusterTrustBundle %s holds an invalid certificate: %w", Name, err)
		}
		certs = append(certs, c)
	}
	return certs, obj.GetAnnotations()[svid.RotationStateAnnotation], nil
}

// write creates or updates the ClusterTrustBundle; a non-nil state replaces
// the rotation state annotation.
func (p *Publisher) write(ctx context.Context, certs []*x509.Certificate, state *string) error {
	if len(certs) == 0 {
		return fmt.Errorf("refusing to publish an empty hub trust bundle")
	}
	gvr, err := p.resource()
	if err != nil {
		return err
	}
	bundle := EncodePEM(certs)
	client := p.client.Resource(gvr)

	existing, err := client.Get(ctx, Name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		obj := &unstructured.Unstructured{Object: map[string]interface{}{
			"apiVersion": gvr.GroupVersion().String(),
			"kind":       "ClusterTrustBundle",
			"metadata":   map[string]interface{}{"name": Name},
			"spec":       map[string]interface{}{"signerName": SignerName, "trustBundle": bundle},
		}}
		if state != nil {
			obj.SetAnnotations(map[string]string{svid.RotationStateAnnotation: *state})
		}
		if _, err := client.Create(ctx, obj, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create ClusterTrustBundle %s: %w", Name, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get ClusterTrustBundle %s: %w", Name, err)
	}

	signer, _, _ := unstructured.NestedString(existing.Object, "spec", "signerName")
	if signer != SignerName {
		return fmt.Errorf("ClusterTrustBundle %s belongs to signer %q, not %q; delete it so it can be recreated",
			Name, signer, SignerName)
	}
	current, _, _ := unstructured.NestedString(existing.Object, "spec", "trustBundle")
	annotations := existing.GetAnnotations()
	if current == bundle && (state == nil || annotations[svid.RotationStateAnnotation] == *state) {
		return nil
	}
	updated := existing.DeepCopy()
	if err := unstructured.SetNestedField(updated.Object, bundle, "spec", "trustBundle"); err != nil {
		return err
	}
	if state != nil {
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[svid.RotationStateAnnotation] = *state
		updated.SetAnnotations(annotations)
	}
	if _, err := client.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
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
