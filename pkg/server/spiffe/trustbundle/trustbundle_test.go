package trustbundle

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	discoveryfake "k8s.io/client-go/discovery/fake"
	dynamicfake "k8s.io/client-go/dynamic/fake"
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

// newClients returns fake clients whose API server serves ClusterTrustBundles
// at version, or not at all when version is empty.
func newClients(version string, objs ...runtime.Object) (*dynamicfake.FakeDynamicClient, *discoveryfake.FakeDiscovery, schema.GroupVersionResource) {
	gvr := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}
	if version == "" {
		gvr.Version = "v1"
	}
	disc := kubefake.NewSimpleClientset().Discovery().(*discoveryfake.FakeDiscovery)
	// The fake clientset registers every built-in resource; serve only what
	// the test asks for.
	disc.Resources = nil
	if version != "" {
		disc.Resources = []*metav1.APIResourceList{{
			GroupVersion: group + "/" + version,
			APIResources: []metav1.APIResource{{Name: resource, Kind: "ClusterTrustBundle"}},
		}}
	}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvr: "ClusterTrustBundleList"}, objs...)
	return dyn, disc, gvr
}

func get(t *testing.T, dyn *dynamicfake.FakeDynamicClient, gvr schema.GroupVersionResource) (string, string) {
	t.Helper()
	obj, err := dyn.Resource(gvr).Get(context.Background(), Name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	signer, _, _ := unstructured.NestedString(obj.Object, "spec", "signerName")
	bundle, _, _ := unstructured.NestedString(obj.Object, "spec", "trustBundle")
	return signer, bundle
}

func TestPublishCreatesUpdatesAndSkips(t *testing.T) {
	for _, version := range []string{"v1", "v1beta1"} {
		t.Run(version, func(t *testing.T) {
			ctx := context.Background()
			dyn, disc, gvr := newClients(version)
			p := NewPublisher(dyn, disc)
			a, b := newCert(t), newCert(t)

			if err := p.Publish(ctx, []*x509.Certificate{a}); err != nil {
				t.Fatal(err)
			}
			signer, bundle := get(t, dyn, gvr)
			if signer != SignerName || bundle != EncodePEM([]*x509.Certificate{a}) {
				t.Errorf("unexpected bundle after create: signer %q", signer)
			}

			if err := p.Publish(ctx, []*x509.Certificate{b, a}); err != nil {
				t.Fatal(err)
			}
			if _, bundle := get(t, dyn, gvr); bundle != EncodePEM([]*x509.Certificate{b, a}) {
				t.Error("unexpected trust bundle after update")
			}

			dyn.ClearActions()
			if err := p.Publish(ctx, []*x509.Certificate{b, a}); err != nil {
				t.Fatal(err)
			}
			for _, action := range dyn.Actions() {
				if action.GetVerb() == "update" || action.GetVerb() == "create" {
					t.Errorf("unchanged trust bundle must not be written, got %s", action.GetVerb())
				}
			}
		})
	}
}

func TestPublishRefusesForeignSigner(t *testing.T) {
	foreign := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "certificates.k8s.io/v1",
		"kind":       "ClusterTrustBundle",
		"metadata":   map[string]interface{}{"name": Name},
		"spec":       map[string]interface{}{"signerName": "example.com/other", "trustBundle": "x"},
	}}
	dyn, disc, _ := newClients("v1", foreign)
	if err := NewPublisher(dyn, disc).Publish(context.Background(), []*x509.Certificate{newCert(t)}); err == nil {
		t.Fatal("expected an error for a bundle owned by another signer")
	}
}

func TestPublishFailsWithoutClusterTrustBundleAPI(t *testing.T) {
	dyn, disc, _ := newClients("")
	if err := NewPublisher(dyn, disc).Publish(context.Background(), []*x509.Certificate{newCert(t)}); err == nil {
		t.Fatal("expected an error when the API server does not serve ClusterTrustBundles")
	}
}

func TestPublishRefusesEmptyBundle(t *testing.T) {
	dyn, disc, _ := newClients("v1")
	if err := NewPublisher(dyn, disc).Publish(context.Background(), nil); err == nil {
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
