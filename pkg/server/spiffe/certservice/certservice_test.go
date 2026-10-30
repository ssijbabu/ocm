package certservice

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	testtoken "open-cluster-management.io/ocm/pkg/server/spiffe/satoken/satokentest"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/memory"
)

const (
	trustDomain = "hub1.example.org"
	audience    = "open-cluster-management.io/hub1"
	cluster     = "cluster1"
	issuerURL   = "https://spoke1.example.org"
)

type fakeCA struct{ ca *signer.CA }

func (f fakeCA) ActiveCA() *signer.CA             { return f.ca }
func (f fakeCA) TrustBundle() []*x509.Certificate { return []*x509.Certificate{f.ca.Certificate} }

type bindings map[string]*Binding

func (b bindings) Lookup(_ context.Context, c string) (*Binding, error) {
	if x, ok := b[c]; ok {
		return x, nil
	}
	return nil, errors.New("not accepted")
}

type addons map[string]*AddonServiceAccount

func (a addons) Lookup(_ context.Context, c, addon string) (*AddonServiceAccount, error) {
	if x, ok := a[c+"/"+addon]; ok {
		return x, nil
	}
	return nil, errors.New("not enabled")
}

type recorded struct{ issuances []Issuance }

func (r *recorded) RecordIssuance(_ context.Context, i Issuance) {
	r.issuances = append(r.issuances, i)
}

type fixture struct {
	svc    *Service
	issuer *testtoken.Issuer
	ca     *signer.CA
	rec    *recorded
}

func newFixture(t *testing.T, mutate func(*Options)) *fixture {
	t.Helper()
	m, err := memory.NewSelfSigned(trustDomain, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := m.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	iss := testtoken.New(issuerURL)
	rec := &recorded{}
	opts := Options{
		TrustDomain: trustDomain,
		Audience:    audience,
		CA:          fakeCA{ca: ca},
		Bindings: bindings{cluster: {
			Issuer:     issuerURL,
			PinnedJWKS: iss.JWKS(),
			ServiceAccounts: []AllowedServiceAccount{
				{Namespace: "open-cluster-management-agent", Name: "klusterlet-registration-sa", UID: "sa-uid-1", Agent: "registration"},
				{Namespace: "open-cluster-management-agent", Name: "klusterlet-work-sa", UID: "sa-uid-2", Agent: "work"},
			},
		}},
		Addons:         addons{cluster + "/managed-serviceaccount": {Namespace: "open-cluster-management-agent-addon", Name: "managed-serviceaccount"}},
		Recorder:       rec,
		PerSourceRate:  1000,
		PerClusterRate: 1000,
	}
	if mutate != nil {
		mutate(&opts)
	}
	svc, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, issuer: iss, ca: ca, rec: rec}
}

func newCSR(t *testing.T, key crypto.Signer) []byte {
	t.Helper()
	if key == nil {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		key = k
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (f *fixture) request(t *testing.T, claims testtoken.Claims) Request {
	if claims.Audience == nil {
		claims.Audience = []string{audience}
	}
	return Request{ClusterName: cluster, CSR: newCSR(t, nil), Token: f.issuer.Token(claims), Source: "10.0.0.1"}
}

func TestIssueRegistrationAndWorkAgentSVIDs(t *testing.T) {
	f := newFixture(t, nil)
	for _, c := range []struct {
		sa, uid, user string
	}{
		{sa: "klusterlet-registration-sa", uid: "sa-uid-1", user: "system:open-cluster-management:cluster1:registration"},
		{sa: "klusterlet-work-sa", uid: "sa-uid-2", user: "system:open-cluster-management:cluster1:work"},
	} {
		resp, err := f.svc.CreateCertificate(context.Background(), f.request(t, testtoken.Claims{Name: c.sa, UID: c.uid}))
		if err != nil {
			t.Fatalf("%s: %v", c.sa, err)
		}
		leaf := resp.Certificate
		if want := "spiffe://hub1.example.org/ocm/cluster/cluster1/ns/open-cluster-management-agent/sa/" + c.sa; leaf.URIs[0].String() != want {
			t.Errorf("want %s, got %s", want, leaf.URIs[0])
		}
		if leaf.Subject.CommonName != c.user {
			t.Errorf("want user %s, got %s", c.user, leaf.Subject.CommonName)
		}
		if strings.Join(leaf.Subject.Organization, ",") != "system:open-cluster-management:cluster1,system:open-cluster-management:managed-clusters" {
			t.Errorf("unexpected groups %v", leaf.Subject.Organization)
		}
		if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
			t.Errorf("agent SVID must be client-only, got %v", leaf.ExtKeyUsage)
		}
		roots := x509.NewCertPool()
		roots.AddCert(f.ca.Certificate)
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			t.Errorf("agent SVID does not verify: %v", err)
		}
		if len(resp.TrustBundle) != 1 {
			t.Errorf("want the hub trust bundle returned")
		}
	}
	if len(f.rec.issuances) != 2 || f.rec.issuances[0].Pod == "" {
		t.Errorf("want two issuance records with the pod, got %+v", f.rec.issuances)
	}
}

func TestIssueAddonAgentSVID(t *testing.T) {
	f := newFixture(t, nil)
	req := f.request(t, testtoken.Claims{Namespace: "open-cluster-management-agent-addon", Name: "managed-serviceaccount", UID: "x"})
	req.AddonName = "managed-serviceaccount"
	resp, err := f.svc.CreateCertificate(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if want := "system:open-cluster-management:cluster:cluster1:addon:managed-serviceaccount:agent:managed-serviceaccount"; resp.Certificate.Subject.CommonName != want {
		t.Errorf("want user %s, got %s", want, resp.Certificate.Subject.CommonName)
	}
}

func TestRefusalsAreUniform(t *testing.T) {
	f := newFixture(t, nil)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	cases := map[string]func() Request{
		"spoke not accepted": func() Request {
			r := f.request(t, testtoken.Claims{})
			r.ClusterName = "cluster2"
			return r
		},
		"ServiceAccount recreated with a new UID": func() Request { return f.request(t, testtoken.Claims{UID: "new-uid"}) },
		"ServiceAccount not bound":                func() Request { return f.request(t, testtoken.Claims{Name: "default"}) },
		"other hub's audience": func() Request {
			return f.request(t, testtoken.Claims{Audience: []string{"open-cluster-management.io/hub2"}})
		},
		"token from another issuer": func() Request {
			r := f.request(t, testtoken.Claims{})
			r.Token = testtoken.New(issuerURL).Token(testtoken.Claims{Audience: []string{audience}})
			return r
		},
		"addon not enabled": func() Request {
			r := f.request(t, testtoken.Claims{Namespace: "open-cluster-management-agent-addon", Name: "managed-serviceaccount"})
			r.AddonName = "other-addon"
			return r
		},
		"addon token for another ServiceAccount": func() Request {
			r := f.request(t, testtoken.Claims{})
			r.AddonName = "managed-serviceaccount"
			return r
		},
		"RSA agent key": func() Request {
			r := f.request(t, testtoken.Claims{})
			r.CSR = newCSR(t, rsaKey)
			return r
		},
		"garbage CSR": func() Request {
			r := f.request(t, testtoken.Claims{})
			r.CSR = []byte("not a CSR")
			return r
		},
		"oversized token": func() Request {
			r := f.request(t, testtoken.Claims{})
			r.Token = strings.Repeat("a", maxTokenSize+1)
			return r
		},
		"no cluster name": func() Request {
			r := f.request(t, testtoken.Claims{})
			r.ClusterName = ""
			return r
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := f.svc.CreateCertificate(context.Background(), mk())
			if !errors.Is(err, ErrNotReady) || err.Error() != ErrNotReady.Error() {
				t.Fatalf("want the uniform not-ready answer, got %v", err)
			}
		})
	}
	if len(f.rec.issuances) != 0 {
		t.Errorf("refused requests must not be recorded as issued")
	}
}

func TestRateLimits(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.PerSourceRate = 0.001 })
	var refused int
	for i := 0; i < 7; i++ {
		if _, err := f.svc.CreateCertificate(context.Background(), f.request(t, testtoken.Claims{})); errors.Is(err, ErrNotReady) {
			refused++
		}
	}
	if refused != 2 {
		t.Errorf("want the burst of 5 allowed and 2 refused, got %d refused", refused)
	}
}

type failingKMS struct{}

func (failingKMS) ActiveCA() *signer.CA             { return nil }
func (failingKMS) TrustBundle() []*x509.Certificate { return nil }

func TestUnavailableWithoutHubCA(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.CA = failingKMS{} })
	if _, err := f.svc.CreateCertificate(context.Background(), f.request(t, testtoken.Claims{})); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestNewValidates(t *testing.T) {
	for name, o := range map[string]Options{
		"no trust domain": {Audience: audience, CA: failingKMS{}, Bindings: bindings{}},
		"no audience":     {TrustDomain: trustDomain, CA: failingKMS{}, Bindings: bindings{}},
		"no CA":           {TrustDomain: trustDomain, Audience: audience, Bindings: bindings{}},
		"no bindings":     {TrustDomain: trustDomain, Audience: audience, CA: failingKMS{}},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestEventRecorder(t *testing.T) {
	client := kubefake.NewSimpleClientset()
	NewEventRecorder(client, "grpc-server").RecordIssuance(context.Background(), Issuance{
		Cluster: cluster, Namespace: "ns", ServiceAccount: "sa", Pod: "pod", SPIFFEID: "spiffe://x", Serial: "1", NotAfter: time.Now(),
	})
	events, err := client.CoreV1().Events(cluster).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Items) != 1 || events.Items[0].Reason != EventReasonAgentSVIDIssued || !strings.Contains(events.Items[0].Message, "pod pod") {
		t.Fatalf("unexpected events %+v", events.Items)
	}
}
