package klusterletcontroller

import (
	"context"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"

	operatorapiv1 "open-cluster-management.io/api/operator/v1"

	testingcommon "open-cluster-management.io/ocm/pkg/common/testing"
	"open-cluster-management.io/ocm/pkg/operator/helpers"
)

func spiffeKlusterlet(mode operatorapiv1.InstallMode) *operatorapiv1.Klusterlet {
	k := newKlusterlet("klusterlet", "testns", "cluster1")
	k.Spec.DeployOption.Mode = mode
	k.Spec.RegistrationConfiguration.RegistrationDriver = operatorapiv1.RegistrationDriver{
		AuthType: operatorapiv1.GRPCAuthType,
		SPIFFE: &operatorapiv1.SPIFFEAgentConfig{
			GRPCServerAddress: "hub.example.org:443",
			TrustDomain:       "hub1.example.org",
			TokenAudience:     "open-cluster-management.io/hub1",
		},
	}
	return k
}

func createdObjectsOf(actions []clienttesting.Action) []runtime.Object {
	var objs []runtime.Object
	for _, a := range actions {
		if a.GetVerb() == createVerb {
			objs = append(objs, a.(clienttesting.CreateActionImpl).Object)
		}
	}
	return objs
}

func assertSPIFFEDeployment(t *testing.T, d *appsv1.Deployment) {
	t.Helper()
	if d == nil {
		t.Fatal("agent deployment not created")
	}
	args := strings.Join(d.Spec.Template.Spec.Containers[0].Args, " ")
	for _, want := range []string{"--spiffe-trust-domain=hub1.example.org", "--spiffe-grpc-server=hub.example.org:443"} {
		if !strings.Contains(args, want) {
			t.Errorf("%s: missing %s in %s", d.Name, want, args)
		}
	}
	if strings.Contains(args, "bootstrap") {
		t.Errorf("%s: SPIFFE mode must not use a bootstrap kubeconfig: %s", d.Name, args)
	}
	var audience, signer string
	for _, v := range d.Spec.Template.Spec.Volumes {
		if v.Secret != nil {
			t.Errorf("%s: SPIFFE mode must mount no Secret, found %s", d.Name, v.Name)
		}
		if v.Projected == nil {
			continue
		}
		for _, src := range v.Projected.Sources {
			if src.ServiceAccountToken != nil {
				audience = src.ServiceAccountToken.Audience
				if src.ServiceAccountToken.ExpirationSeconds == nil || *src.ServiceAccountToken.ExpirationSeconds != 600 {
					t.Errorf("%s: want a 10-minute token", d.Name)
				}
			}
			if src.ClusterTrustBundle != nil && src.ClusterTrustBundle.SignerName != nil {
				signer = *src.ClusterTrustBundle.SignerName
			}
		}
	}
	if audience != "open-cluster-management.io/hub1" {
		t.Errorf("%s: want a projected token with the hub audience, got %q", d.Name, audience)
	}
	if signer != "open-cluster-management.io/spiffe-hub" {
		t.Errorf("%s: want the hub trust bundle from the spoke ClusterTrustBundle, got signer %q", d.Name, signer)
	}
}

func TestSyncDeploySPIFFE(t *testing.T) {
	klusterlet := spiffeKlusterlet(operatorapiv1.InstallModeDefault)
	syncContext := testingcommon.NewFakeSyncContext(t, "klusterlet")
	controller := newTestController(t, klusterlet, syncContext.Recorder(), nil, false, newNamespace("testns"))
	if err := controller.controller.sync(context.TODO(), syncContext, "klusterlet"); err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	assertSPIFFEDeployment(t, getDeployments(controller.kubeClient.Actions(), createVerb, "registration-agent"))
	assertSPIFFEDeployment(t, getDeployments(controller.kubeClient.Actions(), createVerb, "work-agent"))

	var role *rbacv1.ClusterRole
	var binding *rbacv1.ClusterRoleBinding
	var policy *admissionv1.ValidatingAdmissionPolicy
	for _, obj := range createdObjectsOf(controller.kubeClient.Actions()) {
		switch o := obj.(type) {
		case *rbacv1.ClusterRole:
			if strings.HasSuffix(o.Name, "-spiffe:agent") {
				role = o
			}
		case *rbacv1.ClusterRoleBinding:
			if strings.HasSuffix(o.Name, "-spiffe:agent") {
				binding = o
			}
		case *admissionv1.ValidatingAdmissionPolicy:
			policy = o
		}
	}
	if role == nil || binding == nil {
		t.Fatal("ClusterTrustBundle writer role not created on the managed cluster")
	}
	if len(binding.Subjects) != 2 {
		t.Errorf("want the registration and work ServiceAccounts bound, got %v", binding.Subjects)
	}
	if policy == nil {
		t.Fatal("admission policy guarding the agent ServiceAccounts not created")
	}
}

func TestSyncDeploySPIFFESingleton(t *testing.T) {
	klusterlet := spiffeKlusterlet(operatorapiv1.InstallModeSingleton)
	syncContext := testingcommon.NewFakeSyncContext(t, "klusterlet")
	controller := newTestController(t, klusterlet, syncContext.Recorder(), nil, false, newNamespace("testns"))
	if err := controller.controller.sync(context.TODO(), syncContext, "klusterlet"); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	assertSPIFFEDeployment(t, getDeployments(controller.kubeClient.Actions(), createVerb, "agent"))
}

func TestSPIFFERejectedInHostedMode(t *testing.T) {
	klusterlet := newKlusterletHosted("klusterlet", "testns", "cluster1")
	klusterlet.Spec.RegistrationConfiguration.RegistrationDriver = spiffeKlusterlet(operatorapiv1.InstallModeHosted).
		Spec.RegistrationConfiguration.RegistrationDriver
	meta.SetStatusCondition(&klusterlet.Status.Conditions, metav1.Condition{
		Type: operatorapiv1.ConditionReadyToApply, Status: metav1.ConditionTrue, Reason: "KlusterletPrepared",
		Message: "Klusterlet is ready to apply, the external managed kubeconfig secret was created at: " +
			hostedKubeconfigCreationTime,
	})
	agentNamespace := helpers.AgentNamespace(klusterlet)
	syncContext := testingcommon.NewFakeSyncContext(t, "klusterlet")
	controller := newTestControllerHosted(t, klusterlet, nil, newNamespace(agentNamespace),
		newSecret(helpers.ImagePullSecret, "open-cluster-management"))
	if err := controller.controller.sync(context.TODO(), syncContext, "klusterlet"); err == nil {
		t.Fatal("expected SPIFFE in Hosted mode to be refused")
	}
}
