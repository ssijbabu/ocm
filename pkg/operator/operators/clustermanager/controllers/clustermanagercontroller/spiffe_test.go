package clustermanagercontroller

import (
	"os"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"

	operatorapiv1 "open-cluster-management.io/api/operator/v1"

	"open-cluster-management.io/ocm/manifests"
	testingcommon "open-cluster-management.io/ocm/pkg/common/testing"
	"open-cluster-management.io/ocm/pkg/server/spiffe"
)

func spiffeClusterManager() *operatorapiv1.ClusterManager {
	cm := newClusterManager("testhub")
	cm.Spec.RegistrationConfiguration = &operatorapiv1.RegistrationHubConfiguration{
		RegistrationDrivers: []operatorapiv1.RegistrationDriverHub{{
			AuthType: operatorapiv1.GRPCAuthType,
			GRPC: &operatorapiv1.GRPCRegistrationConfig{SPIFFE: &operatorapiv1.SPIFFEHubConfig{
				TrustDomain:               "hub1.example.org",
				TokenAudience:             "open-cluster-management.io/hub1",
				ServiceAccountAnnotations: map[string]string{"example.com/identity": "ocm-grpc-server"},
				PodLabels:                 map[string]string{"example.com/use-identity": "true"},
				Signer: operatorapiv1.SPIFFESigner{
					Type: operatorapiv1.SPIFFESignerTypeOpenBao,
					OpenBao: &operatorapiv1.OpenBaoSigner{
						Address: "https://openbao.example.com:8200", KeyName: "ocm-spiffe-ca",
						CertificatePath: "secret/data/ocm/spiffe-ca", AuthRole: "ocm-grpc-server",
					},
				},
			}},
		}},
	}
	return cm
}

func createdObjects(tc *testController) []runtime.Object {
	var objs []runtime.Object
	for _, action := range append(tc.hubKubeClient.Actions(), tc.managementKubeClient.Actions()...) {
		if action.GetVerb() == createVerb {
			objs = append(objs, action.(clienttesting.CreateActionImpl).Object)
		}
	}
	return objs
}

func TestSyncDeployWithGRPCSPIFFE(t *testing.T) {
	cm := spiffeClusterManager()
	tc := newTestController(t, cm)
	setup(t, tc, nil)
	if err := tc.clusterManagerController.sync(ctx, testingcommon.NewFakeSyncContext(t, "testhub"), "testhub"); err != nil {
		t.Fatalf("sync failed: %v", err)
	}

	var cfg *corev1.ConfigMap
	var sa *corev1.ServiceAccount
	var deploy *appsv1.Deployment
	var policy *admissionv1.ValidatingAdmissionPolicy
	var binding *admissionv1.ValidatingAdmissionPolicyBinding
	var role *rbacv1.ClusterRole
	for _, obj := range createdObjects(tc) {
		switch o := obj.(type) {
		case *corev1.ConfigMap:
			if o.Name == "grpc-server-spiffe-config" {
				cfg = o
			}
		case *corev1.ServiceAccount:
			if o.Name == "grpc-server-sa" {
				sa = o
			}
		case *appsv1.Deployment:
			if o.Name == "testhub-grpc-server" {
				deploy = o
			}
		case *admissionv1.ValidatingAdmissionPolicy:
			policy = o
		case *admissionv1.ValidatingAdmissionPolicyBinding:
			binding = o
		case *rbacv1.ClusterRole:
			if strings.HasSuffix(o.Name, "-grpc-server-spiffe") {
				role = o
			}
		}
	}

	if cfg == nil {
		t.Fatal("SPIFFE config ConfigMap not created")
	}
	parsed := writeAndLoad(t, cfg.Data["config.yaml"])
	if parsed.TrustDomain != "hub1.example.org" || parsed.Signer.OpenBao == nil || parsed.Signer.OpenBao.TokenFile != openBaoTokenFile {
		t.Errorf("unexpected SPIFFE config %+v", parsed)
	}
	if sa == nil || sa.Annotations["example.com/identity"] != "ocm-grpc-server" {
		t.Errorf("grpc-server-sa is missing the provider annotations: %+v", sa)
	}
	if policy == nil || binding == nil || binding.Spec.PolicyName != policy.Name {
		t.Fatal("admission policy guarding grpc-server-sa not created")
	}
	if role == nil {
		t.Fatal("SPIFFE ClusterRole not created")
	}
	attest := false
	for _, r := range role.Rules {
		for _, v := range r.Verbs {
			if v == "attest" && len(r.ResourceNames) == 1 && r.ResourceNames[0] == "open-cluster-management.io/spiffe-hub" {
				attest = true
			}
		}
	}
	if !attest {
		t.Error("gRPC server cannot attest for the OCM SPIFFE signer")
	}

	if deploy == nil {
		t.Fatal("gRPC server Deployment not created")
	}
	pod := deploy.Spec.Template
	if pod.Labels["example.com/use-identity"] != "true" {
		t.Error("provider pod labels not applied")
	}
	if len(pod.Annotations["open-cluster-management.io/spiffe-config-hash"]) != 64 {
		t.Error("the pod template must carry the SPIFFE config hash, so a config change restarts the server")
	}
	if !strings.Contains(strings.Join(pod.Spec.Containers[0].Args, " "), "--spiffe-config=") {
		t.Error("gRPC server not started in SPIFFE mode")
	}
	var openBaoAudience string
	for _, v := range pod.Spec.Volumes {
		if v.Secret != nil {
			t.Errorf("SPIFFE mode must mount no Secret, found volume %s", v.Name)
		}
		if v.Name == "grpc-server-ca" {
			t.Error("SPIFFE mode must not mount the certificate-mode CA bundle")
		}
		if v.Projected != nil {
			for _, src := range v.Projected.Sources {
				if src.ServiceAccountToken != nil {
					openBaoAudience = src.ServiceAccountToken.Audience
				}
			}
		}
	}
	if openBaoAudience != defaultOpenBaoTokenAudience {
		t.Errorf("want a projected token for OpenBao, got audience %q", openBaoAudience)
	}
}

func TestSPIFFERejectedInHostedMode(t *testing.T) {
	cm := spiffeClusterManager()
	cm.Spec.DeployOption.Mode = operatorapiv1.InstallModeHosted
	tc := newTestController(t, cm)
	setup(t, tc, nil)
	if err := tc.clusterManagerController.sync(ctx, testingcommon.NewFakeSyncContext(t, "testhub"), "testhub"); err == nil {
		t.Fatal("expected SPIFFE in Hosted mode to be refused")
	}
}

func TestSPIFFERotationFollowsAgentSVIDLifetime(t *testing.T) {
	spec := spiffeClusterManager().Spec.RegistrationConfiguration.RegistrationDrivers[0].GRPC.SPIFFE
	spec.AgentSVIDLifetime = &metav1.Duration{Duration: 2 * time.Hour}
	config := &manifests.HubConfig{}
	if err := setSPIFFEConfig(config, spec); err != nil {
		t.Fatal(err)
	}
	cfg := writeAndLoad(t, string(config.GRPCSPIFFEConfig))
	if cfg.MaxAgentSVIDLifetime.Duration != 2*time.Hour {
		t.Errorf("hub CA rotation must wait one agent SVID lifetime per stage, got %v", cfg.MaxAgentSVIDLifetime.Duration)
	}
}

func writeAndLoad(t *testing.T, data string) *spiffe.Config {
	t.Helper()
	path := t.TempDir() + "/config.yaml"
	if err := writeFile(path, data); err != nil {
		t.Fatal(err)
	}
	cfg, err := spiffe.LoadConfig(path)
	if err != nil {
		t.Fatalf("rendered SPIFFE config does not load: %v\n%s", err, data)
	}
	return cfg
}

func writeFile(path, data string) error {
	return os.WriteFile(path, []byte(data), 0o600)
}
