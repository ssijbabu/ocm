package manifests

import (
	operatorapiv1 "open-cluster-management.io/api/operator/v1"
)

type HubConfig struct {
	ClusterManagerName             string
	ClusterManagerNamespace        string
	OperatorNamespace              string
	RegistrationImage              string
	RegistrationAPIServiceCABundle string
	WorkImage                      string
	WorkAPIServiceCABundle         string
	PlacementImage                 string
	PlacementDebugServerEnabled    bool
	PlacementServingCertSecret     string
	SIGPlacementDecisionEnabled    bool
	PlacementFeatureGates          []string
	AddonAPIServiceCABundle        string
	Replica                        int32
	HostedMode                     bool
	RegistrationWebhook            Webhook
	WorkWebhook                    Webhook
	AddonWebhook                   Webhook
	RegistrationFeatureGates       []string
	WorkFeatureGates               []string
	AddOnManagerImage              string
	AddOnManagerEnabled            bool
	WorkControllerEnabled          bool
	ClusterProfileEnabled          bool
	AgentImage                     string
	CloudEventsDriverEnabled       bool
	ClusterImporterEnabled         bool
	ImporterRenderers              string
	WorkDriver                     string
	AutoApproveUsers               string
	ImagePullSecret                string
	ImagePullSecretName            string
	// ResourceRequirementResourceType is the resource requirement resource type for the cluster manager managed containers.
	ResourceRequirementResourceType operatorapiv1.ResourceQosClass
	// ResourceRequirements is the resource requirements for the cluster manager managed containers.
	// The type has to be []byte to use "indent" template function.
	ResourceRequirements              []byte
	ManagedClusterIdentityCreatorRole string
	HubClusterArn                     string
	EnabledRegistrationDrivers        string
	AutoApprovedCSRUsers              string
	AutoApprovedARNPatterns           string
	AwsResourceTags                   string
	Labels                            map[string]string
	LabelsString                      string
	GRPCAuthEnabled                   bool
	GRPCServerImage                   string
	GRPCAutoApprovedUsers             string
	GRPCEndpointType                  string
	// GRPCSPIFFEEnabled switches the gRPC server to SPIFFE identities.
	GRPCSPIFFEEnabled bool
	// GRPCSPIFFEConfig is the gRPC server's SPIFFE config file. The type has to
	// be []byte to use the "indent" template function.
	GRPCSPIFFEConfig []byte
	// GRPCSPIFFEConfigHash goes on the gRPC server's pod template, so a
	// changed config restarts the server, which reads it only at startup.
	GRPCSPIFFEConfigHash                string
	GRPCSPIFFEServiceAccountAnnotations map[string]string
	GRPCSPIFFEPodLabels                 map[string]string
	// GRPCSPIFFEOpenBaoTokenAudience is set when the hub CA is in OpenBao: the
	// gRPC server then gets a projected token with this audience for OpenBao.
	GRPCSPIFFEOpenBaoTokenAudience string
	// TLS configuration injected into all managed hub component deployments
	TLSMinVersion   string
	TLSCipherSuites string

	NetworkPoliciesEnabled bool
}

type Webhook struct {
	// Hosted configuration
	HostedIsIPFormat bool
	HostedAddress    string
	HostedPort       int32

	// Bind configuration
	Port            int32
	HealthProbePort int32
	MetricsPort     int32
	HostNetwork     bool
}
