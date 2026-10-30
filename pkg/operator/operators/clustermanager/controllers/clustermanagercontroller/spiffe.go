package clustermanagercontroller

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	operatorapiv1 "open-cluster-management.io/api/operator/v1"

	"open-cluster-management.io/ocm/manifests"
	"open-cluster-management.io/ocm/pkg/server/spiffe"
)

const (
	// openBaoTokenFile is where the gRPC server's projected token for OpenBao
	// is mounted.
	openBaoTokenFile            = "/var/run/secrets/openbao/token"
	defaultOpenBaoTokenAudience = "openbao"
)

// setSPIFFEConfig fills the gRPC server's SPIFFE settings from the
// ClusterManager.
func setSPIFFEConfig(config *manifests.HubConfig, spec *operatorapiv1.SPIFFEHubConfig) error {
	cfg := spiffe.Config{
		TrustDomain:   spec.TrustDomain,
		TokenAudience: spec.TokenAudience,
		DNSNames:      spec.DNSNames,
		Signer:        spiffe.SignerConfig{Type: spiffe.SignerType(spec.Signer.Type)},
	}
	if spec.AgentSVIDLifetime != nil {
		cfg.AgentSVIDLifetime = metav1.Duration{Duration: spec.AgentSVIDLifetime.Duration}
		// Hub CA rotation waits one agent SVID lifetime per stage, so it must
		// follow the lifetime: a shorter wait would sign with a new hub CA
		// before every agent has learned it.
		cfg.MaxAgentSVIDLifetime = cfg.AgentSVIDLifetime
	}
	switch spec.Signer.Type {
	case operatorapiv1.SPIFFESignerTypeAzureKeyVault:
		if spec.Signer.AzureKeyVault == nil {
			return fmt.Errorf("signer.azureKeyVault is required for signer type %s", spec.Signer.Type)
		}
		cfg.Signer.AzureKeyVault = &spiffe.AzureKeyVaultConfig{
			VaultURL:        spec.Signer.AzureKeyVault.VaultURL,
			CertificateName: spec.Signer.AzureKeyVault.CertificateName,
		}
	case operatorapiv1.SPIFFESignerTypeOpenBao:
		o := spec.Signer.OpenBao
		if o == nil {
			return fmt.Errorf("signer.openBao is required for signer type %s", spec.Signer.Type)
		}
		cfg.Signer.OpenBao = &spiffe.OpenBaoConfig{
			Address:         o.Address,
			Namespace:       o.Namespace,
			TransitMount:    o.TransitMount,
			KeyName:         o.KeyName,
			CertificatePath: o.CertificatePath,
			AuthMount:       o.AuthMount,
			AuthRole:        o.AuthRole,
			TokenFile:       openBaoTokenFile,
		}
		config.GRPCSPIFFEOpenBaoTokenAudience = o.TokenAudience
		if config.GRPCSPIFFEOpenBaoTokenAudience == "" {
			config.GRPCSPIFFEOpenBaoTokenAudience = defaultOpenBaoTokenAudience
		}
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid SPIFFE configuration: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(data)
	config.GRPCSPIFFEEnabled = true
	config.GRPCSPIFFEConfig = data
	config.GRPCSPIFFEConfigHash = hex.EncodeToString(sum[:])
	config.GRPCSPIFFEServiceAccountAnnotations = spec.ServiceAccountAnnotations
	config.GRPCSPIFFEPodLabels = spec.PodLabels
	return nil
}
