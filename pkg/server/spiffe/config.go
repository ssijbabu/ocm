// Package spiffe configures the hub gRPC server's SPIFFE mode: the hub CA held
// in an external KMS, the hub server SVID it signs, and the hub trust bundle.
package spiffe

import (
	"fmt"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/azurekeyvault"
	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/openbao"
	"open-cluster-management.io/ocm/pkg/server/spiffe/svid"
)

// SignerType names a KMS the hub CA key can live in.
type SignerType string

const (
	SignerTypeAzureKeyVault SignerType = "AzureKeyVault"
	SignerTypeOpenBao       SignerType = "OpenBao"
)

// Config is the gRPC server's SPIFFE configuration file.
type Config struct {
	// TrustDomain is this hub's SPIFFE trust domain. It must be unique to the hub.
	TrustDomain string `json:"trustDomain"`
	// TokenAudience is the audience spoke agents request on their projected
	// tokens. It must be unique to the hub.
	TokenAudience string `json:"tokenAudience"`
	// AgentSVIDLifetime is the agent SVID lifetime. Defaults to 1h.
	AgentSVIDLifetime metav1.Duration `json:"agentSVIDLifetime,omitempty"`
	// DNSNames are added to the hub server SVID.
	DNSNames []string `json:"dnsNames,omitempty"`
	// ServerSVIDTTL is the hub server SVID lifetime. Defaults to 1h.
	ServerSVIDTTL metav1.Duration `json:"serverSVIDTTL,omitempty"`
	// MaxAgentSVIDLifetime paces hub CA rotation. Defaults to 1h.
	MaxAgentSVIDLifetime metav1.Duration `json:"maxAgentSVIDLifetime,omitempty"`
	// CACheckInterval is how often the KMS is checked for a rotated hub CA. Defaults to 1m.
	CACheckInterval metav1.Duration `json:"caCheckInterval,omitempty"`
	Signer          SignerConfig    `json:"signer"`
}

// SignerConfig selects and configures the KMS holding the hub CA key.
type SignerConfig struct {
	Type          SignerType           `json:"type"`
	AzureKeyVault *AzureKeyVaultConfig `json:"azureKeyVault,omitempty"`
	OpenBao       *OpenBaoConfig       `json:"openBao,omitempty"`
}

// AzureKeyVaultConfig points at the hub CA certificate in Azure Key Vault.
// Authentication uses Microsoft Entra Workload ID from the pod environment.
type AzureKeyVaultConfig struct {
	VaultURL        string `json:"vaultURL"`
	CertificateName string `json:"certificateName"`
}

// OpenBaoConfig points at the hub CA transit key and certificate in OpenBao.
// Authentication uses the Kubernetes auth method with a projected token.
type OpenBaoConfig struct {
	Address         string `json:"address"`
	Namespace       string `json:"namespace,omitempty"`
	TransitMount    string `json:"transitMount,omitempty"`
	KeyName         string `json:"keyName"`
	CertificatePath string `json:"certificatePath"`
	AuthMount       string `json:"authMount,omitempty"`
	AuthRole        string `json:"authRole"`
	TokenFile       string `json:"tokenFile"`
}

// AgentSVIDTTL returns the agent SVID lifetime, defaulting to 1h.
func (c *Config) AgentSVIDTTL() time.Duration {
	if c.AgentSVIDLifetime.Duration == 0 {
		return time.Hour
	}
	return c.AgentSVIDLifetime.Duration
}

// LoadConfig reads and validates a configuration file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read SPIFFE config %s: %w", path, err)
	}
	cfg := &Config{}
	if err := yaml.UnmarshalStrict(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse SPIFFE config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid SPIFFE config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks the configuration without contacting the KMS.
func (c *Config) Validate() error {
	if err := svid.ValidateTrustDomain(c.TrustDomain); err != nil {
		return err
	}
	if c.TokenAudience == "" {
		return fmt.Errorf("tokenAudience is required and must be unique to this hub")
	}
	if c.AgentSVIDLifetime.Duration > c.MaxAgentSVIDLifetime.Duration && c.MaxAgentSVIDLifetime.Duration > 0 {
		return fmt.Errorf("agentSVIDLifetime must not exceed maxAgentSVIDLifetime")
	}
	for name, d := range map[string]time.Duration{
		"agentSVIDLifetime":    c.AgentSVIDLifetime.Duration,
		"serverSVIDTTL":        c.ServerSVIDTTL.Duration,
		"maxAgentSVIDLifetime": c.MaxAgentSVIDLifetime.Duration,
		"caCheckInterval":      c.CACheckInterval.Duration,
	} {
		if d < 0 {
			return fmt.Errorf("%s must not be negative", name)
		}
	}
	switch c.Signer.Type {
	case SignerTypeAzureKeyVault:
		if c.Signer.AzureKeyVault == nil {
			return fmt.Errorf("signer.azureKeyVault is required for signer type %s", c.Signer.Type)
		}
	case SignerTypeOpenBao:
		if c.Signer.OpenBao == nil {
			return fmt.Errorf("signer.openBao is required for signer type %s", c.Signer.Type)
		}
	default:
		return fmt.Errorf("signer.type %q is not supported, use %s or %s", c.Signer.Type, SignerTypeAzureKeyVault, SignerTypeOpenBao)
	}
	return nil
}

// NewSigner builds the hub CA signer the configuration selects.
func NewSigner(c SignerConfig) (signer.Signer, error) {
	switch c.Type {
	case SignerTypeAzureKeyVault:
		if c.AzureKeyVault == nil {
			return nil, fmt.Errorf("signer.azureKeyVault is required")
		}
		tokens, err := azurekeyvault.NewWorkloadIdentityTokenSourceFromEnv()
		if err != nil {
			return nil, err
		}
		return azurekeyvault.New(azurekeyvault.Options{
			VaultURL:        c.AzureKeyVault.VaultURL,
			CertificateName: c.AzureKeyVault.CertificateName,
			TokenSource:     tokens,
		})
	case SignerTypeOpenBao:
		o := c.OpenBao
		if o == nil {
			return nil, fmt.Errorf("signer.openBao is required")
		}
		return openbao.New(openbao.Options{
			Address:         o.Address,
			Namespace:       o.Namespace,
			TransitMount:    o.TransitMount,
			KeyName:         o.KeyName,
			CertificatePath: o.CertificatePath,
			TokenSource: &openbao.KubernetesAuthTokenSource{
				Address:   o.Address,
				Namespace: o.Namespace,
				Mount:     o.AuthMount,
				Role:      o.AuthRole,
				TokenFile: o.TokenFile,
			},
		})
	default:
		return nil, fmt.Errorf("signer.type %q is not supported", c.Type)
	}
}

// SourceOptions converts the configuration into svid.Options.
func (c *Config) SourceOptions() svid.Options {
	return svid.Options{
		TrustDomain:          c.TrustDomain,
		DNSNames:             c.DNSNames,
		TTL:                  c.ServerSVIDTTL.Duration,
		MaxAgentSVIDLifetime: c.MaxAgentSVIDLifetime.Duration,
		CACheckInterval:      c.CACheckInterval.Duration,
	}
}
