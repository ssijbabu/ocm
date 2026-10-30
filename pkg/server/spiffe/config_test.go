package spiffe

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spiffe.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfig(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name: "azure key vault",
			content: `
trustDomain: hub1.example.org
tokenAudience: open-cluster-management.io/hub1
serverSVIDTTL: 30m
signer:
  type: AzureKeyVault
  azureKeyVault:
    vaultURL: https://my-vault.vault.azure.net
    certificateName: ocm-spiffe-ca
`,
		},
		{
			name: "openbao",
			content: `
trustDomain: hub1.example.org
tokenAudience: open-cluster-management.io/hub1
signer:
  type: OpenBao
  openBao:
    address: https://openbao.example.com:8200
    keyName: ocm-spiffe-ca
    certificatePath: secret/data/ocm/spiffe-ca
    authRole: ocm-grpc-server
    tokenFile: /var/run/secrets/openbao/token
`,
		},
		{name: "bad trust domain", content: "trustDomain: Hub\nsigner: {type: OpenBao, openBao: {}}\n", wantErr: true},
		{name: "unknown signer", content: "trustDomain: hub1\ntokenAudience: a\nsigner: {type: Memory}\n", wantErr: true},
		{name: "missing audience", content: "trustDomain: hub1\nsigner: {type: OpenBao, openBao: {}}\n", wantErr: true},
		{name: "missing provider block", content: "trustDomain: hub1\ntokenAudience: a\nsigner: {type: AzureKeyVault}\n", wantErr: true},
		{name: "unknown field", content: "trustDomain: hub1\ntokenAudience: a\ncaKey: x\nsigner: {type: OpenBao, openBao: {}}\n", wantErr: true},
		{name: "negative duration", content: "trustDomain: hub1\ntokenAudience: a\nserverSVIDTTL: -1m\nsigner: {type: OpenBao, openBao: {}}\n", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := LoadConfig(writeConfig(t, c.content))
			if c.wantErr != (err != nil) {
				t.Fatalf("wantErr %v, got %v", c.wantErr, err)
			}
			if err == nil && c.name == "azure key vault" && cfg.SourceOptions().TTL != 30*time.Minute {
				t.Errorf("want serverSVIDTTL 30m, got %s", cfg.SourceOptions().TTL)
			}
		})
	}
}

func TestNewSigner(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "tenant")
	t.Setenv("AZURE_CLIENT_ID", "client")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "/var/run/secrets/azure/tokens/azure-identity-token")

	if _, err := NewSigner(SignerConfig{Type: SignerTypeAzureKeyVault, AzureKeyVault: &AzureKeyVaultConfig{
		VaultURL: "https://my-vault.vault.azure.net", CertificateName: "ocm-spiffe-ca",
	}}); err != nil {
		t.Errorf("azure key vault: %v", err)
	}
	if _, err := NewSigner(SignerConfig{Type: SignerTypeOpenBao, OpenBao: &OpenBaoConfig{
		Address: "https://openbao.example.com:8200", KeyName: "ocm-spiffe-ca", CertificatePath: "secret/data/ca",
		AuthRole: "ocm-grpc-server", TokenFile: "/var/run/secrets/openbao/token",
	}}); err != nil {
		t.Errorf("openbao: %v", err)
	}
	if _, err := NewSigner(SignerConfig{Type: "Memory"}); err == nil {
		t.Error("expected an error for an unsupported signer type")
	}
}
