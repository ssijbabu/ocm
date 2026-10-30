package azurekeyvault

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"k8s.io/utils/clock"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/internal/rest"
)

const (
	defaultAuthorityHost = "https://login.microsoftonline.com/"
	keyVaultScope        = "https://vault.azure.net/.default"
	// refreshBefore renews the access token this long before it expires.
	refreshBefore = 5 * time.Minute
)

// WorkloadIdentityTokenSource exchanges the pod's projected ServiceAccount
// token for a Key Vault access token through Microsoft Entra Workload ID. No
// client secret is involved: the federated credential on the managed identity
// trusts the hub cluster's ServiceAccount issuer.
type WorkloadIdentityTokenSource struct {
	TenantID      string
	ClientID      string
	TokenFile     string
	AuthorityHost string
	HTTPClient    *http.Client
	Clock         clock.PassiveClock

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

var _ TokenSource = &WorkloadIdentityTokenSource{}

// NewWorkloadIdentityTokenSourceFromEnv reads the variables the Azure workload
// identity webhook injects into pods labeled azure.workload.identity/use=true.
func NewWorkloadIdentityTokenSourceFromEnv() (*WorkloadIdentityTokenSource, error) {
	w := &WorkloadIdentityTokenSource{
		TenantID:      os.Getenv("AZURE_TENANT_ID"),
		ClientID:      os.Getenv("AZURE_CLIENT_ID"),
		TokenFile:     os.Getenv("AZURE_FEDERATED_TOKEN_FILE"),
		AuthorityHost: os.Getenv("AZURE_AUTHORITY_HOST"),
	}
	if w.TenantID == "" || w.ClientID == "" || w.TokenFile == "" {
		return nil, fmt.Errorf("AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_FEDERATED_TOKEN_FILE must be set; " +
			"label the gRPC server pod azure.workload.identity/use=true and annotate its ServiceAccount with azure.workload.identity/client-id")
	}
	return w, nil
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (w *WorkloadIdentityTokenSource) Token(ctx context.Context) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	clk := w.Clock
	if clk == nil {
		clk = clock.RealClock{}
	}
	now := clk.Now()
	if w.token != "" && now.Before(w.expiresAt.Add(-refreshBefore)) {
		return w.token, nil
	}

	// Re-read the file every time: the kubelet rotates the projected token.
	assertion, err := os.ReadFile(w.TokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to read the projected ServiceAccount token: %w", err)
	}

	authority := w.AuthorityHost
	if authority == "" {
		authority = defaultAuthorityHost
	}
	authority = strings.TrimSuffix(authority, "/")

	form := url.Values{
		"client_id":             {w.ClientID},
		"scope":                 {keyVaultScope},
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {strings.TrimSpace(string(assertion))},
	}

	client := w.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	var resp tokenResponse
	if err := rest.Do(ctx, client, http.MethodPost,
		authority+"/"+url.PathEscape(w.TenantID)+"/oauth2/v2.0/token",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		strings.NewReader(form.Encode()), &resp); err != nil {
		return "", fmt.Errorf("workload identity token exchange with Microsoft Entra ID failed: %w", err)
	}
	if resp.AccessToken == "" || resp.ExpiresIn <= 0 {
		return "", fmt.Errorf("no access token in the Microsoft Entra ID response")
	}

	w.token = resp.AccessToken
	w.expiresAt = now.Add(time.Duration(resp.ExpiresIn) * time.Second)
	return w.token, nil
}
