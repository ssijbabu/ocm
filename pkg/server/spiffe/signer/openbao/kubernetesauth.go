package openbao

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"k8s.io/utils/clock"

	"open-cluster-management.io/ocm/pkg/server/spiffe/signer/internal/rest"
)

// refreshBefore renews the OpenBao token this long before its lease ends.
const refreshBefore = time.Minute

// KubernetesAuthTokenSource logs in to OpenBao's Kubernetes auth method with
// the pod's projected ServiceAccount token. The OpenBao role should be bound
// only to the gRPC server's ServiceAccount and only to a policy that allows
// signing with the hub CA transit key and reading the hub CA certificate.
type KubernetesAuthTokenSource struct {
	Address   string
	Namespace string
	// Mount is where the Kubernetes auth method is mounted. Defaults to "kubernetes".
	Mount string
	Role  string
	// TokenFile is the projected ServiceAccount token, with an audience the
	// OpenBao role accepts.
	TokenFile  string
	HTTPClient *http.Client
	Clock      clock.PassiveClock

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

var _ TokenSource = &KubernetesAuthTokenSource{}

type loginResponse struct {
	Auth struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int64  `json:"lease_duration"`
	} `json:"auth"`
}

func (k *KubernetesAuthTokenSource) Token(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	clk := k.Clock
	if clk == nil {
		clk = clock.RealClock{}
	}
	now := clk.Now()
	if k.token != "" && now.Before(k.expiresAt.Add(-refreshBefore)) {
		return k.token, nil
	}

	addr, err := validateAddress(k.Address)
	if err != nil {
		return "", err
	}
	if k.Role == "" || k.TokenFile == "" {
		return "", fmt.Errorf("the Kubernetes auth role and token file are required")
	}
	// Re-read the file every time: the kubelet rotates the projected token.
	jwt, err := os.ReadFile(k.TokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to read the projected ServiceAccount token: %w", err)
	}
	mount := strings.Trim(k.Mount, "/")
	if mount == "" {
		mount = "kubernetes"
	}

	body, err := rest.JSONBody(map[string]string{"role": k.Role, "jwt": strings.TrimSpace(string(jwt))})
	if err != nil {
		return "", err
	}
	headers := map[string]string{}
	if k.Namespace != "" {
		headers["X-Vault-Namespace"] = k.Namespace
	}
	client := k.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	var resp loginResponse
	if err := rest.Do(ctx, client, http.MethodPost, addr+"/v1/auth/"+mount+"/login", headers, body, &resp); err != nil {
		return "", fmt.Errorf("Kubernetes auth login to OpenBao as role %q failed: %w", k.Role, err)
	}
	if resp.Auth.ClientToken == "" || resp.Auth.LeaseDuration <= 0 {
		return "", fmt.Errorf("no client token in the OpenBao login response")
	}

	k.token = resp.Auth.ClientToken
	k.expiresAt = now.Add(time.Duration(resp.Auth.LeaseDuration) * time.Second)
	return k.token, nil
}
