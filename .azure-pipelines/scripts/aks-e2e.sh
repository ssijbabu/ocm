#!/usr/bin/env bash
# End-to-end test of the azure registration driver on AKS with Azure Workload Identity.
# Automates AZURE_WORKLOAD_IDENTITY_TESTING.md: creates a hub and a spoke AKS cluster in a
# fresh resource group, installs OCM from the ACR images tagged IMG_TAG, and checks
# auto-approval, manual approval and ManifestWork delivery.
#
# Run from the ocm repo root with `az` logged in (the pipeline uses AzureCLI@2). It does not
# delete the resource group; the pipeline does that in a separate step.
#
# Required: RG, ACR_NAME, IMG_TAG
# Optional: LOCATION, NODE_VM_SIZE, TEST_MANUAL_APPROVAL (true|false), WORK_DIR

set -euo pipefail

: "${RG:?RG is required}"
: "${ACR_NAME:?ACR_NAME is required}"
: "${IMG_TAG:?IMG_TAG is required}"
LOCATION=${LOCATION:-eastus}
NODE_VM_SIZE=${NODE_VM_SIZE:-Standard_D2s_v3}
TEST_MANUAL_APPROVAL=${TEST_MANUAL_APPROVAL:-true}
WORK_DIR=${WORK_DIR:-$(mktemp -d)}

HUB_CLUSTER=ocm-hub
SPOKE_CLUSTER=ocm-spoke
SPOKE_NAME=ocm-spoke
WORKLOAD_IDENTITY_NAME=ocm-spoke-workload-identity
FEDERATED_CRED_NAME=ocm-spoke-workload-fic
HUB_NS=open-cluster-management-hub
AGENT_NS=open-cluster-management-agent

HUB_KUBECONFIG=$WORK_DIR/hub.kubeconfig
SPOKE_KUBECONFIG=$WORK_DIR/spoke.kubeconfig
DIAG_DIR=$WORK_DIR/diagnostics
mkdir -p "$DIAG_DIR"
# Kubeconfigs and the bootstrap token must not be readable by anyone else on the agent.
chmod 700 "$WORK_DIR"

log() { echo "##[section]$*"; }
fail() { echo "##[error]$*"; exit 1; }
hub() { kubectl --kubeconfig "$HUB_KUBECONFIG" "$@"; }
spoke() { kubectl --kubeconfig "$SPOKE_KUBECONFIG" "$@"; }

# wait_until <timeout-seconds> <description> <command...>
wait_until() {
  local timeout=$1 desc=$2
  shift 2
  local deadline=$((SECONDS + timeout))
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < deadline)) || fail "timed out after ${timeout}s waiting for: $desc"
    sleep 10
  done
  echo "ok: $desc"
}

collect_diagnostics() {
  set +e
  log "Collecting diagnostics into $DIAG_DIR"
  if [[ -f $HUB_KUBECONFIG ]]; then
    hub get managedcluster -o yaml >"$DIAG_DIR/hub-managedclusters.yaml" 2>&1
    hub -n "$HUB_NS" get pods -o wide >"$DIAG_DIR/hub-pods.txt" 2>&1
    hub -n "$HUB_NS" logs deploy/cluster-manager-registration-controller --tail=1000 \
      >"$DIAG_DIR/hub-registration-controller.log" 2>&1
    hub get csr >"$DIAG_DIR/hub-csrs.txt" 2>&1
  fi
  if [[ -f $SPOKE_KUBECONFIG ]]; then
    spoke -n "$AGENT_NS" get pods -o yaml >"$DIAG_DIR/spoke-agent-pods.yaml" 2>&1
    spoke -n "$AGENT_NS" logs -l app=klusterlet-agent --tail=1000 >"$DIAG_DIR/spoke-agent.log" 2>&1
    spoke -n open-cluster-management logs deploy/klusterlet --tail=1000 >"$DIAG_DIR/spoke-operator.log" 2>&1
  fi
}
trap collect_diagnostics EXIT

# --- predicates used with wait_until --------------------------------------------------------

condition_true() { # <managedcluster> <condition type>
  [[ $(hub get managedcluster "$1" -o jsonpath="{.status.conditions[?(@.type=='$2')].status}") == True ]]
}

work_condition_true() { # <manifestwork> <condition type>
  [[ $(hub -n "$SPOKE_NAME" get manifestwork "$1" -o jsonpath="{.status.conditions[?(@.type=='$2')].status}") == True ]]
}

hub_ready() {
  (($(hub -n "$HUB_NS" get deploy -o name | wc -l) >= 3)) &&
    hub -n "$HUB_NS" wait --for=condition=Available deploy --all --timeout=5s
}

wi_webhook_running() {
  spoke -n kube-system get pods --no-headers | grep azure-wi-webhook | grep -q Running
}

agent_pod_mutated() {
  local pod
  pod=$(spoke -n "$AGENT_NS" get pod -l app=klusterlet-agent -o jsonpath='{.items[0].metadata.name}')
  [[ -n $pod ]] &&
    spoke -n "$AGENT_NS" get pod "$pod" -o jsonpath='{.spec.containers[0].env[*].name}' |
    grep -q AZURE_FEDERATED_TOKEN_FILE
}

# --- helpers ---------------------------------------------------------------------------------

write_hub_values() { # <auto-approve: true|false>
  local gates="" drivers
  if [[ $1 == true ]]; then
    gates="
      - feature: ManagedClusterAutoApproval
        mode: Enable"
    drivers="
      - authType: azure
        azure:
          autoApprovedIdentities:
            - \"^${WORKLOAD_PRINCIPAL_ID}\$\""
  else
    drivers="
      - authType: azure"
  fi
  cat >"$WORK_DIR/hub-values.yaml" <<EOF
createBootstrapSA: true
images:
  registry: ${ACR_NAME}.azurecr.io
  tag: ${IMG_TAG}
clusterManager:
  create: true
  mode: Default
  registrationConfiguration:
    featureGates:
      - feature: DefaultClusterSet
        mode: Enable${gates}
    registrationDrivers:${drivers}
  workConfiguration:
    workDriver: kube
EOF
}

wait_for_join() {
  wait_until 600 "ManagedCluster $SPOKE_NAME exists" hub get managedcluster "$SPOKE_NAME"
  wait_until 600 "$SPOKE_NAME accepted" condition_true "$SPOKE_NAME" HubAcceptedManagedCluster
  wait_until 600 "$SPOKE_NAME joined" condition_true "$SPOKE_NAME" ManagedClusterJoined
  wait_until 600 "$SPOKE_NAME available" condition_true "$SPOKE_NAME" ManagedClusterConditionAvailable
}

assert_no_csr() {
  local csrs
  csrs=$(hub get csr -l "open-cluster-management.io/cluster-name=$SPOKE_NAME" -o name)
  [[ -z $csrs ]] || fail "azure driver should not create CSRs, found: $csrs"
  echo "ok: no CSRs for $SPOKE_NAME"
}

manifestwork_smoke_test() { # <suffix>
  local work=azure-wi-smoke-$1 cm=azure-wi-proof-$1
  log "ManifestWork smoke test ($1)"
  hub apply -f - <<EOF
apiVersion: work.open-cluster-management.io/v1
kind: ManifestWork
metadata:
  name: ${work}
  namespace: ${SPOKE_NAME}
spec:
  workload:
    manifests:
      - apiVersion: v1
        kind: ConfigMap
        metadata:
          name: ${cm}
          namespace: default
        data:
          hello: "delivered via azure workload identity federation"
EOF
  wait_until 300 "ManifestWork $work applied" work_condition_true "$work" Applied
  wait_until 300 "ManifestWork $work available" work_condition_true "$work" Available
  spoke -n default get configmap "$cm" >/dev/null || fail "ConfigMap $cm not found on the spoke"
  echo "ok: ConfigMap $cm delivered to the spoke"
  hub -n "$SPOKE_NAME" delete manifestwork "$work" --wait=true
}

# --- 1-3. Clusters, ACR access, kubeconfigs --------------------------------------------------

log "Checking images ${ACR_NAME}.azurecr.io/*:${IMG_TAG}"
for image in registration registration-operator work placement addon-manager; do
  az acr repository show --name "$ACR_NAME" --image "${image}:${IMG_TAG}" -o none ||
    fail "image ${image}:${IMG_TAG} not found in ${ACR_NAME}"
done

log "Creating resource group $RG and AKS clusters in $LOCATION"
az group create --name "$RG" --location "$LOCATION" \
  --tags purpose=ocm-aks-e2e build="${BUILD_BUILDID:-local}" -o none

az aks create --resource-group "$RG" --name "$HUB_CLUSTER" --location "$LOCATION" \
  --node-count 1 --node-vm-size "$NODE_VM_SIZE" \
  --enable-managed-identity --enable-aad --generate-ssh-keys --no-wait -o none
az aks create --resource-group "$RG" --name "$SPOKE_CLUSTER" --location "$LOCATION" \
  --node-count 1 --node-vm-size "$NODE_VM_SIZE" \
  --enable-managed-identity --enable-oidc-issuer --enable-workload-identity \
  --generate-ssh-keys --no-wait -o none
az aks wait --resource-group "$RG" --name "$HUB_CLUSTER" --created --timeout 1800
az aks wait --resource-group "$RG" --name "$SPOKE_CLUSTER" --created --timeout 1800

log "Granting both clusters pull access to $ACR_NAME"
az aks update --resource-group "$RG" --name "$HUB_CLUSTER" --attach-acr "$ACR_NAME" -o none
az aks update --resource-group "$RG" --name "$SPOKE_CLUSTER" --attach-acr "$ACR_NAME" -o none

az aks get-credentials --resource-group "$RG" --name "$HUB_CLUSTER" --admin \
  --file "$HUB_KUBECONFIG" --overwrite-existing
az aks get-credentials --resource-group "$RG" --name "$SPOKE_CLUSTER" --admin \
  --file "$SPOKE_KUBECONFIG" --overwrite-existing

wait_until 600 "workload identity webhook running on the spoke" wi_webhook_running

# --- 5. Workload identity and federated credential -------------------------------------------

log "Creating workload identity $WORKLOAD_IDENTITY_NAME"
az identity create --resource-group "$RG" --name "$WORKLOAD_IDENTITY_NAME" --location "$LOCATION" -o none
WORKLOAD_CLIENT_ID=$(az identity show -g "$RG" -n "$WORKLOAD_IDENTITY_NAME" --query clientId -o tsv)
WORKLOAD_PRINCIPAL_ID=$(az identity show -g "$RG" -n "$WORKLOAD_IDENTITY_NAME" --query principalId -o tsv)
OIDC_ISSUER=$(az aks show -g "$RG" -n "$SPOKE_CLUSTER" --query oidcIssuerProfile.issuerUrl -o tsv)

# Singleton mode runs the agent as klusterlet-work-sa in open-cluster-management-agent.
az identity federated-credential create \
  --name "$FEDERATED_CRED_NAME" \
  --identity-name "$WORKLOAD_IDENTITY_NAME" \
  --resource-group "$RG" \
  --issuer "$OIDC_ISSUER" \
  --subject "system:serviceaccount:${AGENT_NS}:klusterlet-work-sa" \
  --audience api://AzureADTokenExchange -o none

# --- 6. Hub, auto-approval -------------------------------------------------------------------

log "Installing the hub (auto-approval)"
write_hub_values true
hub create namespace open-cluster-management --dry-run=client -o yaml | hub apply -f -
helm --kubeconfig "$HUB_KUBECONFIG" install cluster-manager deploy/cluster-manager/chart/cluster-manager \
  --namespace open-cluster-management -f "$WORK_DIR/hub-values.yaml"
wait_until 900 "hub deployments available" hub_ready

# --- 7. Bootstrap kubeconfig -----------------------------------------------------------------

log "Building the bootstrap kubeconfig"
BOOTSTRAP_TOKEN=$(hub -n open-cluster-management create token agent-registration-bootstrap --duration=4h)
echo "##vso[task.setsecret]$BOOTSTRAP_TOKEN"
HUB_SERVER=$(hub config view --minify -o jsonpath='{.clusters[0].cluster.server}')
HUB_CA=$(hub config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
cat >"$WORK_DIR/bootstrap-hub.kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: ${HUB_CA}
    server: ${HUB_SERVER}
  name: hub
contexts:
- context:
    cluster: hub
    user: bootstrap
  name: bootstrap
current-context: bootstrap
users:
- name: bootstrap
  user:
    token: ${BOOTSTRAP_TOKEN}
EOF

# --- 8. Spoke --------------------------------------------------------------------------------

log "Installing the klusterlet on the spoke"
cat >"$WORK_DIR/spoke-values.yaml" <<EOF
images:
  registry: ${ACR_NAME}.azurecr.io
  tag: ${IMG_TAG}
klusterlet:
  create: true
  mode: Singleton
  clusterName: ${SPOKE_NAME}
  registrationConfiguration:
    registrationDriver:
      authType: azure
      azure:
        managedClusterAzureID: "${WORKLOAD_PRINCIPAL_ID}"
        clientID: "${WORKLOAD_CLIENT_ID}"
EOF
spoke create namespace open-cluster-management --dry-run=client -o yaml | spoke apply -f -
helm --kubeconfig "$SPOKE_KUBECONFIG" install klusterlet deploy/klusterlet/chart/klusterlet \
  --namespace open-cluster-management \
  --set-file bootstrapHubKubeConfig="$WORK_DIR/bootstrap-hub.kubeconfig" \
  -f "$WORK_DIR/spoke-values.yaml"

wait_until 600 "agent pod mutated by the workload identity webhook" agent_pod_mutated
wait_for_join
assert_no_csr

# --- 10. ManifestWork delivery ---------------------------------------------------------------

manifestwork_smoke_test auto

# --- 9. Manual approval ----------------------------------------------------------------------

if [[ $TEST_MANUAL_APPROVAL == true || $TEST_MANUAL_APPROVAL == True ]]; then
  log "Switching the hub to manual approval and re-joining the spoke"
  write_hub_values false
  helm --kubeconfig "$HUB_KUBECONFIG" upgrade cluster-manager deploy/cluster-manager/chart/cluster-manager \
    --namespace open-cluster-management -f "$WORK_DIR/hub-values.yaml"
  hub delete managedcluster "$SPOKE_NAME" --ignore-not-found --wait=true --timeout=5m
  hub wait --for=delete "namespace/$SPOKE_NAME" --timeout=10m || true

  spoke -n "$AGENT_NS" delete secret hub-kubeconfig-secret --ignore-not-found
  spoke -n "$AGENT_NS" delete pod -l app=klusterlet-agent

  wait_until 600 "ManagedCluster $SPOKE_NAME re-created" hub get managedcluster "$SPOKE_NAME"
  log "Checking that $SPOKE_NAME stays pending without approval"
  sleep 60
  [[ $(hub get managedcluster "$SPOKE_NAME" -o jsonpath='{.spec.hubAcceptsClient}') != true ]] ||
    fail "$SPOKE_NAME was accepted without approval"
  ! condition_true "$SPOKE_NAME" ManagedClusterJoined ||
    fail "$SPOKE_NAME joined without approval"
  echo "ok: $SPOKE_NAME is pending"

  log "Approving $SPOKE_NAME"
  hub patch managedcluster "$SPOKE_NAME" --type=merge -p '{"spec":{"hubAcceptsClient":true}}'
  wait_for_join
  assert_no_csr
  manifestwork_smoke_test manual
fi

log "AKS e2e passed"
