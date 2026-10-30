// Copyright Contributors to the Open Cluster Management project
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope="Cluster",shortName={"mcid"}
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Issuer",type="string",JSONPath=".spec.issuer"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// ManagedClusterIdentity records which projected ServiceAccount tokens may act
// for a managed cluster when the hub uses SPIFFE identities. It has the same
// name as the ManagedCluster. Only hub admins may write it: agents have no
// access to it, so a compromised agent cannot change which tokens are trusted
// for its cluster.
type ManagedClusterIdentity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec is the binding the hub admin approved when accepting the cluster.
	// +required
	Spec ManagedClusterIdentitySpec `json:"spec"`

	// status holds changes reported by the cluster that wait for approval.
	// +optional
	Status ManagedClusterIdentityStatus `json:"status,omitempty"`
}

// ManagedClusterIdentitySpec binds a managed cluster's ServiceAccount token
// issuer and agent ServiceAccounts.
type ManagedClusterIdentitySpec struct {
	// issuer is the managed cluster's ServiceAccount token issuer URL.
	// +required
	// +kubebuilder:validation:Pattern=`^https://[^?#]+$`
	// +kubebuilder:validation:MaxLength=1024
	Issuer string `json:"issuer"`

	// jwks pins the issuer's public signing keys as a JSON Web Key Set. When
	// set, the hub never contacts the issuer. When empty, the hub discovers the
	// keys from the issuer over https.
	// +optional
	// +kubebuilder:validation:MaxLength=65536
	JWKS string `json:"jwks,omitempty"`

	// serviceAccounts are the agent ServiceAccounts on the managed cluster that
	// may obtain agent SVIDs, identified by UID so a recreated ServiceAccount
	// does not inherit the binding.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=map
	// +listMapKey=namespace
	// +listMapKey=name
	ServiceAccounts []BoundServiceAccount `json:"serviceAccounts"`
}

// BoundServiceAccount is an agent ServiceAccount on the managed cluster.
type BoundServiceAccount struct {
	// namespace of the ServiceAccount.
	// +required
	// +kubebuilder:validation:MaxLength=63
	Namespace string `json:"namespace"`

	// name of the ServiceAccount.
	// +required
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// uid of the ServiceAccount, as recorded at join.
	// +required
	// +kubebuilder:validation:MaxLength=64
	UID string `json:"uid"`

	// agent names the agent, such as registration or work. It becomes part of
	// the agent's hub user name, system:open-cluster-management:{cluster}:{agent}.
	// +required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:MaxLength=63
	Agent string `json:"agent"`
}

// ManagedClusterIdentityStatus holds changes reported by the cluster's
// registration agent. The hub never applies them on its own.
type ManagedClusterIdentityStatus struct {
	// pendingJWKS are new issuer signing keys the registration agent reported
	// after the managed cluster rotated them. A hub admin approves them by
	// copying them into spec.jwks after comparing thumbprints with the managed
	// cluster admin.
	// +optional
	// +kubebuilder:validation:MaxLength=65536
	PendingJWKS string `json:"pendingJWKS,omitempty"`

	// pendingSince is when pendingJWKS was reported.
	// +optional
	PendingSince *metav1.Time `json:"pendingSince,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ManagedClusterIdentityList is a collection of ManagedClusterIdentity.
type ManagedClusterIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard list metadata.
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#types-kinds
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	// items is a list of ManagedClusterIdentity.
	Items []ManagedClusterIdentity `json:"items"`
}
