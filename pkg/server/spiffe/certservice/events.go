package certservice

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// EventReasonAgentSVIDIssued marks issuance Events, which replace the
// CertificateSigningRequest objects that used to record agent certificates.
const EventReasonAgentSVIDIssued = "AgentSVIDIssued"

// EventRecorder records each issuance as an Event in the spoke's cluster
// namespace on the hub.
type EventRecorder struct {
	client    kubernetes.Interface
	component string
}

var _ Recorder = &EventRecorder{}

// NewEventRecorder returns a Recorder writing Events with the given client.
func NewEventRecorder(client kubernetes.Interface, component string) *EventRecorder {
	return &EventRecorder{client: client, component: component}
}

func (r *EventRecorder) RecordIssuance(ctx context.Context, i Issuance) {
	who := fmt.Sprintf("ServiceAccount %s/%s", i.Namespace, i.ServiceAccount)
	if i.Addon != "" {
		who = fmt.Sprintf("addon %s, %s", i.Addon, who)
	}
	now := metav1.NewTime(time.Now())
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{GenerateName: i.Cluster + "-svid-", Namespace: i.Cluster},
		// The Event lives in the cluster namespace, so the reference carries
		// that namespace even though ManagedCluster is cluster-scoped: the API
		// server requires the two to match.
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "cluster.open-cluster-management.io/v1",
			Kind:       "ManagedCluster",
			Name:       i.Cluster,
			Namespace:  i.Cluster,
		},
		Reason:         EventReasonAgentSVIDIssued,
		Message:        fmt.Sprintf("Issued agent SVID %s to %s, pod %s, serial %s, expires %s", i.SPIFFEID, who, i.Pod, i.Serial, i.NotAfter.UTC().Format(time.RFC3339)),
		Type:           corev1.EventTypeNormal,
		Source:         corev1.EventSource{Component: r.component},
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
	}
	// The server log and the KMS audit log also record the issuance, so a
	// failed Event does not fail the request.
	if _, err := r.client.CoreV1().Events(i.Cluster).Create(ctx, event, metav1.CreateOptions{}); err != nil {
		klog.FromContext(ctx).Error(err, "Failed to record agent SVID issuance", "cluster", i.Cluster, "serial", i.Serial)
	}
}
