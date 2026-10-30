package grpc

import (
	"context"
	"time"

	coordv1 "k8s.io/api/coordination/v1"

	addonv1beta1 "open-cluster-management.io/api/addon/v1beta1"
	addoninformers "open-cluster-management.io/api/client/addon/informers/externalversions"
	clusterv1client "open-cluster-management.io/api/client/cluster/clientset/versioned"
	clusterinformers "open-cluster-management.io/api/client/cluster/informers/externalversions"
	clusterv1informer "open-cluster-management.io/api/client/cluster/informers/externalversions/cluster/v1"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
	cloudeventsaddon "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/addon"
	cloudeventsaddonv1beta1 "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/addon/v1beta1"
	cloudeventscluster "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/cluster"
	cloudeventsevent "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/event"
	cloudeventslease "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/lease"
	cloudeventsoptions "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/options"
	cloudeventsstore "open-cluster-management.io/sdk-go/pkg/cloudevents/clients/store"

	"open-cluster-management.io/ocm/pkg/registration/register"
)

// NewClusterClients builds the ManagedCluster client and informer of the
// registration agent over CloudEvents. config is a *grpc.GRPCOptions.
func NewClusterClients(ctx context.Context, config any, clusterName string) (
	clusterv1client.Interface, clusterv1informer.ManagedClusterInformer, error) {
	clusterWatchStore := cloudeventsstore.NewAgentInformerWatcherStore[*clusterv1.ManagedCluster]()
	clusterClientHolder, err := cloudeventscluster.NewClientHolder(
		ctx,
		cloudeventsoptions.NewGenericClientOptions(
			config,
			cloudeventscluster.NewManagedClusterCodec(),
			clusterName,
		).
			WithClusterName(clusterName).
			WithClientWatcherStore(clusterWatchStore))
	if err != nil {
		return nil, nil, err
	}
	clusterClient := clusterClientHolder.ClusterInterface()
	clusterInformers := clusterinformers.NewSharedInformerFactory(
		clusterClient, 10*time.Minute).Cluster().V1().ManagedClusters()
	return clusterClient, clusterInformers, nil
}

// NewAgentClients builds the lease, event and add-on clients the registration
// agent uses after bootstrap, over CloudEvents.
func NewAgentClients(ctx context.Context, config any, clusterName string,
	clusterClient clusterv1client.Interface, clusterInformer clusterv1informer.ManagedClusterInformer) (*register.Clients, error) {
	leaseWatchStore := cloudeventsstore.NewSimpleStore[*coordv1.Lease]()
	leaseClient, err := cloudeventslease.NewLeaseClient(
		ctx,
		cloudeventsoptions.NewGenericClientOptions(
			config,
			cloudeventslease.NewLeaseCodec(),
			clusterName,
		).WithClusterName(clusterName).WithClientWatcherStore(leaseWatchStore),
		clusterName,
	)
	if err != nil {
		return nil, err
	}

	eventClient, err := cloudeventsevent.NewClientHolder(
		ctx,
		cloudeventsoptions.NewGenericClientOptions(
			config,
			cloudeventsevent.NewEventCodec(),
			clusterName,
		).WithClusterName(clusterName).WithSubscription(false).WithResyncEnabled(false),
	)
	if err != nil {
		return nil, err
	}

	addonWatchStore := cloudeventsstore.NewAgentInformerWatcherStore[*addonv1beta1.ManagedClusterAddOn]()
	addonClient, err := cloudeventsaddon.ManagedClusterAddOnInterface(
		ctx,
		cloudeventsoptions.NewGenericClientOptions(
			config,
			cloudeventsaddonv1beta1.NewManagedClusterAddOnCodec(),
			clusterName,
		).WithClusterName(clusterName).WithClientWatcherStore(addonWatchStore))
	if err != nil {
		return nil, err
	}
	addonInformer := addoninformers.NewSharedInformerFactoryWithOptions(
		addonClient, 10*time.Minute, addoninformers.WithNamespace(clusterName)).
		Addon().V1beta1().ManagedClusterAddOns()

	return &register.Clients{
		ClusterClient:   clusterClient,
		ClusterInformer: clusterInformer,
		AddonClient:     addonClient,
		AddonInformer:   addonInformer,
		LeaseClient:     leaseClient,
		EventsClient:    eventClient,
	}, nil
}
