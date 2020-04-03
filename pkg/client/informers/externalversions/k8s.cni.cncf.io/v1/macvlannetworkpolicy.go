/*
Copyright 2020 The Kubernetes Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by informer-gen. DO NOT EDIT.

package v1

import (
	time "time"

	k8scnicncfiov1 "github.com/s1061123/macvlan-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1"
	versioned "github.com/s1061123/macvlan-networkpolicy/pkg/client/clientset/versioned"
	internalinterfaces "github.com/s1061123/macvlan-networkpolicy/pkg/client/informers/externalversions/internalinterfaces"
	v1 "github.com/s1061123/macvlan-networkpolicy/pkg/client/listers/k8s.cni.cncf.io/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// MacvlanNetworkPolicyInformer provides access to a shared informer and lister for
// MacvlanNetworkPolicies.
type MacvlanNetworkPolicyInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1.MacvlanNetworkPolicyLister
}

type macvlanNetworkPolicyInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewMacvlanNetworkPolicyInformer constructs a new informer for MacvlanNetworkPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewMacvlanNetworkPolicyInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredMacvlanNetworkPolicyInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredMacvlanNetworkPolicyInformer constructs a new informer for MacvlanNetworkPolicy type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredMacvlanNetworkPolicyInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.K8sCniCncfIoV1().MacvlanNetworkPolicies(namespace).List(options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.K8sCniCncfIoV1().MacvlanNetworkPolicies(namespace).Watch(options)
			},
		},
		&k8scnicncfiov1.MacvlanNetworkPolicy{},
		resyncPeriod,
		indexers,
	)
}

func (f *macvlanNetworkPolicyInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredMacvlanNetworkPolicyInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *macvlanNetworkPolicyInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&k8scnicncfiov1.MacvlanNetworkPolicy{}, f.defaultInformer)
}

func (f *macvlanNetworkPolicyInformer) Lister() v1.MacvlanNetworkPolicyLister {
	return v1.NewMacvlanNetworkPolicyLister(f.Informer().GetIndexer())
}
