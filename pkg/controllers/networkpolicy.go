/*
Copyright 2017 The Kubernetes Authors.

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

package controllers

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	multiinformerv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/informers/externalversions/k8s.cni.cncf.io/v1beta1"

	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

// NetworkPolicyHandler is an abstract interface of objects which receive
// notifications about policy object changes.
type NetworkPolicyHandler interface {
	// OnPolicyAdd is called whenever creation of new policy object
	// is observed.
	OnPolicyAdd(policy *multiv1beta1.MultiNetworkPolicy)
	// OnPolicyUpdate is called whenever modification of an existing
	// policy object is observed.
	OnPolicyUpdate(oldPolicy, policy *multiv1beta1.MultiNetworkPolicy)
	// OnPolicyDelete is called whenever deletion of an existing policy
	// object is observed.
	OnPolicyDelete(policy *multiv1beta1.MultiNetworkPolicy)
	// OnPolicySynced is called once all the initial event handlers were
	// called and the state is fully propagated to local cache.
	OnPolicySynced()
}

// NetworkPolicyConfig ...
type NetworkPolicyConfig struct {
	listerSynced  cache.InformerSynced
	eventHandlers []NetworkPolicyHandler
}

// NewNetworkPolicyConfig creates a new NetworkPolicyConfig .
func NewNetworkPolicyConfig(policyInformer multiinformerv1beta1.MultiNetworkPolicyInformer, resyncPeriod time.Duration) *NetworkPolicyConfig {
	result := &NetworkPolicyConfig{
		listerSynced: policyInformer.Informer().HasSynced,
	}

	policyInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    result.handleAddPolicy,
			UpdateFunc: result.handleUpdatePolicy,
			DeleteFunc: result.handleDeletePolicy,
		}, resyncPeriod,
	)

	return result
}

// RegisterEventHandler registers a handler which is called on every policy change.
func (c *NetworkPolicyConfig) RegisterEventHandler(handler NetworkPolicyHandler) {
	c.eventHandlers = append(c.eventHandlers, handler)
}

// Run ...
func (c *NetworkPolicyConfig) Run(stopCh <-chan struct{}) {
	klog.Info("Starting policy config controller")

	if !cache.WaitForNamedCacheSync("policy config", stopCh, c.listerSynced) {
		return
	}

	for i := range c.eventHandlers {
		klog.V(4).Infof("Calling handler.OnPolicySynced()")
		c.eventHandlers[i].OnPolicySynced()
	}
}

func (c *NetworkPolicyConfig) handleAddPolicy(obj interface{}) {
	policy, ok := obj.(*multiv1beta1.MultiNetworkPolicy)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		return
	}

	for i := range c.eventHandlers {
		klog.V(4).Infof("Calling handler.OnPolicyAdd")
		c.eventHandlers[i].OnPolicyAdd(policy)
	}
}

func (c *NetworkPolicyConfig) handleUpdatePolicy(oldObj, newObj interface{}) {
	oldPolicy, ok := oldObj.(*multiv1beta1.MultiNetworkPolicy)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", oldObj))
		return
	}
	policy, ok := newObj.(*multiv1beta1.MultiNetworkPolicy)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", newObj))
		return
	}
	for i := range c.eventHandlers {
		klog.V(4).Infof("Calling handler.OnPolicyUpdate")
		c.eventHandlers[i].OnPolicyUpdate(oldPolicy, policy)
	}
}

func (c *NetworkPolicyConfig) handleDeletePolicy(obj interface{}) {
	policy, ok := obj.(*multiv1beta1.MultiNetworkPolicy)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		}
		if policy, ok = tombstone.Obj.(*multiv1beta1.MultiNetworkPolicy); !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
			return
		}
	}
	for i := range c.eventHandlers {
		klog.V(4).Infof("Calling handler.OnPolicyDelete")
		c.eventHandlers[i].OnPolicyDelete(policy)
	}
}

// PolicyInfo contains information that defines a policy.
type PolicyInfo struct {
	Policy *multiv1beta1.MultiNetworkPolicy
}

// Name ...
func (info *PolicyInfo) Name() string {
	return info.Policy.ObjectMeta.Name
}

func (info *PolicyInfo) Namespace() string {
	return info.Policy.ObjectMeta.Namespace
}

// PolicyMap ...
type PolicyMap map[types.NamespacedName]PolicyInfo

// Update ...
func (pm *PolicyMap) Update(changes *PolicyChangeTracker) {
	if pm != nil {
		pm.apply(changes)
	}
}

func (pm *PolicyMap) apply(changes *PolicyChangeTracker) {
	if pm == nil || changes == nil {
		return
	}

	changes.lock.Lock()
	defer changes.lock.Unlock()
	for _, change := range changes.items {
		pm.unmerge(change.previous)
		pm.merge(change.current)
	}
	// clear changes after applying them to ServiceMap.
	changes.items = make(map[types.NamespacedName]*policyChange)
	return
}

func (pm *PolicyMap) merge(other PolicyMap) {
	for policyName, info := range other {
		(*pm)[policyName] = info
	}
}

func (pm *PolicyMap) unmerge(other PolicyMap) {
	for policyName := range other {
		delete(*pm, policyName)
	}
}

//XXX: for debug, to be removed
/*
func (pm *PolicyMap)String() string {
	if pm == nil {
		return ""
	}
	str := ""
	for _, v := range *pm {
		str = fmt.Sprintf("%s\n\tpod: %s", str, v.Name())
	}
	return str
}
*/

type policyChange struct {
	previous PolicyMap
	current  PolicyMap
}

// PolicyChangeTracker ...
type PolicyChangeTracker struct {
	// lock protects items.
	lock sync.Mutex
	// items maps a service to its serviceChange.
	items map[types.NamespacedName]*policyChange
}

// String ...
func (pct *PolicyChangeTracker) String() string {
	return fmt.Sprintf("policyChange: %v", pct.items)
}

func (pct *PolicyChangeTracker) newPolicyInfo(policy *multiv1beta1.MultiNetworkPolicy) (*PolicyInfo, error) {
	info := &PolicyInfo{
		Policy: policy,
	}
	return info, nil
}

func (pct *PolicyChangeTracker) policyToPolicyMap(policy *multiv1beta1.MultiNetworkPolicy) PolicyMap {
	if policy == nil {
		return nil
	}
	policyMap := make(PolicyMap)
	policyInfo, err := pct.newPolicyInfo(policy)
	if err != nil {
		return nil
	}

	policyMap[types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}] = *policyInfo
	return policyMap
}

// Update ...
func (pct *PolicyChangeTracker) Update(previous, current *multiv1beta1.MultiNetworkPolicy) bool {
	policy := current

	if pct == nil {
		return false
	}

	if policy == nil {
		policy = previous
	}
	if policy == nil {
		return false
	}

	namespacedName := types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}

	pct.lock.Lock()
	defer pct.lock.Unlock()

	change, exists := pct.items[namespacedName]
	if !exists {
		change = &policyChange{}
		prevPolicyMap := pct.policyToPolicyMap(previous)
		change.previous = prevPolicyMap
		pct.items[namespacedName] = change
	}

	curPolicyMap := pct.policyToPolicyMap(current)
	change.current = curPolicyMap
	if reflect.DeepEqual(change.previous, change.current) {
		delete(pct.items, namespacedName)
	}

	return len(pct.items) >= 0
}

// NewPolicyChangeTracker ...
func NewPolicyChangeTracker() *PolicyChangeTracker {
	return &PolicyChangeTracker{
		items: make(map[types.NamespacedName]*policyChange),
	}
}
