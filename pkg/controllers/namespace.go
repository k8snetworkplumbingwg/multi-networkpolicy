package controllers

import (
	"fmt"
	"reflect"
	"sync"
	"time"

	"k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog"
)

// NamespaceHandler is an abstract interface of objects which receive
// notifications about pod object changes.
type NamespaceHandler interface {
	// OnNamespaceAdd is called whenever creation of new ns object
	// is observed.
	OnNamespaceAdd(ns *v1.Namespace)
	// OnNamespaceUpdate is called whenever modification of an existing
	// ns object is observed.
	OnNamespaceUpdate(oldNS, ns *v1.Namespace)
	// OnNamespaceDelete is called whenever deletion of an existing ns
	// object is observed.
	OnNamespaceDelete(ns *v1.Namespace)
	// OnNamespaceSynced is called once all the initial event handlers were
	// called and the state is fully propagated to local cache.
	OnNamespaceSynced()
}

// NamespaceConfig ...
type NamespaceConfig struct {
	listerSynced  cache.InformerSynced
	eventHandlers []NamespaceHandler
}

// NewNamespaceConfig creates a new NamespaceConfig.
func NewNamespaceConfig(nsInformer coreinformers.NamespaceInformer, resyncPeriod time.Duration) *NamespaceConfig {
	result := &NamespaceConfig{
		listerSynced: nsInformer.Informer().HasSynced,
	}

	nsInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    result.handleAddNamespace,
			UpdateFunc: result.handleUpdateNamespace,
			DeleteFunc: result.handleDeleteNamespace,
		},
		resyncPeriod,
	)
	return result
}

// RegisterEventHandler registers a handler which is called on every pod change.
func (c *NamespaceConfig) RegisterEventHandler(handler NamespaceHandler) {
	c.eventHandlers = append(c.eventHandlers, handler)
}

// Run waits for cache synced and invokes handlers after syncing.
func (c *NamespaceConfig) Run(stopCh <-chan struct{}) {
	klog.Info("Starting ns config controller")

	if !cache.WaitForNamedCacheSync("ns config", stopCh, c.listerSynced) {
		return
	}

	for i := range c.eventHandlers {
		klog.V(4).Infof("Calling handler.OnNamespaceSynced()")
		c.eventHandlers[i].OnNamespaceSynced()
	}
}

func (c *NamespaceConfig) handleAddNamespace(obj interface{}) {
	ns, ok := obj.(*v1.Namespace)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		return
	}

	for i := range c.eventHandlers {
		klog.V(4).Infof("Calling handler.OnNamespaceAdd")
		c.eventHandlers[i].OnNamespaceAdd(ns)
	}
}

func (c *NamespaceConfig) handleUpdateNamespace(oldObj, newObj interface{}) {
	oldNamespace, ok := oldObj.(*v1.Namespace)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", oldObj))
		return
	}
	ns, ok := newObj.(*v1.Namespace)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", newObj))
		return
	}
	for i := range c.eventHandlers {
		klog.V(4).Infof("Calling handler.OnNamespaceUpdate")
		c.eventHandlers[i].OnNamespaceUpdate(oldNamespace, ns)
	}
}

func (c *NamespaceConfig) handleDeleteNamespace(obj interface{}) {
	ns, ok := obj.(*v1.Namespace)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		}
		if ns, ok = tombstone.Obj.(*v1.Namespace); !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
			return
		}
	}
	for i := range c.eventHandlers {
		klog.V(4).Infof("Calling handler.OnNamespaceDelete")
		c.eventHandlers[i].OnNamespaceDelete(ns)
	}
}

// NamespaceInfo contains information that defines a namespace.
type NamespaceInfo struct {
	Name   string
	Labels map[string]string
}

type nsChange struct {
	previous NamespaceMap
	current  NamespaceMap
}

// NamespaceChangeTracker carries state about uncommitted changes to an arbitrary number of
// Namespaces in the node, keyed by their namespace and name
type NamespaceChangeTracker struct {
	// lock protects items.
	lock sync.Mutex
	// items maps a service to its podChange.
	items map[string]*nsChange
}

func (nct *NamespaceChangeTracker) newNamespaceInfo(ns *v1.Namespace) *NamespaceInfo {
	return &NamespaceInfo{
		Name:   ns.Name,
		Labels: ns.Labels,
	}
}

// NewNamespaceChangeTracker ...
func NewNamespaceChangeTracker() *NamespaceChangeTracker {
	return &NamespaceChangeTracker{
		items: make(map[string]*nsChange),
	}
}

func (nct *NamespaceChangeTracker) nsToNamespaceMap(ns *v1.Namespace) NamespaceMap {
	if ns == nil {
		return nil
	}

	namespaceMap := make(NamespaceMap)
	nsInfo := nct.newNamespaceInfo(ns)
	namespaceMap[ns.Name] = *nsInfo
	return namespaceMap
}

// Update ...
func (nct *NamespaceChangeTracker) Update(previous, current *v1.Namespace) bool {
	ns := current

	if nct == nil {
		return false
	}

	if ns == nil {
		ns = previous
	}
	if ns == nil {
		return false
	}

	nct.lock.Lock()
	defer nct.lock.Unlock()

	change, exists := nct.items[ns.Name]
	if !exists {
		change = &nsChange{}
		prevNamespaceMap := nct.nsToNamespaceMap(previous)
		change.previous = prevNamespaceMap
		nct.items[ns.Name] = change
	}
	curNamespaceMap := nct.nsToNamespaceMap(current)
	change.current = curNamespaceMap
	if reflect.DeepEqual(change.previous, change.current) {
		delete(nct.items, ns.Name)
	}
	return len(nct.items) >= 0
}

// NamespaceMap ...
type NamespaceMap map[string]NamespaceInfo

// Update updates podMap base on the given changes
func (nm *NamespaceMap) Update(changes *NamespaceChangeTracker) {
	if nm != nil {
		nm.apply(changes)
	}
}

func (nm *NamespaceMap) apply(changes *NamespaceChangeTracker) {
	if nm == nil || changes == nil {
		return
	}

	changes.lock.Lock()
	defer changes.lock.Unlock()
	for _, change := range changes.items {
		nm.unmerge(change.previous)
		nm.merge(change.current)
	}
	// clear changes after applying them to ServiceMap.
	changes.items = make(map[string]*nsChange)
	return
}

func (nm *NamespaceMap) merge(other NamespaceMap) {
	for nsName, info := range other {
		(*nm)[nsName] = info
	}
}

func (nm *NamespaceMap) unmerge(other NamespaceMap) {
	for nsName := range other {
		delete(*nm, nsName)
	}
}

// GetNamespaceInfo ...
func (nm *NamespaceMap) GetNamespaceInfo(nsName string) (*NamespaceInfo, error) {
	nsInfo, ok := (*nm)[nsName]
	if ok {
		return &nsInfo, nil
	}

	return nil, fmt.Errorf("not found")
}
