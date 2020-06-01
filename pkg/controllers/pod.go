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
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"

	docker "github.com/docker/docker/client"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"

	"google.golang.org/grpc"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	"k8s.io/klog"
	k8sutils "k8s.io/kubernetes/pkg/kubelet/util"
)

// PodHandler is an abstract interface of objects which receive
// notifications about pod object changes.
type PodHandler interface {
	// OnPodAdd is called whenever creation of new pod object
	// is observed.
	OnPodAdd(pod *v1.Pod)
	// OnPodUpdate is called whenever modification of an existing
	// pod object is observed.
	OnPodUpdate(oldPod, pod *v1.Pod)
	// OnPodDelete is called whenever deletion of an existing pod
	// object is observed.
	OnPodDelete(pod *v1.Pod)
	// OnPodSynced is called once all the initial event handlers were
	// called and the state is fully propagated to local cache.
	OnPodSynced()
}

// PodConfig ...
type PodConfig struct {
	listerSynched cache.InformerSynced
	eventHandlers []PodHandler
}

// NewPodConfig creates a new PodConfig.
func NewPodConfig(podInformer coreinformers.PodInformer, resyncPeriod time.Duration) *PodConfig {
	result := &PodConfig{
		listerSynched: podInformer.Informer().HasSynced,
	}

	podInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    result.handleAddPod,
			UpdateFunc: result.handleUpdatePod,
			DeleteFunc: result.handleDeletePod,
		},
		resyncPeriod,
	)
	return result
}

// RegisterEventHandler registers a handler which is called on every pod change.
func (c *PodConfig) RegisterEventHandler(handler PodHandler) {
	c.eventHandlers = append(c.eventHandlers, handler)
}

// Run waits for cache synced and invokes handlers after syncing.
func (c *PodConfig) Run(stopCh <-chan struct{}) {
	klog.Info("Starting pod config controller")

	if !cache.WaitForNamedCacheSync("pod config", stopCh, c.listerSynched) {
		return
	}

	for i := range c.eventHandlers {
		klog.V(4).Infof("Calling handler.OnPodSynced()")
		c.eventHandlers[i].OnPodSynced()
	}
}

func (c *PodConfig) handleAddPod(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		return
	}

	for i := range c.eventHandlers {
		klog.V(4).Infof("Calling handler.OnPodAdd")
		c.eventHandlers[i].OnPodAdd(pod)
	}
}

func (c *PodConfig) handleUpdatePod(oldObj, newObj interface{}) {
	oldPod, ok := oldObj.(*v1.Pod)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", oldObj))
		return
	}
	pod, ok := newObj.(*v1.Pod)
	if !ok {
		utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", newObj))
		return
	}
	for i := range c.eventHandlers {
		klog.V(4).Infof("Calling handler.OnPodUpdate")
		c.eventHandlers[i].OnPodUpdate(oldPod, pod)
	}
}

func (c *PodConfig) handleDeletePod(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
		}
		if pod, ok = tombstone.Obj.(*v1.Pod); !ok {
			utilruntime.HandleError(fmt.Errorf("unexpected object type: %v", obj))
			return
		}
	}
	for i := range c.eventHandlers {
		klog.V(4).Infof("Calling handler.OnPodDelete")
		c.eventHandlers[i].OnPodDelete(pod)
	}
}

// MacvlanInterfaceInfo ...
type MacvlanInterfaceInfo struct {
	NetattachName string
	InterfaceName string
	InterfaceType string
	IPs           []string
}

// PodInfo contains information that defines a pod.
type PodInfo struct {
	name               string
	namespace          string
	networkNamespace   string
	networkAttachments []*netdefv1.NetworkSelectionElement
	networkStatus      []netdefv1.NetworkStatus
	nodeName           string
	macVlanInterfaces  []MacvlanInterfaceInfo
}

// GetMultusNetIFs ...
func (info *PodInfo) GetMultusNetIFs() []string {
	results := []string{}

	if info != nil && len(info.networkStatus) > 0 {
		klog.Info("XXXST:", info.networkStatus)
		for _, status := range info.networkStatus[1:] {
			results = append(results, status.Interface)
		}
	}
	return results
}

// String ...
func (info *PodInfo) String() string {
	return fmt.Sprintf("pod:%s", info.name)
}

// Name ...
func (info *PodInfo) Name() string {
	return info.name
}

// Namespace ...
func (info *PodInfo) Namespace() string {
	return info.namespace
}

// NetworkNamespace ...
func (info *PodInfo) NetworkNamespace() string {
	return info.networkNamespace
}

// NetworkAttachments ...
func (info *PodInfo) NetworkAttachments() []*netdefv1.NetworkSelectionElement {
	return info.networkAttachments
}

// NetworkStatus ...
func (info *PodInfo) NetworkStatus() []netdefv1.NetworkStatus {
	return info.networkStatus
}

// Node ...
func (info *PodInfo) Node() string {
	return info.nodeName
}

// MacvlanInterfaces ...
func (info *PodInfo) MacvlanInterfaces() []MacvlanInterfaceInfo {
	return info.macVlanInterfaces
}

type podChange struct {
	previous PodMap
	current  PodMap
}

// PodChangeTracker carries state about uncommitted changes to an arbitrary number of
// Pods in the node, keyed by their namespace and name
type PodChangeTracker struct {
	// lock protects items.
	lock          sync.Mutex
	hostname      string
	netdefChanges *NetDefChangeTracker
	// items maps a service to its podChange.
	items    map[types.NamespacedName]*podChange
	recorder record.EventRecorder

	crioClient pb.RuntimeServiceClient
	crioConn   *grpc.ClientConn
}

// String
func (pct *PodChangeTracker) String() string {
	return fmt.Sprintf("podChange: %v", pct.items)
}

func (pct *PodChangeTracker) getPodNetworkNamespace(pod *v1.Pod) (string, error) {
	netNamespace := ""

	// get Container netns
	procPrefix := ""
	if len(pod.Status.ContainerStatuses) == 0 {
		return "", fmt.Errorf("XXX: No container status")
	}

	runtimeKind := strings.Split(pod.Status.ContainerStatuses[0].ContainerID, ":")
	if runtimeKind[0] == "docker" {
		containerID := strings.TrimPrefix(pod.Status.ContainerStatuses[0].ContainerID, "docker://")
		if len(containerID) > 0 {
			c, err := docker.NewEnvClient()
			if err != nil {
				panic(err)
			}

			c.NegotiateAPIVersion(context.TODO())
			json, err := c.ContainerInspect(context.TODO(), containerID)
			if err != nil {
				return "", fmt.Errorf("failed to get container info: %v", err)
			}
			if json.NetworkSettings == nil {
				return "", fmt.Errorf("failed to get container info: %v", err)
			}
			netNamespace = fmt.Sprintf("%s/proc/%d/ns/net", procPrefix, json.State.Pid)
		}
	} else { // crio
		containerID := strings.TrimPrefix(pod.Status.ContainerStatuses[0].ContainerID, "cri-o://")
		if len(containerID) > 0 {
			request := &pb.ContainerStatusRequest{
				ContainerId: containerID,
				Verbose:     true,
			}
			r, err := pct.crioClient.ContainerStatus(context.TODO(), request)
			if err != nil {
				return "", fmt.Errorf("cannot get containerStatus")
			}

			info := r.GetInfo()
			var infop interface{}
			json.Unmarshal([]byte(info["info"]), &infop)
			pid, ok := infop.(map[string]interface{})["pid"].(float64)
			if !ok {
				return "", fmt.Errorf("cannot get pid from containerStatus info")
			}
			netNamespace = fmt.Sprintf("%s/proc/%d/ns/net", procPrefix, int(pid))
		}
	}
	return netNamespace, nil
}

func (pct *PodChangeTracker) newPodInfo(pod *v1.Pod) (*PodInfo, error) {
	networks, err := netdefutils.ParsePodNetworkAnnotation(pod)
	if err != nil {
		klog.Infof("failed to get pod network annotation: %v", err)
	}
	// parse networkStatus
	statuses, _ := netdefutils.GetNetworkStatus(pod)

	// get container network namespace
	netNamespace := ""
	if pct.hostname == pod.Spec.NodeName {
		netNamespace, err = pct.getPodNetworkNamespace(pod)
		if err != nil {
			return nil, fmt.Errorf("failed to get pod network namespace: %v", err)
		}
	}

	// netdefname -> plugin name map
	networkPlugins := make(map[types.NamespacedName]string)
	if networks == nil {
		klog.Infof("XXX: %s/%s: NO NET", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
	} else {
		klog.Infof("XXX: %s/%s: net: %v", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, networks)
	}
	for _, n := range networks {
		namespace := pod.ObjectMeta.Namespace
		if n.Namespace != "" {
			namespace = n.Namespace
		}
		namespacedName := types.NamespacedName{Namespace: namespace, Name: n.Name}
		klog.Infof("XXX: networkPlugins[%s], %v", namespacedName, pct.netdefChanges.GetPluginType(namespacedName))
		networkPlugins[namespacedName] = pct.netdefChanges.GetPluginType(namespacedName)
	}
	klog.Infof("XXX: netdef->pluginMap: %v", networkPlugins)

	var macvlans []MacvlanInterfaceInfo
	for _, s := range statuses {
		namespace := pod.ObjectMeta.Namespace
		namespacedName := types.NamespacedName{Namespace: namespace, Name: s.Name}
		if networkPlugins[namespacedName] == "macvlan" {
			macvlans = append(macvlans, MacvlanInterfaceInfo{
				NetattachName: s.Name,
				InterfaceName: s.Interface,
				InterfaceType: networkPlugins[namespacedName],
				IPs:           s.IPs,
			})
		}
	}

	klog.Infof("XXX: Pod: %s/%s netns:%s macvlanIF:%v", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, netNamespace, macvlans)
	info := &PodInfo{
		name:               pod.ObjectMeta.Name,
		namespace:          pod.ObjectMeta.Namespace,
		networkAttachments: networks,
		networkStatus:      statuses,
		networkNamespace:   netNamespace,
		nodeName:           pod.Spec.NodeName,
		macVlanInterfaces:  macvlans,
	}
	return info, nil
}

// NewPodChangeTracker ...
func NewPodChangeTracker(hostname, hostPrefix string, recorder record.EventRecorder, ndt *NetDefChangeTracker) *PodChangeTracker {
	crioClient, crioConn, err := GetCrioRuntimeClient(hostPrefix)
	if err != nil {
		klog.Errorf("failed to get crio client: %v", err)
		return nil
	}

	return &PodChangeTracker{
		items:         make(map[types.NamespacedName]*podChange),
		hostname:      hostname,
		netdefChanges: ndt,
		recorder:      recorder,
		crioClient:    crioClient,
		crioConn:      crioConn,
	}
}

func (pct *PodChangeTracker) podToPodMap(pod *v1.Pod) PodMap {
	if pod == nil {
		return nil
	}

	podMap := make(PodMap)
	podinfo, err := pct.newPodInfo(pod)
	if err != nil {
		return nil
	}

	podMap[types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}] = *podinfo
	return podMap
}

// Update ...
func (pct *PodChangeTracker) Update(previous, current *v1.Pod) bool {
	pod := current

	if pct == nil {
		return false
	}

	if pod == nil {
		pod = previous
	}
	if pod == nil {
		return false
	}
	namespacedName := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}

	pct.lock.Lock()
	defer pct.lock.Unlock()

	change, exists := pct.items[namespacedName]
	if !exists {
		change = &podChange{}
		prevPodMap := pct.podToPodMap(previous)
		change.previous = prevPodMap
		pct.items[namespacedName] = change
	}
	curPodMap := pct.podToPodMap(current)
	change.current = curPodMap
	if reflect.DeepEqual(change.previous, change.current) {
		delete(pct.items, namespacedName)
	}
	return len(pct.items) > 0
}

// PodMap ...
type PodMap map[types.NamespacedName]PodInfo

// Update updates podMap base on the given changes
func (pm *PodMap) Update(changes *PodChangeTracker) {
	if pm != nil {
		pm.apply(changes)
	}
}

func (pm *PodMap) apply(changes *PodChangeTracker) {
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
	changes.items = make(map[types.NamespacedName]*podChange)
	return
}

func (pm *PodMap) merge(other PodMap) {
	for podName, info := range other {
		(*pm)[podName] = info
	}
}

func (pm *PodMap) unmerge(other PodMap) {
	for podName := range other {
		delete(*pm, podName)
	}
}

// GetPodInfo ...
func (pm *PodMap) GetPodInfo(pod *v1.Pod) (*PodInfo, error) {
	namespacedName := types.NamespacedName{Namespace: pod.Namespace, Name: pod.Name}

	podInfo, ok := (*pm)[namespacedName]
	if ok {
		return &podInfo, nil
	}

	return nil, fmt.Errorf("not found")
}

//XXX: for debug, to be removed
func (pm *PodMap) String() string {
	if pm == nil {
		return ""
	}
	str := ""
	for _, v := range *pm {
		str = fmt.Sprintf("%s\n\tpod: %s", str, v.Name())
	}
	return str
}

// =====================================
// misc functions...
// =====================================

func parsePodNetworkObjectName(podnetwork string) (string, string, string, error) {
	var netNsName string
	var netIfName string
	var networkName string

	slashItems := strings.Split(podnetwork, "/")
	if len(slashItems) == 2 {
		netNsName = strings.TrimSpace(slashItems[0])
		networkName = slashItems[1]
	} else if len(slashItems) == 1 {
		networkName = slashItems[0]
	} else {
		return "", "", "", fmt.Errorf("parsePodNetworkObjectName: Invalid network object (failed at '/')")
	}

	atItems := strings.Split(networkName, "@")
	networkName = strings.TrimSpace(atItems[0])
	if len(atItems) == 2 {
		netIfName = strings.TrimSpace(atItems[1])
	} else if len(atItems) != 1 {
		return "", "", "", fmt.Errorf("parsePodNetworkObjectName: Invalid network object (failed at '@')")
	}

	// Check and see if each item matches the specification for valid attachment name.
	// "Valid attachment names must be comprised of units of the DNS-1123 label format"
	// [a-z0-9]([-a-z0-9]*[a-z0-9])?
	// And we allow at (@), and forward slash (/) (units separated by commas)
	// It must start and end alphanumerically.
	allItems := []string{netNsName, networkName, netIfName}
	for i := range allItems {
		matched, _ := regexp.MatchString("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", allItems[i])
		if !matched && len([]rune(allItems[i])) > 0 {
			return "", "", "", fmt.Errorf(fmt.Sprintf("parsePodNetworkObjectName: Failed to parse: one or more items did not match comma-delimited format (must consist of lower case alphanumeric characters). Must start and end with an alphanumeric character), mismatch @ '%v'", allItems[i]))
		}
	}

	return netNsName, networkName, netIfName, nil
}

func getRuntimeClientConnection(hostPrefix string) (*grpc.ClientConn, error) {
	//return nil, fmt.Errorf("--runtime-endpoint is not set")
	//Docker/cri-o
	RuntimeEndpoint := fmt.Sprintf("unix://%s/var/run/crio/crio.sock", hostPrefix)
	Timeout := 10 * time.Second

	addr, dialer, err := k8sutils.GetAddressAndDialer(RuntimeEndpoint)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.Dial(addr, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(Timeout), grpc.WithContextDialer(dialer))
	if err != nil {
		return nil, fmt.Errorf("failed to connect, make sure you are running as root and the runtime has been started: %v", err)
	}
	return conn, nil
}

// GetCrioRuntimeClient retrieves crio grpc client
func GetCrioRuntimeClient(hostPrefix string) (pb.RuntimeServiceClient, *grpc.ClientConn, error) {
	// Set up a connection to the server.
	conn, err := getRuntimeClientConnection(hostPrefix)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect: %v", err)
	}
	runtimeClient := pb.NewRuntimeServiceClient(conn)
	return runtimeClient, conn, nil
}

// CloseCrioConnection closes grpc connection in client
func CloseCrioConnection(conn *grpc.ClientConn) error {
	if conn == nil {
		return nil
	}
	return conn.Close()
}
