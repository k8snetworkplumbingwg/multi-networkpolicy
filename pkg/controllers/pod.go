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
	"strings"
	"sync"
	"time"

	docker "github.com/docker/docker/client"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefutils "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/utils"

	"google.golang.org/grpc"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/tools/cache"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	"k8s.io/klog"
	k8sutils "k8s.io/kubernetes/pkg/kubelet/util"
)

// RuntimeKind is enum type variable for container runtime
type RuntimeKind int

const (
	Crio = iota
	Docker
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
	listerSynced  cache.InformerSynced
	eventHandlers []PodHandler
}

// NewPodConfig creates a new PodConfig.
func NewPodConfig(podInformer coreinformers.PodInformer, resyncPeriod time.Duration) *PodConfig {
	result := &PodConfig{
		listerSynced: podInformer.Informer().HasSynced,
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

	if !cache.WaitForNamedCacheSync("pod config", stopCh, c.listerSynced) {
		return
	}

	for i := range c.eventHandlers {
		klog.V(9).Infof("Calling handler.OnPodSynced()")
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
		klog.V(9).Infof("Calling handler.OnPodAdd")
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
		klog.V(9).Infof("Calling handler.OnPodUpdate")
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
		klog.V(9).Infof("Calling handler.OnPodDelete")
		c.eventHandlers[i].OnPodDelete(pod)
	}
}

// InterfaceInfo ...
type InterfaceInfo struct {
	NetattachName string
	InterfaceName string
	InterfaceType string
	IPs           []string
}

func (info *InterfaceInfo) CheckPolicyNetwork(policyNetworks []string) bool {
	isExists := false
	for _, policyNetworkName := range policyNetworks {
		if policyNetworkName == info.NetattachName {
			isExists = true
		}
	}
	return isExists
}

// PodInfo contains information that defines a pod.
type PodInfo struct {
	Name          string
	Namespace     string
	NetNSPath     string
	NetworkStatus []netdefv1.NetworkStatus
	NodeName      string
	Interfaces    []InterfaceInfo
}

// GetMultusNetIFs ...
func (info *PodInfo) GetMultusNetIFs() []string {
	results := []string{}

	if info != nil && len(info.NetworkStatus) > 0 {
		for _, status := range info.NetworkStatus[1:] {
			results = append(results, status.Interface)
		}
	}
	return results
}

// String ...
func (info *PodInfo) String() string {
	return fmt.Sprintf("pod:%s", info.Name)
}

type podChange struct {
	previous PodMap
	current  PodMap
}

// PodChangeTracker carries state about uncommitted changes to an arbitrary number of
// Pods in the node, keyed by their namespace and name
type PodChangeTracker struct {
	// lock protects items.
	lock           sync.Mutex
	hostname       string
	networkPlugins []string
	netdefChanges  *NetDefChangeTracker
	// items maps a service to its podChange.
	items map[types.NamespacedName]*podChange

	// for cri-o
	crioClient pb.RuntimeServiceClient
	crioConn   *grpc.ClientConn

	// for docker
	dockerClient *docker.Client
}

// String
func (pct *PodChangeTracker) String() string {
	return fmt.Sprintf("podChange: %v", pct.items)
}

func (pct *PodChangeTracker) getPodNetNSPath(pod *v1.Pod) (string, error) {
	netnsPath := ""

	// get Container netns
	procPrefix := ""
	if len(pod.Status.ContainerStatuses) == 0 {
		return "", fmt.Errorf("No container status")
	}

	runtimeKind := strings.Split(pod.Status.ContainerStatuses[0].ContainerID, ":")
	if runtimeKind[0] == "docker" {
		if pct.dockerClient == nil {
			return "", fmt.Errorf("cannot find docker client")
		}
		containerID := strings.TrimPrefix(pod.Status.ContainerStatuses[0].ContainerID, "docker://")
		if len(containerID) > 0 {
			json, err := pct.dockerClient.ContainerInspect(context.TODO(), containerID)
			if err != nil {
				return "", fmt.Errorf("failed to get container info: %v", err)
			}
			if json.NetworkSettings == nil {
				return "", fmt.Errorf("failed to get container info: %v", err)
			}
			netnsPath = fmt.Sprintf("%s/proc/%d/ns/net", procPrefix, json.State.Pid)
		}
	} else if runtimeKind[0] == "cri-o" { // crio
		if pct.crioConn == nil {
			return "", fmt.Errorf("cannot find docker client")
		}
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
			netnsPath = fmt.Sprintf("%s/proc/%d/ns/net", procPrefix, int(pid))
		}
	} else {
		if pct.dockerClient == nil && pct.crioConn == nil {
			return "", nil
		}
		return "", fmt.Errorf("unknown container id: %s", pod.Status.ContainerStatuses[0].ContainerID)
	}
	return netnsPath, nil
}

func (pct *PodChangeTracker) newPodInfo(pod *v1.Pod) (*PodInfo, error) {
	networks, err := netdefutils.ParsePodNetworkAnnotation(pod)
	if err != nil {
		if _, ok := err.(*netdefv1.NoK8sNetworkError); !ok {
			klog.Errorf("failed to get pod network annotation: %v", err)
		}
	}
	// parse networkStatus
	statuses, _ := netdefutils.GetNetworkStatus(pod)

	// get container network namespace
	netnsPath := ""
	if pct.hostname == pod.Spec.NodeName {
		netnsPath, err = pct.getPodNetNSPath(pod)
		if err != nil {
			return nil, fmt.Errorf("failed to get pod network namespace: %v", err)
		}
	}

	// netdefname -> plugin name map
	networkPlugins := make(map[types.NamespacedName]string)
	if networks == nil {
		klog.V(8).Infof("%s/%s: NO NET", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name)
	} else {
		klog.V(8).Infof("%s/%s: net: %v", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, networks)
	}
	for _, n := range networks {
		namespace := pod.ObjectMeta.Namespace
		if n.Namespace != "" {
			namespace = n.Namespace
		}
		namespacedName := types.NamespacedName{Namespace: namespace, Name: n.Name}
		klog.V(8).Infof("networkPlugins[%s], %v", namespacedName, pct.netdefChanges.GetPluginType(namespacedName))
		networkPlugins[namespacedName] = pct.netdefChanges.GetPluginType(namespacedName)
	}
	klog.V(8).Infof("netdef->pluginMap: %v", networkPlugins)

	// match it with
	var netifs []InterfaceInfo
	for _, s := range statuses {
		var netNamespace, netName string
		slashItems := strings.Split(s.Name, "/")
		if len(slashItems) == 2 {
			netNamespace = strings.TrimSpace(slashItems[0])
			netName = slashItems[1]
		} else {
			netNamespace = pod.ObjectMeta.Namespace
			netName = s.Name
		}
		namespacedName := types.NamespacedName{Namespace: netNamespace, Name: netName}

		for _, pluginName := range pct.networkPlugins {
			if networkPlugins[namespacedName] == pluginName {
				netifs = append(netifs, InterfaceInfo{
					NetattachName: s.Name,
					InterfaceName: s.Interface,
					InterfaceType: networkPlugins[namespacedName],
					IPs:           s.IPs,
				})
			}
		}
	}

	klog.V(6).Infof("Pod: %s/%s netns:%s netIF:%v", pod.ObjectMeta.Namespace, pod.ObjectMeta.Name, netnsPath, netifs)
	info := &PodInfo{
		Name:          pod.ObjectMeta.Name,
		Namespace:     pod.ObjectMeta.Namespace,
		NetworkStatus: statuses,
		NetNSPath:     netnsPath,
		NodeName:      pod.Spec.NodeName,
		Interfaces:    netifs,
	}
	return info, nil
}

// NewPodChangeTracker ...
func NewPodChangeTracker(runtime RuntimeKind, hostname, hostPrefix string, networkPlugins []string, ndt *NetDefChangeTracker) *PodChangeTracker {
	switch runtime {
	case Crio:
		return NewPodChangeTrackerCrio(hostname, hostPrefix, networkPlugins, ndt)
	case Docker:
		return NewPodChangeTrackerDocker(hostname, hostPrefix, networkPlugins, ndt)
	default:
		klog.Errorf("unknown container runtime: %v", runtime)
		return nil
	}
}

func NewPodChangeTrackerCrio(hostname, hostPrefix string, networkPlugins []string, ndt *NetDefChangeTracker) *PodChangeTracker {
	crioClient, crioConn, err := GetCrioRuntimeClient(hostPrefix)
	if err != nil {
		klog.Errorf("failed to get crio client: %v", err)
		return nil
	}

	return &PodChangeTracker{
		items:          make(map[types.NamespacedName]*podChange),
		hostname:       hostname,
		networkPlugins: networkPlugins,
		netdefChanges:  ndt,
		crioClient:     crioClient,
		crioConn:       crioConn,
	}
}

func NewPodChangeTrackerDocker(hostname, hostPrefix string, networkPlugins []string, ndt *NetDefChangeTracker) *PodChangeTracker {
	cli, err := docker.NewEnvClient()

	if err != nil {
		panic(err)
	}
	cli.NegotiateAPIVersion(context.TODO())

	return &PodChangeTracker{
		items:          make(map[types.NamespacedName]*podChange),
		hostname:       hostname,
		networkPlugins: networkPlugins,
		netdefChanges:  ndt,
		dockerClient:   cli,
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
	return len(pct.items) >= 0
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
/*
func (pm *PodMap) String() string {
	if pm == nil {
		return ""
	}
	str := ""
	for _, v := range *pm {
		str = fmt.Sprintf("%s\n\tpod: %s", str, v.Name)
	}
	return str
}
*/

// =====================================
// misc functions...
// =====================================
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
