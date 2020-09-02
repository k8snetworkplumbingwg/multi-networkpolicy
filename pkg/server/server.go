package server

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containernetworking/plugins/pkg/ns"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	multiclient "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/clientset/versioned"
	multiinformer "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/informers/externalversions"
	multilisterv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/listers/k8s.cni.cncf.io/v1beta1"
	"github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/controllers"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdefclient "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned"
	netdefinformerv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/informers/externalversions"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	v1core "k8s.io/client-go/kubernetes/typed/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"
	api "k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/util/async"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	utilnode "k8s.io/kubernetes/pkg/util/node"
	"k8s.io/utils/exec"
)

// Server structure defines data for server
type Server struct {
	podChanges          *controllers.PodChangeTracker
	policyChanges       *controllers.PolicyChangeTracker
	netdefChanges       *controllers.NetDefChangeTracker
	nsChanges           *controllers.NamespaceChangeTracker
	mu                  sync.Mutex // protects the following fields
	podMap              controllers.PodMap
	policyMap           controllers.PolicyMap
	namespaceMap        controllers.NamespaceMap
	Client              clientset.Interface
	Hostname            string
	hostPrefix          string
	NetworkPolicyClient multiclient.Interface
	NetDefClient        netdefclient.Interface
	Broadcaster         record.EventBroadcaster
	Recorder            record.EventRecorder
	Options             *Options
	ConfigSyncPeriod    time.Duration
	NodeRef             *v1.ObjectReference
	ip4Tables           utiliptables.Interface
	ip6Tables           utiliptables.Interface

	initialized int32

	podSynced    bool
	policySynced bool
	netdefSynced bool
	nsSynced     bool

	podLister    corelisters.PodLister
	policyLister multilisterv1beta1.MultiNetworkPolicyLister

	syncRunner *async.BoundedFrequencyRunner
}

// RunPodConfig ...
func (s *Server) RunPodConfig() {
	klog.Infof("Starting pod config")
	informerFactory := informers.NewSharedInformerFactoryWithOptions(s.Client, s.ConfigSyncPeriod)
	s.podLister = informerFactory.Core().V1().Pods().Lister()

	podConfig := controllers.NewPodConfig(informerFactory.Core().V1().Pods(), s.ConfigSyncPeriod)
	podConfig.RegisterEventHandler(s)
	go podConfig.Run(wait.NeverStop)
	informerFactory.Start(wait.NeverStop)
	s.SyncLoop()
}

// Run ...
func (s *Server) Run(hostname string) error {
	if s.Broadcaster != nil {
		s.Broadcaster.StartRecordingToSink(
			&v1core.EventSinkImpl{Interface: s.Client.CoreV1().Events("")})
	}

	informerFactory := informers.NewSharedInformerFactoryWithOptions(s.Client, s.ConfigSyncPeriod)
	nsConfig := controllers.NewNamespaceConfig(informerFactory.Core().V1().Namespaces(), s.ConfigSyncPeriod)
	nsConfig.RegisterEventHandler(s)
	go nsConfig.Run(wait.NeverStop)
	informerFactory.Start(wait.NeverStop)

	policyInformerFactory := multiinformer.NewSharedInformerFactoryWithOptions(
		s.NetworkPolicyClient, s.ConfigSyncPeriod)
	s.policyLister = policyInformerFactory.K8sCniCncfIo().V1beta1().MultiNetworkPolicies().Lister()

	policyConfig := controllers.NewNetworkPolicyConfig(
		policyInformerFactory.K8sCniCncfIo().V1beta1().MultiNetworkPolicies(), s.ConfigSyncPeriod)
	policyConfig.RegisterEventHandler(s)
	go policyConfig.Run(wait.NeverStop)
	policyInformerFactory.Start(wait.NeverStop)

	netdefInformarFactory := netdefinformerv1.NewSharedInformerFactoryWithOptions(
		s.NetDefClient, s.ConfigSyncPeriod)
	netdefConfig := controllers.NewNetDefConfig(
		netdefInformarFactory.K8sCniCncfIo().V1().NetworkAttachmentDefinitions(), s.ConfigSyncPeriod)
	netdefConfig.RegisterEventHandler(s)
	go netdefConfig.Run(wait.NeverStop)
	netdefInformarFactory.Start(wait.NeverStop)

	s.birthCry()

	return nil
}

func (s *Server) setInitialized(value bool) {
	var initialized int32
	if value {
		initialized = 1
	}
	atomic.StoreInt32(&s.initialized, initialized)
}

func (s *Server) isInitialized() bool {
	return atomic.LoadInt32(&s.initialized) > 0
}

func (s *Server) birthCry() {
	klog.Infof("Starting network-policy-node")
	s.Recorder.Eventf(s.NodeRef, api.EventTypeNormal, "Starting", "Starting network-policy-node.")
}

// SyncLoop ...
func (s *Server) SyncLoop() {
	s.syncRunner.Loop(wait.NeverStop)
}

// NewServer ...
func NewServer(o *Options) (*Server, error) {
	var kubeConfig *rest.Config
	var err error
	if len(o.Kubeconfig) == 0 {
		klog.Info("Neither kubeconfig file nor master URL was specified. Falling back to in-cluster config.")
		kubeConfig, err = rest.InClusterConfig()
	} else {
		kubeConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{ExplicitPath: o.Kubeconfig},
			&clientcmd.ConfigOverrides{ClusterInfo: clientcmdapi.Cluster{Server: o.master}},
		).ClientConfig()
	}
	if err != nil {
		return nil, err
	}

	client, err := clientset.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	networkPolicyClient, err := multiclient.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	netdefClient, err := netdefclient.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}

	hostname, err := utilnode.GetHostname(o.hostnameOverride)
	if err != nil {
		return nil, err
	}

	eventBroadcaster := record.NewBroadcaster()
	recorder := eventBroadcaster.NewRecorder(
		scheme.Scheme,
		v1.EventSource{Component: "multi-networkpolicy-node", Host: hostname})

	nodeRef := &v1.ObjectReference{
		Kind:      "Node",
		Name:      hostname,
		UID:       types.UID(hostname),
		Namespace: "",
	}

	syncPeriod := 30 * time.Second
	minSyncPeriod := 0 * time.Second
	burstSyncs := 2

	policyChanges := controllers.NewPolicyChangeTracker()
	if policyChanges == nil {
		return nil, fmt.Errorf("cannot create policy change tracker")
	}
	netdefChanges := controllers.NewNetDefChangeTracker()
	if netdefChanges == nil {
		return nil, fmt.Errorf("cannot create net-attach-def change tracker")
	}
	nsChanges := controllers.NewNamespaceChangeTracker()
	if nsChanges == nil {
		return nil, fmt.Errorf("cannot create namespace change tracker")
	}
	podChanges := controllers.NewPodChangeTracker(o.containerRuntime, hostname, o.hostPrefix, o.networkPlugins, netdefChanges)
	if podChanges == nil {
		return nil, fmt.Errorf("cannot create pod change tracker")
	}

	server := &Server{
		Options:             o,
		Client:              client,
		Hostname:            hostname,
		hostPrefix:          o.hostPrefix,
		NetworkPolicyClient: networkPolicyClient,
		NetDefClient:        netdefClient,
		Broadcaster:         eventBroadcaster,
		Recorder:            recorder,
		ConfigSyncPeriod:    15 * time.Minute,
		NodeRef:             nodeRef,
		ip4Tables:           utiliptables.New(exec.New(), utiliptables.ProtocolIpv4),
		ip6Tables:           utiliptables.New(exec.New(), utiliptables.ProtocolIpv6),

		policyChanges: policyChanges,
		podChanges:    podChanges,
		netdefChanges: netdefChanges,
		nsChanges:     nsChanges,
		podMap:        make(controllers.PodMap),
		policyMap:     make(controllers.PolicyMap),
		namespaceMap:  make(controllers.NamespaceMap),
	}
	server.syncRunner = async.NewBoundedFrequencyRunner(
		"sync-runner", server.syncMultiPolicy, minSyncPeriod, syncPeriod, burstSyncs)

	// XXX: Need to monitor?
	//server.ipt4Interface.Monitor(utiliptables.Chain("MULTI-NETWORK-POLICY")
	return server, nil
}

// Sync ...
func (s *Server) Sync() {
	klog.V(4).Infof("Sync Done!")
	s.syncRunner.Run()
}

// AllSynced ...
func (s *Server) AllSynced() bool {
	return (s.policySynced == true && s.netdefSynced == true && s.nsSynced == true)
}

// OnPodAdd ...
func (s *Server) OnPodAdd(pod *v1.Pod) {
	klog.V(4).Infof("OnPodUpdate")
	s.OnPodUpdate(nil, pod)
}

// OnPodUpdate ...
func (s *Server) OnPodUpdate(oldPod, pod *v1.Pod) {
	klog.V(4).Infof("OnPodUpdate")
	if s.podChanges.Update(oldPod, pod) && s.podSynced {
		s.Sync()
	}
}

// OnPodDelete ...
func (s *Server) OnPodDelete(pod *v1.Pod) {
	klog.V(4).Infof("OnPodDelete")
	s.OnPodUpdate(pod, nil)
}

// OnPodSynced ...
func (s *Server) OnPodSynced() {
	klog.Infof("OnPodSynced")
	s.mu.Lock()
	s.podSynced = true
	s.setInitialized(s.podSynced)
	s.mu.Unlock()

	s.syncMultiPolicy()
}

// OnPolicyAdd ...
func (s *Server) OnPolicyAdd(policy *multiv1beta1.MultiNetworkPolicy) {
	klog.V(4).Infof("OnPolicyAdd")
	s.OnPolicyUpdate(nil, policy)
}

// OnPolicyUpdate ...
func (s *Server) OnPolicyUpdate(oldPolicy, policy *multiv1beta1.MultiNetworkPolicy) {
	klog.V(4).Infof("OnPolicyUpdate")
	if s.policyChanges.Update(oldPolicy, policy) && s.isInitialized() {
		s.Sync()
	}
}

// OnPolicyDelete ...
func (s *Server) OnPolicyDelete(policy *multiv1beta1.MultiNetworkPolicy) {
	klog.V(4).Infof("OnPolicyDelete")
	s.OnPolicyUpdate(policy, nil)
}

// OnPolicySynced ...
func (s *Server) OnPolicySynced() {
	klog.Infof("OnPolicySynced")
	s.mu.Lock()
	s.policySynced = true
	s.setInitialized(s.policySynced)
	s.mu.Unlock()

	if s.AllSynced() {
		s.RunPodConfig()
	}
}

// OnNetDefAdd ...
func (s *Server) OnNetDefAdd(net *netdefv1.NetworkAttachmentDefinition) {
	klog.V(4).Infof("OnNetDefAdd")
	s.OnNetDefUpdate(nil, net)
}

// OnNetDefUpdate ...
func (s *Server) OnNetDefUpdate(oldNet, net *netdefv1.NetworkAttachmentDefinition) {
	klog.V(4).Infof("OnNetDefUpdate")
	if s.netdefChanges.Update(oldNet, net) && s.isInitialized() {
		s.Sync()
	}
}

// OnNetDefDelete ...
func (s *Server) OnNetDefDelete(net *netdefv1.NetworkAttachmentDefinition) {
	klog.V(4).Infof("OnNetDefDelete")
	s.OnNetDefUpdate(net, nil)
}

// OnNetDefSynced ...
func (s *Server) OnNetDefSynced() {
	klog.Infof("OnNetDefSynced")
	s.mu.Lock()
	s.netdefSynced = true
	s.setInitialized(s.netdefSynced)
	s.mu.Unlock()

	if s.AllSynced() {
		s.RunPodConfig()
	}
}

// OnNamespaceAdd ...
func (s *Server) OnNamespaceAdd(ns *v1.Namespace) {
	klog.V(4).Infof("OnNamespaceAdd")
	s.OnNamespaceUpdate(nil, ns)
}

// OnNamespaceUpdate ...
func (s *Server) OnNamespaceUpdate(oldNamespace, ns *v1.Namespace) {
	klog.V(4).Infof("OnNamespaceUpdate")
	if s.nsChanges.Update(oldNamespace, ns) && s.isInitialized() {
		s.Sync()
	}
}

// OnNamespaceDelete ...
func (s *Server) OnNamespaceDelete(ns *v1.Namespace) {
	klog.V(4).Infof("OnNamespaceDelete")
	s.OnNamespaceUpdate(ns, nil)
}

// OnNamespaceSynced ...
func (s *Server) OnNamespaceSynced() {
	klog.Infof("OnNamespaceSynced")
	s.mu.Lock()
	s.nsSynced = true
	s.setInitialized(s.nsSynced)
	s.mu.Unlock()

	if s.AllSynced() {
		s.RunPodConfig()
	}
}

func (s *Server) syncMultiPolicy() {
	klog.V(4).Infof("syncMultiPolicy")
	s.podMap.Update(s.podChanges)
	s.policyMap.Update(s.policyChanges)

	pods, err := s.podLister.Pods(metav1.NamespaceAll).List(labels.Everything())
	if err != nil {
		klog.Errorf("failed to get pods")
	}
	for _, p := range pods {
		klog.V(8).Infof("SYNC %s/%s", p.Namespace, p.Name)
		if p.Spec.NodeName == s.Hostname {
			namespacedName := types.NamespacedName{Namespace: p.Namespace, Name: p.Name}
			if podInfo, ok := s.podMap[namespacedName]; ok {
				if len(podInfo.Interfaces) == 0 {
					klog.V(8).Infof("skipped due to no interfaces")
					continue
				}
				netnsPath := podInfo.NetNSPath
				if s.hostPrefix != "" {
					netnsPath = fmt.Sprintf("%s/%s", s.hostPrefix, netnsPath)
				}

				netns, err := ns.GetNS(netnsPath)
				if err != nil {
					klog.Errorf("cannot get netns: %v", err)
					continue
				}

				klog.V(8).Infof("pod: %s/%s %s", p.Namespace, p.Name, netnsPath)
				_ = netns.Do(func(_ ns.NetNS) error {
					return s.generatePolicyRules(p, podInfo.Interfaces)
				})
			}
		}
	}
}

const (
	ingressChain = "MULTI-INGRESS"
	egressChain  = "MULTI-EGRESS"
)

func (s *Server) generatePolicyRules(pod *v1.Pod, multiIntf []controllers.InterfaceInfo) error {
	klog.V(8).Infof("Generate rules for Pod :%v/%v\n", pod.Namespace, pod.Name)
	// -t filter -N MULTI-POLICY-INGRESS # ensure chain
	s.ip4Tables.EnsureChain(utiliptables.TableFilter, ingressChain)
	// -t filter -N MULTI-POLICY-EGRESS # ensure chain
	s.ip4Tables.EnsureChain(utiliptables.TableFilter, egressChain)

	for _, multiIF := range multiIntf {
		//    -A INPUT -j MULTI-POLICY-INGRESS # ensure rules
		s.ip4Tables.EnsureRule(
			utiliptables.Prepend, utiliptables.TableFilter, "INPUT", "-i", multiIF.InterfaceName, "-j", ingressChain)
		//    -A OUTPUT -j MULTI-POLICY-EGRESS # ensure rules
		s.ip4Tables.EnsureRule(
			utiliptables.Prepend, utiliptables.TableFilter, "OUTPUT", "-o", multiIF.InterfaceName, "-j", egressChain)
		//    -A PREROUTING -i net1 -j RETURN # ensure rules
		s.ip4Tables.EnsureRule(
			utiliptables.Prepend, utiliptables.TableNAT, "PREROUTING", "-i", multiIF.InterfaceName, "-j", "RETURN")
	}

	iptableBuffer := newIptableBuffer()
	iptableBuffer.Init(s.ip4Tables)
	for _, p := range s.policyMap {
		policy := p.Policy
		if policy.Spec.PodSelector.Size() != 0 {
			policyMap, err := metav1.LabelSelectorAsMap(&policy.Spec.PodSelector)
			if err != nil {
				klog.Errorf("label selector: %v", err)
				continue
			}
			policyPodSelector := labels.Set(policyMap).AsSelectorPreValidated()
			if !policyPodSelector.Matches(labels.Set(pod.Labels)) {
				continue
			}
		}

		var ingressEnable, egressEnable bool
		if len(policy.Spec.PolicyTypes) == 0 {
			ingressEnable = true
			egressEnable = true
		} else {
			for _, v := range policy.Spec.PolicyTypes {
				if strings.EqualFold(string(v), string(multiv1beta1.PolicyTypeIngress)) {
					ingressEnable = true
				} else if strings.EqualFold(string(v), string(multiv1beta1.PolicyTypeEgress)) {
					egressEnable = true
				}
			}
		}
		klog.V(8).Infof("ingress/egress = %v/%v\n", ingressEnable, egressEnable)

		iptableBuffer.Reset()

		policyNetworksAnnot, ok := policy.GetAnnotations()[PolicyNetworkAnnotation]
		if !ok {
			continue
		}
		policyNetworksAnnot = strings.ReplaceAll(policyNetworksAnnot, " ", "")
		policyNetworks := strings.Split(policyNetworksAnnot, ",")
		for idx, networkName := range policyNetworks {
			// fill namespace
			if strings.IndexAny(networkName, "/") == -1 {
				policyNetworks[idx] = fmt.Sprintf("%s/%s", policy.GetNamespace(), networkName)
			}
		}

		if ingressEnable {
			iptableBuffer.renderIngress(s, pod, policy.Spec.Ingress, policyNetworks)
		}
		if egressEnable {
			iptableBuffer.renderEgress(s, pod, policy.Spec.Egress, policyNetworks)
		}
	}

	if !iptableBuffer.IsUsed() {
		iptableBuffer.Init(s.ip4Tables)
	}

	iptableBuffer.FinalizeRules()
	if err := iptableBuffer.SyncRules(s.ip4Tables); err != nil {
		klog.Errorf("sync rules failed: %v", err)
		return err
	}

	return nil
}
