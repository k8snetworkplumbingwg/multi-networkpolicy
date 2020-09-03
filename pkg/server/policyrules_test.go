package server

import (
	"bytes"
	"fmt"
	"time"

	multiv1beta1 "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/apis/k8s.cni.cncf.io/v1beta1"
	multifake "github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/client/clientset/versioned/fake"
	"github.com/k8snetworkplumbingwg/multi-networkpolicy/pkg/controllers"
	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netfake "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	fakeiptables "k8s.io/kubernetes/pkg/util/iptables/testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var informerFactory informers.SharedInformerFactory

// NewFakeServer creates fake server object for unit-test
func NewFakeServer(hostname string) *Server {
	fakeClient := k8sfake.NewSimpleClientset()
	netClient := netfake.NewSimpleClientset()
	policyClient := multifake.NewSimpleClientset()

	policyChanges := controllers.NewPolicyChangeTracker()
	if policyChanges == nil {
		return nil
	}
	netdefChanges := controllers.NewNetDefChangeTracker()
	if netdefChanges == nil {
		return nil
	}
	nsChanges := controllers.NewNamespaceChangeTracker()
	if nsChanges == nil {
		return nil
	}
	hostPrefix := "/host"
	networkPlugins := []string{"multi"}
	containerRuntime := controllers.RuntimeKind(controllers.Docker)
	podChanges := controllers.NewPodChangeTracker(containerRuntime, hostname, hostPrefix, networkPlugins, netdefChanges)
	if podChanges == nil {
		return nil
	}
	informerFactory = informers.NewSharedInformerFactoryWithOptions(fakeClient, 15*time.Minute)
	podConfig := controllers.NewPodConfig(informerFactory.Core().V1().Pods(), 15*time.Minute)

	nodeRef := &v1.ObjectReference{
		Kind:      "Node",
		Name:      hostname,
		UID:       types.UID(hostname),
		Namespace: "",
	}

	server := &Server{
		Client:              fakeClient,
		Hostname:            hostname,
		NetworkPolicyClient: policyClient,
		NetDefClient:        netClient,
		ConfigSyncPeriod:    15 * time.Minute,
		NodeRef:             nodeRef,
		ip4Tables:           fakeiptables.NewFake(),
		//ip6Tables: fakeiptables.NewIPv6Fake(),

		hostPrefix:    hostPrefix,
		policyChanges: policyChanges,
		podChanges:    podChanges,
		netdefChanges: netdefChanges,
		nsChanges:     nsChanges,
		podMap:        make(controllers.PodMap),
		policyMap:     make(controllers.PolicyMap),
		namespaceMap:  make(controllers.NamespaceMap),
		podLister:     informerFactory.Core().V1().Pods().Lister(),
	}
	podConfig.RegisterEventHandler(server)
	go podConfig.Run(wait.NeverStop)
	informerFactory.Start(wait.NeverStop)
	return server
}

func NewFakePodWithNetAnnotation(namespace, name, annot, status string, labels map[string]string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       "testUID",
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/networks": annot,
				netdefv1.NetworkStatusAnnot:   status,
			},
			Labels: labels,
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Name: "ctr1", Image: "image"},
			},
		},
	}
}

func AddNamespace(s *Server, name string) {
	namespace := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			//Labels: labels,
		},
	}
	Expect(s.nsChanges.Update(nil, namespace)).To(BeTrue())
	s.namespaceMap.Update(s.nsChanges)
}

func AddPod(s *Server, pod *v1.Pod) {
	Expect(s.podChanges.Update(nil, pod)).To(BeTrue())
	s.podMap.Update(s.podChanges)
	informerFactory.Core().V1().Pods().Informer().GetIndexer().Add(pod)
}

func NewFakeNetworkStatus(netns, netname, eth0, net1 string) string {
	// dummy interface is for testing not to include dummy ip in iptable rules
	baseStr := `
	[{
            "name": "",
            "interface": "eth0",
            "ips": [
                "%s"
            ],
            "mac": "aa:e1:20:71:15:01",
            "default": true,
            "dns": {}
        },{
            "name": "%s/%s",
            "interface": "net1",
            "ips": [
                "%s"
            ],
            "mac": "42:90:65:12:3e:bf",
            "dns": {}
        },{
            "name": "dummy-interface",
            "interface": "net2",
            "ips": [
                "244.244.244.244"
            ],
            "mac": "42:90:65:12:3e:bf",
            "dns": {}
        }]
`
	return fmt.Sprintf(baseStr, eth0, netns, netname, net1)
}

func NewNetDef(namespace, name, cniConfig string) *netdefv1.NetworkAttachmentDefinition {
	return &netdefv1.NetworkAttachmentDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: netdefv1.NetworkAttachmentDefinitionSpec{
			Config: cniConfig,
		},
	}
}

func NewCNIConfig(cniName, cniType string) string {
	cniConfigTemp := `
	{
		"name": "%s",
		"type": "%s"
	}`
	return fmt.Sprintf(cniConfigTemp, cniName, cniType)
}

func NewCNIConfigList(cniName, cniType string) string {
	cniConfigTemp := `
	{
		"name": "%s",
		"plugins": [ 
			{
				"type": "%s"
			}]
	}`
	return fmt.Sprintf(cniConfigTemp, cniName, cniType)
}

var _ = Describe("policyrules testing", func() {
	It("Initialization", func() {
		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		filterChains := []byte("*filter\n:MULTI-INGRESS - [0:0]\n:MULTI-EGRESS - [0:0]\n")
		Expect(buf.filterChains.Bytes()).To(Equal(filterChains))
		emptyBytes := []byte("")
		Expect(buf.policyIndex.Bytes()).To(Equal(emptyBytes))
		Expect(buf.ingressPorts.Bytes()).To(Equal(emptyBytes))
		Expect(buf.ingressFrom.Bytes()).To(Equal(emptyBytes))
		Expect(buf.egressPorts.Bytes()).To(Equal(emptyBytes))
		Expect(buf.egressTo.Bytes()).To(Equal(emptyBytes))

		// finalize buf and verify rules buffer
		buf.FinalizeRules()
		filterRules := []byte("*filter\n:MULTI-INGRESS - [0:0]\n:MULTI-EGRESS - [0:0]\nCOMMIT\n")
		Expect(buf.filterRules.Bytes()).To(Equal(filterRules))

		// sync and verify iptable
		Expect(buf.SyncRules(ipt)).To(BeNil())
		iptableRules := bytes.NewBuffer(nil)
		ipt.SaveInto(utiliptables.TableFilter, iptableRules)
		Expect(iptableRules.Bytes()).To(Equal(filterRules))

		// reset and verify empty
		buf.Reset()
		Expect(buf.policyIndex.Bytes()).To(Equal(emptyBytes))
		Expect(buf.ingressPorts.Bytes()).To(Equal(emptyBytes))
		Expect(buf.ingressFrom.Bytes()).To(Equal(emptyBytes))
		Expect(buf.egressPorts.Bytes()).To(Equal(emptyBytes))
		Expect(buf.egressTo.Bytes()).To(Equal(emptyBytes))
	})

	It("ingress rules ipblock", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		ingressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								IPBlock: &multiv1beta1.IPBlock{
									CIDR:   "10.1.1.1/24",
									Except: []string{"10.1.1.1"},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).To(BeNil())

		buf.renderIngress(s, podInfo1, 0, ingressPolicies1, []string{"testns1/net-attach1"})

		portRules := []byte("-A MULTI-0-INGRESS-0-PORTS -i net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000\n")
		Expect(buf.ingressPorts.Bytes()).To(Equal(portRules))

		fromRules := []byte("-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1 -j DROP\n-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1/24 -j MARK --set-xmark 0x20000/0x20000\n")
		Expect(buf.ingressFrom.Bytes()).To(Equal(fromRules))

		buf.FinalizeRules()
		finalizedRules := []byte(
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
-A MULTI-INGRESS -m comment --comment "policy:ingressPolicies1 net-attach-def:testns1/net-attach1" -i net1 -j MULTI-0-INGRESS
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS -j DROP
-A MULTI-0-INGRESS-0-PORTS -i net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1 -j DROP
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.1/24 -j MARK --set-xmark 0x20000/0x20000
COMMIT
`)
		Expect(buf.filterRules.Bytes()).To(Equal(finalizedRules))
	})

	It("ingress rules podselector/matchlabels", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		ingressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foobar": "enabled",
									},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		AddNamespace(s, "testns1")

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).To(BeNil())

		pod2 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod2",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.2", "10.1.1.2"),
			map[string]string{
				"foobar": "enabled",
			})
		AddPod(s, pod2)

		buf.renderIngress(s, podInfo1, 0, ingressPolicies1, []string{"testns1/net-attach1"})

		portRules := []byte("-A MULTI-0-INGRESS-0-PORTS -i net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000\n")
		Expect(buf.ingressPorts.Bytes()).To(Equal(portRules))

		fromRules := []byte("-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.2 -j MARK --set-xmark 0x20000/0x20000\n")
		Expect(buf.ingressFrom.Bytes()).To(Equal(fromRules))

		buf.FinalizeRules()
		finalizedRules := []byte(
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
-A MULTI-INGRESS -m comment --comment "policy:ingressPolicies1 net-attach-def:testns1/net-attach1" -i net1 -j MULTI-0-INGRESS
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS -j DROP
-A MULTI-0-INGRESS-0-PORTS -i net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-INGRESS-0-FROM -i net1 -s 10.1.1.2 -j MARK --set-xmark 0x20000/0x20000
COMMIT
`)
		Expect(buf.filterRules.Bytes()).To(Equal(finalizedRules))
	})

	It("egress rules ipblock", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		egressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "EgressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								IPBlock: &multiv1beta1.IPBlock{
									CIDR:   "10.1.1.1/24",
									Except: []string{"10.1.1.1"},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).To(BeNil())

		buf.renderEgress(s, podInfo1, 0, egressPolicies1, []string{"testns1/net-attach1"})

		portRules := []byte("-A MULTI-0-EGRESS-0-PORTS -o net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000\n")
		Expect(buf.egressPorts.Bytes()).To(Equal(portRules))

		toRules := []byte("-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.1 -j DROP\n-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.1/24 -j MARK --set-xmark 0x20000/0x20000\n")
		Expect(buf.egressTo.Bytes()).To(Equal(toRules))

		buf.FinalizeRules()
		finalizedRules := []byte(
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-0-EGRESS - [0:0]
:MULTI-0-EGRESS-0-PORTS - [0:0]
:MULTI-0-EGRESS-0-TO - [0:0]
-A MULTI-EGRESS -m comment --comment "policy:EgressPolicies1 net-attach-def:testns1/net-attach1" -o net1 -j MULTI-0-EGRESS
-A MULTI-0-EGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-PORTS
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-TO
-A MULTI-0-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-EGRESS -j DROP
-A MULTI-0-EGRESS-0-PORTS -o net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.1 -j DROP
-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.1/24 -j MARK --set-xmark 0x20000/0x20000
COMMIT
`)
		Expect(buf.filterRules.Bytes()).To(Equal(finalizedRules))
	})

	It("egress rules podselector/matchlabels", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		egressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "EgressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foobar": "enabled",
									},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		AddNamespace(s, "testns1")

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).To(BeNil())

		pod2 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod2",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.2", "10.1.1.2"),
			map[string]string{
				"foobar": "enabled",
			})
		AddPod(s, pod2)

		buf.renderEgress(s, podInfo1, 0, egressPolicies1, []string{"testns1/net-attach1"})

		portRules := []byte("-A MULTI-0-EGRESS-0-PORTS -o net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000\n")
		Expect(buf.egressPorts.Bytes()).To(Equal(portRules))

		toRules := []byte("-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.2 -j MARK --set-xmark 0x20000/0x20000\n")
		Expect(buf.egressTo.Bytes()).To(Equal(toRules))

		buf.FinalizeRules()
		finalizedRules := []byte(
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-0-EGRESS - [0:0]
:MULTI-0-EGRESS-0-PORTS - [0:0]
:MULTI-0-EGRESS-0-TO - [0:0]
-A MULTI-EGRESS -m comment --comment "policy:EgressPolicies1 net-attach-def:testns1/net-attach1" -o net1 -j MULTI-0-EGRESS
-A MULTI-0-EGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-PORTS
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-TO
-A MULTI-0-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-EGRESS -j DROP
-A MULTI-0-EGRESS-0-PORTS -o net1 -m tcp -p tcp --dport 8888 -j MARK --set-xmark 0x10000/0x10000
-A MULTI-0-EGRESS-0-TO -o net1 -d 10.1.1.2 -j MARK --set-xmark 0x20000/0x20000
COMMIT
`)
		Expect(buf.filterRules.Bytes()).To(Equal(finalizedRules))
	})

})

var _ = Describe("policyrules testing - invalid case", func() {
	It("Initialization", func() {
		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		filterChains := []byte("*filter\n:MULTI-INGRESS - [0:0]\n:MULTI-EGRESS - [0:0]\n")
		Expect(buf.filterChains.Bytes()).To(Equal(filterChains))
		emptyBytes := []byte("")
		Expect(buf.policyIndex.Bytes()).To(Equal(emptyBytes))
		Expect(buf.ingressPorts.Bytes()).To(Equal(emptyBytes))
		Expect(buf.ingressFrom.Bytes()).To(Equal(emptyBytes))
		Expect(buf.egressPorts.Bytes()).To(Equal(emptyBytes))
		Expect(buf.egressTo.Bytes()).To(Equal(emptyBytes))

		// finalize buf and verify rules buffer
		buf.FinalizeRules()
		filterRules := []byte("*filter\n:MULTI-INGRESS - [0:0]\n:MULTI-EGRESS - [0:0]\nCOMMIT\n")
		Expect(buf.filterRules.Bytes()).To(Equal(filterRules))

		// sync and verify iptable
		Expect(buf.SyncRules(ipt)).To(BeNil())
		iptableRules := bytes.NewBuffer(nil)
		ipt.SaveInto(utiliptables.TableFilter, iptableRules)
		Expect(iptableRules.Bytes()).To(Equal(filterRules))

		// reset and verify empty
		buf.Reset()
		Expect(buf.policyIndex.Bytes()).To(Equal(emptyBytes))
		Expect(buf.ingressPorts.Bytes()).To(Equal(emptyBytes))
		Expect(buf.ingressFrom.Bytes()).To(Equal(emptyBytes))
		Expect(buf.egressPorts.Bytes()).To(Equal(emptyBytes))
		Expect(buf.egressTo.Bytes()).To(Equal(emptyBytes))
	})

	It("ingress rules ipblock", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		ingressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								IPBlock: &multiv1beta1.IPBlock{
									CIDR:   "10.1.1.1/24",
									Except: []string{"10.1.1.1"},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).To(BeNil())

		buf.renderIngress(s, podInfo1, 0, ingressPolicies1, []string{})

		buf.FinalizeRules()
		finalizedRules := []byte(
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS -j DROP
COMMIT
`)
		Expect(buf.filterRules.Bytes()).To(Equal(finalizedRules))
	})

	It("ingress rules podselector/matchlabels", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		ingressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "ingressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Ingress: []multiv1beta1.MultiNetworkPolicyIngressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						From: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foobar": "enabled",
									},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		AddNamespace(s, "testns1")

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).To(BeNil())

		pod2 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod2",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.2", "10.1.1.2"),
			map[string]string{
				"foobar": "enabled",
			})
		AddPod(s, pod2)

		buf.renderIngress(s, podInfo1, 0, ingressPolicies1, []string{})

		buf.FinalizeRules()
		finalizedRules := []byte(
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-0-INGRESS - [0:0]
:MULTI-0-INGRESS-0-PORTS - [0:0]
:MULTI-0-INGRESS-0-FROM - [0:0]
-A MULTI-0-INGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-PORTS
-A MULTI-0-INGRESS -j MULTI-0-INGRESS-0-FROM
-A MULTI-0-INGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-INGRESS -j DROP
COMMIT
`)
		Expect(buf.filterRules.Bytes()).To(Equal(finalizedRules))
	})

	It("egress rules ipblock", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		egressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "EgressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								IPBlock: &multiv1beta1.IPBlock{
									CIDR:   "10.1.1.1/24",
									Except: []string{"10.1.1.1"},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).To(BeNil())

		buf.renderEgress(s, podInfo1, 0, egressPolicies1, []string{})

		buf.FinalizeRules()
		finalizedRules := []byte(
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-0-EGRESS - [0:0]
:MULTI-0-EGRESS-0-PORTS - [0:0]
:MULTI-0-EGRESS-0-TO - [0:0]
-A MULTI-0-EGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-PORTS
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-TO
-A MULTI-0-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-EGRESS -j DROP
COMMIT
`)
		Expect(buf.filterRules.Bytes()).To(Equal(finalizedRules))
	})

	It("egress rules podselector/matchlabels", func() {
		port := intstr.FromInt(8888)
		protoTCP := v1.ProtocolTCP
		egressPolicies1 := &multiv1beta1.MultiNetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "EgressPolicies1",
				Namespace: "testns1",
			},
			Spec: multiv1beta1.MultiNetworkPolicySpec{
				Egress: []multiv1beta1.MultiNetworkPolicyEgressRule{
					{
						Ports: []multiv1beta1.MultiNetworkPolicyPort{
							{
								Protocol: &protoTCP,
								Port:     &port,
							},
						},
						To: []multiv1beta1.MultiNetworkPolicyPeer{
							{
								PodSelector: &metav1.LabelSelector{
									MatchLabels: map[string]string{
										"foobar": "enabled",
									},
								},
							},
						},
					},
				},
			},
		}

		ipt := fakeiptables.NewFake()
		Expect(ipt).NotTo(BeNil())
		buf := newIptableBuffer()
		Expect(buf).NotTo(BeNil())

		// verify buf initialized at init
		buf.Init(ipt)
		s := NewFakeServer("samplehost")
		Expect(s).NotTo(BeNil())

		AddNamespace(s, "testns1")

		Expect(s.netdefChanges.Update(
			nil,
			NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "multi")))).To(BeTrue())
		Expect(s.netdefChanges.GetPluginType(types.NamespacedName{Namespace: "testns1", Name: "net-attach1"})).To(Equal("multi"))

		pod1 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod1",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.1", "10.1.1.1"),
			nil)
		AddPod(s, pod1)
		podInfo1, err := s.podMap.GetPodInfo(pod1)
		Expect(err).To(BeNil())

		pod2 := NewFakePodWithNetAnnotation(
			"testns1",
			"testpod2",
			"net-attach1",
			NewFakeNetworkStatus("testns1", "net-attach1", "192.168.1.2", "10.1.1.2"),
			map[string]string{
				"foobar": "enabled",
			})
		AddPod(s, pod2)

		buf.renderEgress(s, podInfo1, 0, egressPolicies1, []string{"testns2/net-attach1"})

		buf.FinalizeRules()
		finalizedRules := []byte(
			`*filter
:MULTI-INGRESS - [0:0]
:MULTI-EGRESS - [0:0]
:MULTI-0-EGRESS - [0:0]
:MULTI-0-EGRESS-0-PORTS - [0:0]
:MULTI-0-EGRESS-0-TO - [0:0]
-A MULTI-0-EGRESS -j MARK --set-xmark 0x0/0x30000
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-PORTS
-A MULTI-0-EGRESS -j MULTI-0-EGRESS-0-TO
-A MULTI-0-EGRESS -m mark --mark 0x30000/0x30000 -j RETURN
-A MULTI-0-EGRESS -j DROP
COMMIT
`)
		Expect(buf.filterRules.Bytes()).To(Equal(finalizedRules))
	})

})
