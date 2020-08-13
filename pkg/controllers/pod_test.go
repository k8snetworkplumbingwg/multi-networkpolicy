package controllers

import (
	"fmt"
	"time"

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"

	"k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type FakePodConfigStub struct {
	CounterAdd    int
	CounterUpdate int
	CounterDelete int
	CounterSynced int
}

func (f *FakePodConfigStub) OnPodAdd(_ *v1.Pod) {
	f.CounterAdd++
}

func (f *FakePodConfigStub) OnPodUpdate(_, _ *v1.Pod) {
	f.CounterUpdate++
}

func (f *FakePodConfigStub) OnPodDelete(_ *v1.Pod) {
	f.CounterDelete++
}

func (f *FakePodConfigStub) OnPodSynced() {
	f.CounterSynced++
}

func NewFakePodConfig(stub *FakePodConfigStub) *PodConfig {
	configSync := 15 * time.Minute
	fakeClient := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactoryWithOptions(fakeClient, configSync)
	podConfig := NewPodConfig(informerFactory.Core().V1().Pods(), configSync)
	podConfig.RegisterEventHandler(stub)
	return podConfig
}

func NewFakePodWithNetAnnotation(namespace, name, annot, status string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       "testUID",
			Annotations: map[string]string{
				"k8s.v1.cni.cncf.io/networks": annot,
				netdefv1.NetworkStatusAnnot:   status,
			},
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Name: "ctr1", Image: "image"},
			},
		},
	}
}

func NewFakeNetworkStatus(netns, netname string) string {
	baseStr := `
	[{
            "name": "",
            "interface": "eth0",
            "ips": [
                "10.244.1.4"
            ],
            "mac": "aa:e1:20:71:15:01",
            "default": true,
            "dns": {}
        },{
            "name": "%s/%s",
            "interface": "net1",
            "ips": [
                "10.1.1.101"
            ],
            "mac": "42:90:65:12:3e:bf",
            "dns": {}
        }]
`
	return fmt.Sprintf(baseStr, netns, netname)
}

func NewFakePod(namespace, name string) *v1.Pod {
	return &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			UID:       "testUID",
		},
		Spec: v1.PodSpec{
			Containers: []v1.Container{
				{Name: "ctr1", Image: "image"},
			},
		},
	}
}

func NewFakePodChangeTracker(hostname, hostPrefix string, ndt *NetDefChangeTracker) *PodChangeTracker {
	return &PodChangeTracker{
		items:          make(map[types.NamespacedName]*podChange),
		hostname:       hostname,
		netdefChanges:  ndt,
		networkPlugins: []string{"macvlan"},
	}
}

var _ = Describe("pod config", func() {
	It("check add handler", func() {
		stub := &FakePodConfigStub{}
		nsConfig := NewFakePodConfig(stub)
		nsConfig.handleAddPod(NewFakePod("testns1", "pod"))
		Expect(stub.CounterAdd).To(Equal(1))
		Expect(stub.CounterUpdate).To(Equal(0))
		Expect(stub.CounterDelete).To(Equal(0))
		Expect(stub.CounterSynced).To(Equal(0))
	})

	It("check update handler", func() {
		stub := &FakePodConfigStub{}
		nsConfig := NewFakePodConfig(stub)
		nsConfig.handleUpdatePod(NewFakePod("testns1", "pod"), NewFakePod("testns2", "pod"))
		Expect(stub.CounterAdd).To(Equal(0))
		Expect(stub.CounterUpdate).To(Equal(1))
		Expect(stub.CounterDelete).To(Equal(0))
		Expect(stub.CounterSynced).To(Equal(0))
	})

	It("check update handler", func() {
		stub := &FakePodConfigStub{}
		nsConfig := NewFakePodConfig(stub)
		nsConfig.handleDeletePod(NewFakePod("testns1", "pod"))
		Expect(stub.CounterAdd).To(Equal(0))
		Expect(stub.CounterUpdate).To(Equal(0))
		Expect(stub.CounterDelete).To(Equal(1))
		Expect(stub.CounterSynced).To(Equal(0))
	})
})

var _ = Describe("pod controller", func() {
	It("Initialize and verify empty", func() {
		ndChanges := NewNetDefChangeTracker()
		podChanges := NewFakePodChangeTracker("nodeName", "hostPrefix", ndChanges)
		podMap := make(PodMap)
		podMap.Update(podChanges)
		Expect(len(podMap)).To(Equal(0))
	})

	It("Add pod and verify", func() {
		ndChanges := NewNetDefChangeTracker()
		podChanges := NewFakePodChangeTracker("nodeName", "hostPrefix", ndChanges)

		Expect(podChanges.Update(nil, NewFakePod("testns1", "testpod1"))).To(BeTrue())

		podMap := make(PodMap)
		podMap.Update(podChanges)
		Expect(len(podMap)).To(Equal(1))

		pod1, ok := podMap[types.NamespacedName{Namespace: "testns1", Name: "testpod1"}]
		Expect(ok).To(BeTrue())
		Expect(pod1.Name).To(Equal("testpod1"))
		Expect(pod1.Namespace).To(Equal("testns1"))
	})

	It("Add ns then del ns and verify", func() {
		ndChanges := NewNetDefChangeTracker()
		podChanges := NewFakePodChangeTracker("nodeName", "hostPrefix", ndChanges)

		Expect(podChanges.Update(nil, NewFakePod("testns1", "testpod1"))).To(BeTrue())
		Expect(podChanges.Update(NewFakePod("testns1", "testpod1"), nil)).To(BeTrue())
		Expect(podChanges.Update(nil, NewFakePod("testns2", "testpod2"))).To(BeTrue())

		podMap := make(PodMap)
		podMap.Update(podChanges)
		Expect(len(podMap)).To(Equal(1))

		pod1, ok := podMap[types.NamespacedName{Namespace: "testns2", Name: "testpod2"}]
		Expect(ok).To(BeTrue())
		Expect(pod1.Name).To(Equal("testpod2"))
		Expect(pod1.Namespace).To(Equal("testns2"))
	})

	It("invalid Update case", func() {
		ndChanges := NewNetDefChangeTracker()
		podChanges := NewFakePodChangeTracker("nodeName", "hostPrefix", ndChanges)
		Expect(podChanges.Update(nil, nil)).To(BeFalse())
	})

	It("Add pod with net-attach annotation and verify", func() {
		ndChanges := NewNetDefChangeTracker()
		podChanges := NewFakePodChangeTracker("nodeName", "hostPrefix", ndChanges)

		Expect(ndChanges.Update(nil, NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "macvlan")))).To(BeTrue())

		Expect(podChanges.Update(nil, NewFakePodWithNetAnnotation("testns1", "testpod1", "net-attach1", NewFakeNetworkStatus("testns1", "net-attach1")))).To(BeTrue())
		podMap := make(PodMap)
		podMap.Update(podChanges)
		Expect(len(podMap)).To(Equal(1))

		pod1, ok := podMap[types.NamespacedName{Namespace: "testns1", Name: "testpod1"}]
		Expect(ok).To(BeTrue())
		Expect(pod1.Name).To(Equal("testpod1"))
		Expect(pod1.Namespace).To(Equal("testns1"))
		Expect(len(pod1.Interfaces)).To(Equal(1))
	})

	It("Add pod with net-attach annotation and verify", func() {
		ndChanges := NewNetDefChangeTracker()
		podChanges := NewFakePodChangeTracker("nodeName", "hostPrefix", ndChanges)

		Expect(ndChanges.Update(nil, NewNetDef("testns1", "net-attach1", NewCNIConfig("testCNI", "macvlan")))).To(BeTrue())
		Expect(podChanges.Update(nil, NewFakePod("testns1", "testpod1"))).To(BeTrue())
		podMap := make(PodMap)
		podMap.Update(podChanges)
		Expect(len(podMap)).To(Equal(1))

		pod1, ok := podMap[types.NamespacedName{Namespace: "testns1", Name: "testpod1"}]
		Expect(ok).To(BeTrue())
		Expect(pod1.Name).To(Equal("testpod1"))
		Expect(pod1.Namespace).To(Equal("testns1"))
		Expect(len(pod1.Interfaces)).To(Equal(0))

		Expect(podChanges.Update(NewFakePod("testns1", "testpod1"), NewFakePodWithNetAnnotation("testns1", "testpod1", "net-attach1", NewFakeNetworkStatus("testns1", "net-attach1")))).To(BeTrue())

		podMap.Update(podChanges)
		Expect(len(podMap)).To(Equal(1))

		pod2, ok := podMap[types.NamespacedName{Namespace: "testns1", Name: "testpod1"}]
		Expect(ok).To(BeTrue())
		Expect(pod2.Name).To(Equal("testpod1"))
		Expect(pod2.Namespace).To(Equal("testns1"))
		Expect(len(pod2.Interfaces)).To(Equal(1))
	})

})
