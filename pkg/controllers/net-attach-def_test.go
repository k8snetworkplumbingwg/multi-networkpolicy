package controllers

import (
	"fmt"
	"time"

	netdefv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	netdeffake "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/clientset/versioned/fake"
	netdefinformerv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/client/informers/externalversions"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type FakeNetDefConfigStub struct {
	CounterAdd    int
	CounterUpdate int
	CounterDelete int
	CounterSynced int
}

func (f *FakeNetDefConfigStub) OnNetDefAdd(_ *netdefv1.NetworkAttachmentDefinition) {
	f.CounterAdd++
}

func (f *FakeNetDefConfigStub) OnNetDefUpdate(_, _ *netdefv1.NetworkAttachmentDefinition) {
	f.CounterUpdate++
}

func (f *FakeNetDefConfigStub) OnNetDefDelete(_ *netdefv1.NetworkAttachmentDefinition) {
	f.CounterDelete++
}

func (f *FakeNetDefConfigStub) OnNetDefSynced() {
	f.CounterSynced++
}

func NewFakeNetDefConfig(stub *FakeNetDefConfigStub) *NetDefConfig {
	configSync := 15 * time.Minute
	fakeClient := netdeffake.NewSimpleClientset()
	netdefInformarFactory := netdefinformerv1.NewSharedInformerFactoryWithOptions(fakeClient, configSync)
	netdefConfig := NewNetDefConfig(netdefInformarFactory.K8sCniCncfIo().V1().NetworkAttachmentDefinitions(), configSync)
	netdefConfig.RegisterEventHandler(stub)
	return netdefConfig
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

var _ = Describe("net-attach-def config", func() {
	It("check add handler", func() {
		stub := &FakeNetDefConfigStub{}
		ndConfig := NewFakeNetDefConfig(stub)
		ndConfig.handleAddNetDef(NewNetDef("testns1", "test1", NewCNIConfig("cniConfig1", "testType1")))
		Expect(stub.CounterAdd).To(Equal(1))
		Expect(stub.CounterUpdate).To(Equal(0))
		Expect(stub.CounterDelete).To(Equal(0))
		Expect(stub.CounterSynced).To(Equal(0))
	})

	It("check update handler", func() {
		stub := &FakeNetDefConfigStub{}
		ndConfig := NewFakeNetDefConfig(stub)
		ndConfig.handleUpdateNetDef(
			NewNetDef("testns1", "test1", NewCNIConfig("cniConfig1", "testType1")),
			NewNetDef("testns1", "test1", NewCNIConfig("cniConfig2", "testType2")))
		Expect(stub.CounterAdd).To(Equal(0))
		Expect(stub.CounterUpdate).To(Equal(1))
		Expect(stub.CounterDelete).To(Equal(0))
		Expect(stub.CounterSynced).To(Equal(0))
	})

	It("check delete handler", func() {
		stub := &FakeNetDefConfigStub{}
		ndConfig := NewFakeNetDefConfig(stub)
		ndConfig.handleDeleteNetDef(NewNetDef("testns", "test", NewCNIConfig("cniConfig1", "testType1")))
		Expect(stub.CounterAdd).To(Equal(0))
		Expect(stub.CounterUpdate).To(Equal(0))
		Expect(stub.CounterDelete).To(Equal(1))
		Expect(stub.CounterSynced).To(Equal(0))
	})
})

var _ = Describe("net-attach-def controller", func() {
	It("Initialize and verify empty", func() {
		netDefChanges := NewNetDefChangeTracker()
		ndMap := make(NetDefMap)
		ndMap.Update(netDefChanges)
		Expect(len(ndMap)).To(Equal(0))
	})

	It("Add netdef and verify", func() {
		ndChanges := NewNetDefChangeTracker()
		ndChanges.Update(nil, NewNetDef("testns1", "test1", NewCNIConfig("cniConfig1", "testType1")))
		ndChanges.Update(nil, NewNetDef("testns2", "test2", NewCNIConfigList("cniConfig2", "testType2")))

		ndMap := make(NetDefMap)
		ndMap.Update(ndChanges)
		Expect(len(ndMap)).To(Equal(2))
		ndTest1, ok := ndMap[types.NamespacedName{Namespace: "testns1", Name: "test1"}]
		Expect(ok).To(BeTrue())
		Expect(ndTest1.Name()).To(Equal("test1"))
		Expect(ndTest1.PluginType).To(Equal("testType1"))

		ndTest2, ok := ndMap[types.NamespacedName{Namespace: "testns2", Name: "test2"}]
		Expect(ok).To(BeTrue())
		Expect(ndTest2.Name()).To(Equal("test2"))
		Expect(ndTest2.PluginType).To(Equal("testType2"))
	})

	It("Add netdef then del it and verify", func() {
		ndChanges := NewNetDefChangeTracker()
		ndChanges.Update(nil, NewNetDef("testns1", "test1", NewCNIConfigList("cniConfig1", "testType1")))
		ndChanges.Update(nil, NewNetDef("testns1", "test2", NewCNIConfig("cniConfig2", "testType2")))
		ndChanges.Update(NewNetDef("testns1", "test2", NewCNIConfig("cniConfig2", "testType2")), nil)

		ndMap := make(NetDefMap)
		ndMap.Update(ndChanges)
		Expect(len(ndMap)).To(Equal(1))
		ndTest1, ok := ndMap[types.NamespacedName{Namespace: "testns1", Name: "test1"}]
		Expect(ok).To(BeTrue())
		Expect(ndTest1.Name()).To(Equal("test1"))
		Expect(ndTest1.PluginType).To(Equal("testType1"))
	})

	It("invalid Update case", func() {
		ndChanges := NewNetDefChangeTracker()
		Expect(ndChanges.Update(nil, nil)).To(BeFalse())
	})

	It("Add netdef then update it and verify", func() {
		ndChanges := NewNetDefChangeTracker()
		ndChanges.Update(nil, NewNetDef("testns1", "test1", NewCNIConfig("cniConfig1", "testType1")))
		ndChanges.Update(NewNetDef("testns1", "test1", NewCNIConfig("cniConfig1", "testType1")),
			NewNetDef("testns1", "test1", NewCNIConfigList("cniConfig2", "testType2")))

		ndMap := make(NetDefMap)
		ndMap.Update(ndChanges)
		Expect(len(ndMap)).To(Equal(1))
		ndTest1, ok := ndMap[types.NamespacedName{Namespace: "testns1", Name: "test1"}]
		Expect(ok).To(BeTrue())
		Expect(ndTest1.Name()).To(Equal("test1"))
		Expect(ndTest1.PluginType).To(Equal("testType2"))
	})
})
