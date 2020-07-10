package controllers

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

type FakeNamespaceConfigStub struct {
	CounterAdd    int
	CounterUpdate int
	CounterDelete int
	CounterSynced int
}

func (f *FakeNamespaceConfigStub) OnNamespaceAdd(_ *v1.Namespace) {
	f.CounterAdd++
}

func (f *FakeNamespaceConfigStub) OnNamespaceUpdate(_, _ *v1.Namespace) {
	f.CounterUpdate++
}

func (f *FakeNamespaceConfigStub) OnNamespaceDelete(_ *v1.Namespace) {
	f.CounterDelete++
}

func (f *FakeNamespaceConfigStub) OnNamespaceSynced() {
	f.CounterSynced++
}

func NewFakeNamespaceConfig(stub *FakeNamespaceConfigStub) *NamespaceConfig {
	configSync := 15 * time.Minute
	fakeClient := fake.NewSimpleClientset()
	informerFactory := informers.NewSharedInformerFactoryWithOptions(fakeClient, configSync)
	nsConfig := NewNamespaceConfig(informerFactory.Core().V1().Namespaces(), configSync)
	nsConfig.RegisterEventHandler(stub)
	return nsConfig
}

func NewNamespace(name string, labels map[string]string) *v1.Namespace {
	return &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
	}
}

var _ = Describe("namespace config", func() {
	It("check add handler", func() {
		stub := &FakeNamespaceConfigStub{}
		nsConfig := NewFakeNamespaceConfig(stub)
		nsConfig.handleAddNamespace(NewNamespace("test", nil))
		Expect(stub.CounterAdd).To(Equal(1))
		Expect(stub.CounterUpdate).To(Equal(0))
		Expect(stub.CounterDelete).To(Equal(0))
		Expect(stub.CounterSynced).To(Equal(0))
	})

	It("check update handler", func() {
		stub := &FakeNamespaceConfigStub{}
		nsConfig := NewFakeNamespaceConfig(stub)
		nsConfig.handleUpdateNamespace(NewNamespace("test1", nil), NewNamespace("test2", nil))
		Expect(stub.CounterAdd).To(Equal(0))
		Expect(stub.CounterUpdate).To(Equal(1))
		Expect(stub.CounterDelete).To(Equal(0))
		Expect(stub.CounterSynced).To(Equal(0))
	})

	It("check delete handler", func() {
		stub := &FakeNamespaceConfigStub{}
		nsConfig := NewFakeNamespaceConfig(stub)
		nsConfig.handleDeleteNamespace(NewNamespace("test1", nil))
		Expect(stub.CounterAdd).To(Equal(0))
		Expect(stub.CounterUpdate).To(Equal(0))
		Expect(stub.CounterDelete).To(Equal(1))
		Expect(stub.CounterSynced).To(Equal(0))
	})
})

var _ = Describe("namespace controller", func() {
	It("Initialize and verify empty", func() {
		nsChanges := NewNamespaceChangeTracker()
		nsMap := make(NamespaceMap)
		nsMap.Update(nsChanges)
		Expect(len(nsMap)).To(Equal(0))
	})

	It("Add ns and verify", func() {
		nsChanges := NewNamespaceChangeTracker()
		Expect(nsChanges.Update(nil, NewNamespace("test1", map[string]string{"labelName1": "labelValue1"}))).To(BeTrue())

		nsMap := make(NamespaceMap)
		nsMap.Update(nsChanges)
		Expect(len(nsMap)).To(Equal(1))
		nsTest1, ok := nsMap["test1"]
		Expect(ok).To(BeTrue())
		Expect(nsTest1.Name).To(Equal("test1"))
		Expect(len(nsTest1.Labels)).To(Equal(1))

		labelTest, ok := nsTest1.Labels["labelName1"]
		Expect(ok).To(BeTrue())
		Expect(labelTest).To(Equal("labelValue1"))
	})

	It("Add ns then del ns and verify", func() {
		nsChanges := NewNamespaceChangeTracker()
		Expect(nsChanges.Update(nil, NewNamespace("test1", map[string]string{"labelName1": "labelValue1"}))).To(BeTrue())
		Expect(nsChanges.Update(nil, NewNamespace("test2", map[string]string{"labelName2": "labelValue2"}))).To(BeTrue())
		Expect(nsChanges.Update(NewNamespace("test2", map[string]string{"labelName2": "labelValue2"}), nil)).To(BeTrue())

		nsMap := make(NamespaceMap)
		nsMap.Update(nsChanges)
		Expect(len(nsMap)).To(Equal(1))
		nsTest1, ok := nsMap["test1"]
		Expect(ok).To(BeTrue())
		Expect(nsTest1.Name).To(Equal("test1"))
		Expect(len(nsTest1.Labels)).To(Equal(1))

		labelTest, ok := nsTest1.Labels["labelName1"]
		Expect(ok).To(BeTrue())
		Expect(labelTest).To(Equal("labelValue1"))
	})

	It("invalid Update case", func() {
		nsChanges := NewNamespaceChangeTracker()
		Expect(nsChanges.Update(nil, nil)).To(BeFalse())
	})

	It("Add ns then update ns and verify", func() {
		nsChanges := NewNamespaceChangeTracker()
		Expect(nsChanges.Update(nil, NewNamespace("test1", map[string]string{"labelName1": "labelValue1"}))).To(BeTrue())
		Expect(nsChanges.Update(nil, NewNamespace("test1", map[string]string{"labelName2": "labelValue2"}))).To(BeTrue())
		nsMap := make(NamespaceMap)
		nsMap.Update(nsChanges)
		Expect(len(nsMap)).To(Equal(1))
		nsTest1, ok := nsMap["test1"]
		Expect(ok).To(BeTrue())
		Expect(nsTest1.Name).To(Equal("test1"))
		Expect(len(nsTest1.Labels)).To(Equal(1))

		labelTest, ok := nsTest1.Labels["labelName2"]
		Expect(ok).To(BeTrue())
		Expect(labelTest).To(Equal("labelValue2"))
	})
})
