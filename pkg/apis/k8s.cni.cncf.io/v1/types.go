package v1

import (
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resourceName=macvlan-networkpolicies

// MacvlanNetworkPolicy ...
type MacvlanNetworkPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +optional
	Spec MacvlanNetworkPolicySpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// MacvlanNetworkPolicyList ...
type MacvlanNetworkPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []MacvlanNetworkPolicy `json:"items"`
}

// MacvlanPolicyType ...
type MacvlanPolicyType string

const (
	// PolicyTypeIngress ...
	PolicyTypeIngress MacvlanPolicyType = "Ingress"
	// PolicyTypeEgress ...
	PolicyTypeEgress  MacvlanPolicyType = "Egress"
)

// MacvlanNetworkPolicySpec ...
type MacvlanNetworkPolicySpec struct {
	PodSelector metav1.LabelSelector `json:"podSelector"`

	// +optional
	Ingress []MacvlanNetworkPolicyIngressRule `json:"ingress,omitempty"`

	// +optional
	Egress []MacvlanNetworkPolicyEgressRule `json:"egress,omitempty"`
	// +optional
	PolicyTypes []MacvlanPolicyType `json:"policyTypes,omitempty"`
}

// MacvlanNetworkPolicyIngressRule ...
type MacvlanNetworkPolicyIngressRule struct {
	// +optional
	Ports []MacvlanNetworkPolicyPort `json:"ports,omitempty"`

	// +optional
	From []MacvlanNetworkPolicyPeer `json:"from,omitempty"`
}

// MacvlanNetworkPolicyEgressRule ...
type MacvlanNetworkPolicyEgressRule struct {
	// +optional
	Ports []MacvlanNetworkPolicyPort `json:"ports,omitempty"`

	// +optional
	To []MacvlanNetworkPolicyPeer `json:"to,omitempty"`
}

// MacvlanNetworkPolicyPort ...
type MacvlanNetworkPolicyPort struct {
	// +optional
	Protocol *v1.Protocol `json:"protocol,omitempty"`

	// +optional
	Port *intstr.IntOrString `json:"port,omitempty"`
}

// IPBlock ...
type IPBlock struct {
	CIDR string `json:"cidr"`
	// +optional
	Except []string `json:"except,omitempty"`
}

// MacvlanNetworkPolicyPeer ...
type MacvlanNetworkPolicyPeer struct {
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`

	// +optional
	IPBlock *IPBlock `json:"ipBlock,omitempty"`
}
