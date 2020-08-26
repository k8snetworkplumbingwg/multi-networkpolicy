# multi-networkpolicy

multi-networkpolicy provides network policy functionality for network attachment definition

## Current Status of the Repository

It is now actively developping hence not stable yet. Bug report and feature request are welcome.

## Description

Kubernetes provides [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) for network security. Currently net-attach-def does not support Network Policies because net-attach-def is CRD, user defined resources, outside of Kubernetes.
multi-network policy implements Network Policiy functionality for net-attach-def, by iptables and provies network security for net-attach-def networks.

## Quickstart

```
$ git clone https://github.com/k8snetworkplumbingwg/multi-networkpolicy
$ cd multi-networkpolicy
$ kubectl create -f scheme.yml
customresourcedefinition.apiextensions.k8s.io/multi-networkpolicies.k8s.cni.cncf.io created
$ kubectl create -f deploy.yml
clusterrole.rbac.authorization.k8s.io/multi-networkpolicy created
clusterrolebinding.rbac.authorization.k8s.io/multi-networkpolicy created
serviceaccount/multi-networkpolicy created
daemonset.apps/multi-networkpolicy-ds-amd64 created
```

## Demo

(TBD)

## How it Works

multi-networkpolicy consists from two components, CRD and daemonset.

### Macvlan Network Policy CRD

It provides new CRD for Network Policy, MacvlanNetworkPolicy, to prevent it from conflicting with Kubernetes network policy. Hence user can implement different network policy for net-attach-def from Kubernetes network policy. MacvlanNetworkPolicy is same scheme from NetworkPolicy (apiVersion: networking.k8s.io/v1), so nothing is different, except for `k8s.v1.cni.cncf.io/policy-for` annotation.

#### 'policy-for' annotation

`k8s.v1.cni.cncf.io/policy-for` annotation specifies which net-attach-def is the policy target as comma separated list, as `k8s.v1.cni.cncf.io/policy-for: macvlan-net1, macvlan-net3, ipvlan-net1`.

#### Policy Sample

(TBD)


### MacvlanNetworkPolicy DaemonSet

MacvlanNetworkPolicy creates DaemonSet and it runs `multi-network-policy-node` for each node. `multi-network-policy-node` watches MacvlanNetworkPolicy object and creates iptables rules into 'pod's network namespace', not container host and the iptables rules filters packets to interface, based on MultiNetworkPolicy.

## TODO

* Alternative packet processing other than iptables (e.g. xdp)

## Contact Us

For any questions about multi-networkpolicy, feel free to ask a question in #k8s-npwg-discussion in the [Intel-Corp Slack](https://intel-corp.herokuapp.com/), or open up a GitHub issue.
