# multi-networkpolicy APIs

multi-networkpolicy APIs provides API for multi-networkpolicy, the network policy functionality for network attachment definition

## Current Status of the Repository

It is now actively developping hence not stable yet. Bug report and feature request are welcome.

## Description

Kubernetes provides [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) for network security. Currently net-attach-def does not support Network Policies because net-attach-def is CRD, user defined resources, outside of Kubernetes.
multi-network policy implements Network Policiy functionality for net-attach-def, by iptables and provies network security for net-attach-def networks.

## Current API version / branch

Currently API version and branch are mapped as following. `master` branch is working version, hence the CRD will be changed sometimes. If you want to have stable API, we recommend to use previous one.

| branch name | API version                          |
|-------------|--------------------------------------|
| master      | v1beta2 (working version, not fixed) |
| v1beta1     | v1beta1 (fixed)                      |

## Current Implementations

- [multi-networkpolicy-iptables](https://github.com/k8snetworkplumbingwg/multi-networkpolicy-iptables) supports v1beta1
- [multi-networkpolicy-tc](https://github.com/Mellanox/multi-networkpolicy-tc) supports v1beta1

## MultiNetworkPolicy CRD

### Macvlan Network Policy CRD

It provides new CRD for Network Policy, MultiNetworkPolicy, to prevent it from conflicting with Kubernetes network policy. Hence user can implement different network policy for net-attach-def from Kubernetes network policy. MultiNetworkPolicy is same scheme from NetworkPolicy (apiVersion: networking.k8s.io/v1), so nothing is different, except for `k8s.v1.cni.cncf.io/policy-for` annotation.

#### 'policy-for' annotation

`k8s.v1.cni.cncf.io/policy-for` annotation specifies which net-attach-def is the policy target as comma separated list, as `k8s.v1.cni.cncf.io/policy-for: macvlan-net1, macvlan-net3, ipvlan-net1`.

#### Policy Sample

(TBD)


## TODO

* Alternative packet processing other than iptables (e.g. xdp)

## Contact Us

For any questions about multi-networkpolicy, feel free to ask a question in #k8s-npwg-discussion in the [Intel-Corp Slack](https://intel-corp.herokuapp.com/), or open up a GitHub issue.
