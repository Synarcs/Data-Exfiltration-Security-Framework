package cni

/*
	The eBPF Node Agent runs over Host bridges deep inside the kernel Traffic control direct action qdisc
	CNI works most for l7 proxy over envoy based on filter chains all in user space.
	CNI for K8s based on CNI config runs over Ipv4 / ipv6 IPAM ove kernel l4/ l3 and l2 veth pairs mtu or via vxlan encap or BGP
	// Although all of the CNI relies over kernel's iptables (netfilter),  IPVS (over virtual router in kernel), eBPF for cilium always running over sock / cgroups for l44, lb , rate limit netpool etc.
		// these CNI plugin often support L7 filter either via envoy or l7 upstream proxy filters all user space with over proxy post sock layer read from kernel
		// For cilium DNS / HTTP / TLS and other L7 proxy are done with CNI proxy filters running in user space, since the eBPF agent runs on host net_device bridge this is used to dynamically
			inkect L7 netpools from host globally to enforce and instruct Kubelet to apply those netpools for l7 filtering
		Note if the eBPF node agent running over tc on is present with CNI supporting eBPF socks the agent can also prevent data breach from pods, but if added L7 sock filter the CNI can filter it out much before in kernel network stack before it reach tc host layer in kernel
		The eBPF Node agent as guard will instruct its slave inside k8s as a deploy or nodeport service with payload, which can further go and create required dynamic l4/l3/l7 network policies for eBPF sock maps or user space l7 proxies
*/

type CiliumNetworkPolicy struct {
	Cni     string
	Version string
}

func NewCiliunNetworkPolicy() *CiliumNetworkPolicy {
	return &CiliumNetworkPolicy{
		Cni:     "cilium",
		Version: "v1",
	}
}

// the controller dont care about specific node selector and affinity its kernel enforced security over the entire cluster
type CiliumL3NetworkPolicyRequest struct {
	Ipv4 []string
	Ipv6 []string
}

// the controller dont care about specific node selector and affinity its kernel enforced security over the entire cluster
type CiliumL7NetworkPolicyRequest struct {
	Tld  []string
	Fqdn []string
}

func (cni *CiliumNetworkPolicy) CreateL3NetworkPolicy([]string) error {
	return nil
}

func (cni *CiliumNetworkPolicy) CreateL7NetworkPolicy([]string) error {
	return nil
}

func (cni *CiliumNetworkPolicy) GetCniVersion() string {
	return ""
}

func (cni *CiliumNetworkPolicy) GetCniName() string {
	return ""
}
