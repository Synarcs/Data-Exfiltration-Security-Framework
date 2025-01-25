package sidecar

// used to guard exfiltration against pod veth net_device for egress traffic
// the sock ops operates over IPAM managed by the CNI on the node
// for any sidecar traffic the filter chains are iptables or ebpf based the exfiltration gaaurd operates as post root tunnel betweem mutliple sockets over smae pod network space
/*
	eth0@xx (pod host net_device veth issued ipam from CNI)
			the ipam uses the gatway for CNI overlay configured on Node based on disjoint IPAM while the CNI on the node boots the pod networking for kubelet (eBPF, IPVS, IPtables for br_netfilter chains)

	lo		(local pod loopback interface)

	gx@xx 	(guard net_devices added as by the container in the same pod for multi container steup where all the container share same net_device and overall pod networking ns, ipc, hts etc)
			 This all relies on containerd and containerd rungime followed with kube pause to ensure all these net_device get shared networking if_index
			 the guard container inject eBPF programs over this link which holds skbb_reidrect in kernel to redirect to different net-device do DPI and resent from host net_device if found benign, if it has istio it will take l7 to be forwarded upstream for dns case it
			 			systemd-resolved on host net_deivce forwarded via  kube_dns

			For Istio, and service mesh in sidecar pattern and not ambient mode
			  Istio Init configures the pre init iptables rules in most case for envoy l7 to intercept traffic since the eBPF node agent container runs in CAP_NET_ADMIN,

*/
const (
	SOCK_SKB_FILTER = "sock.o" // root skb_filter for egress
)

const (
	POD_EBPF_PROGRAM_MOUNT_PATH = "/opt" // DNS security eBPF container will mount volume or builtint the image
)
