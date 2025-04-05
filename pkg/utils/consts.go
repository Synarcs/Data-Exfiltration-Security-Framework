package utils

// used to guard exfiltration against host net_device for egress traffic
const (
	TC_EGRESS_ROOT_NETIFACE_INT    = "ebpf/tc.o"
	NF_EGRESS_BRIDGE_NETIFACE_INT  = "ebpf/bridge_ing.o"
	NF_INGRESS_BRIDGE_NETIFACE_INT = "ebpf/bridge_ing.o"
	TC_EGRESS_TUNNEL_NETIFACE_INT  = "ebpf/tun.o"
	SOCK_TUNNEL_CODE_EBPF          = "ebpf/netlink.o"
	TRACEPOINT_KERNEL_PROG         = "ebpf/tracepoint.o"

	LSM_CRYPTO_BPF_VERIFER_PROG = "ebpf/lsm_bpf.o"

	SOCK_SKB_OP_CODE_EBPF = "ebpf/sock.o" // kernel egress sock prog for sock op over a cgroup
	// sdr sock_ops and sock_filter for skb_buff
	SDR_SOCK_NETIFACT_FILTER = "ebpf/sock.o"
)
