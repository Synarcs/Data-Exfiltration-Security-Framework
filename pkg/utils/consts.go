package utils

// used to guard exfiltration against host net_device for egress traffic
const (
	TC_EGRESS_ROOT_NETIFACE_INT   = "ebpf/tc.o"
	NF_EGRESS_BRIDGE_NETIFACE_INT = "ebpf/bridge.o"
	TC_EGRESS_TUNNEL_NETIFACE_INT = "ebpf/tun.o"
	SOCK_TUNNEL_CODE_EBPF         = "ebpf/netlink.o"
	// sdr sock_ops and sock_filter for skb_buff
	SDR_SOCK_NETIFACT_FILTER = "ebpf/sock.o"
)
