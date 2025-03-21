package progs

const (
	TC_PROG        = "tc"
	NETFILTER_PROG = "nft"
	SOCK_PROG      = "sock"
	KPROBE         = "kprobe"
	TRACEPOINT     = "tracepoint"
	XDP            = "xdp"
)

// all the eBPF filter the node agent can inject in kernel, over the entire kernel network stack
// converts other prog and filter for netlink message for different netdev creation (tun/tap, vxlan etc)
// sock layer --> netfilter --> tc --> xdp
