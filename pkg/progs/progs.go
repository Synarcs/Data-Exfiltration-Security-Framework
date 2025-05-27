/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package progs

// kernel network stack prog types
const (
	TC_PROG        = "tc"
	NETFILTER_PROG = "nft"
	SOCK_PROG      = "sock"
	KPROBE         = "kprobe"
	TRACEPOINT     = "tracepoint"
	XDP            = "xdp"
)

// kernel security / mac
const (
	LSM_BPF_HOOKS = "lsm"
)

// all the eBPF filter the node agent can inject in kernel, over the entire kernel network stack
// converts other prog and filter for netlink message for different netdev creation (tun/tap, vxlan etc)
// sock layer --> netfilter --> tc --> xdp
