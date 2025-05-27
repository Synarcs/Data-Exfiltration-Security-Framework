/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package utils

import (
	"errors"
	"os"
	"strings"
)

// used to guard exfiltration against host net_device for egress traffic
var (
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

func ConfigureCustomEBPFProgOutputPath(path string) error {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			Log("Error please provide a valide path containing all the eBPF kernel eBPF programs for eBPF agent")
		}
		return err
	}

	// configure custom path
	TC_EGRESS_ROOT_NETIFACE_INT = path + "/" + strings.Split(TC_EGRESS_ROOT_NETIFACE_INT, "/")[1]
	NF_EGRESS_BRIDGE_NETIFACE_INT = path + "/" + strings.Split(NF_EGRESS_BRIDGE_NETIFACE_INT, "/")[1]
	NF_INGRESS_BRIDGE_NETIFACE_INT = path + "/" + strings.Split(NF_INGRESS_BRIDGE_NETIFACE_INT, "/")[1]
	TC_EGRESS_TUNNEL_NETIFACE_INT = path + "/" + strings.Split(TC_EGRESS_TUNNEL_NETIFACE_INT, "/")[1]
	SOCK_TUNNEL_CODE_EBPF = path + "/" + strings.Split(SOCK_TUNNEL_CODE_EBPF, "/")[1]

	TRACEPOINT_KERNEL_PROG = path + "/" + strings.Split(TRACEPOINT_KERNEL_PROG, "/")[1]
	LSM_CRYPTO_BPF_VERIFER_PROG = path + "/" + strings.Split(LSM_CRYPTO_BPF_VERIFER_PROG, "/")[1]

	SOCK_SKB_OP_CODE_EBPF = path + "/" + strings.Split(SOCK_SKB_OP_CODE_EBPF, "/")[1]
	SDR_SOCK_NETIFACT_FILTER = path + "/" + strings.Split(SDR_SOCK_NETIFACT_FILTER, "/")[1]

	return nil
}
