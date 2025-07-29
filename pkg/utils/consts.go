/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package utils

import (
	"errors"
	"os"
	"strings"
	"time"
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

var DEBUG = false

// kernel network traffic control and xdp ingress layer
const (
	TC_CONTROL_PROG                = "exfil_sec"                       // CLSACT  QDISC
	TC_CONTROL_PROG_BRIDGE_INGRESS = "exfil_sec_bridge_ingress_filter" // CLSACT  QDISC
	TC_CONTROL_PROG_BRIDGE_EGRESS  = "exfil_sec_bridge_ingress_filter" // CLSACT  QDISC

	TRACEPOINT_PROC_KILL_TRACEPOINT = "handle_mal_c2_proc_exit" // sched_process_exit
	SOCK_OPS_PROC_UDP_TRACEPOINT    = "dns_udp_sock_ops"        // cgroups_skb/egress
	XDP_CONTROL_PROG                = "xdp"                     // XDP Non Offloaded BXDINAUB Fkiid orevebtuib '

	LSM_CRYPTO_VERIFY_PROG        = "bpf" // runs over lsm crypto for bpf_prog load lsm.o
	TC_CLSACT_PARENT_QDISC_HANDLE = 0xffff
	TC_CLSACT_PARENT_QDISC_PRIO   = 1
	DEFAULT_SK_BUFF_NUONCE        = 0xffff
)

// capture performance benchmark details
const (
	ENABLE_KERNEL_DPI_IMPACT_MEASURE_TIME = true
)

const (
	SOCK_TUNNEL_CODE = "netlink_socket"
)

const (
	SUSPICIOUS_NETNS_IPV6 = "fe80::d091:3cff:fe25:6d96"
	MALICIOUS_NETNS_IPV6  = "fe80::d091:3cff:fe25:6d97"
)

var (
	// google DNS servers
	GLOBAL_ROUTE_IPV6_TRANSFER_LINKS = []string{
		"2001:4860:4860::8888",
		"2001:4860:4860::8844",
		"2606:4700:4700::1111",
		"2606:4700:4700::1001",
	}
	GLOBAL_ROUTE_IPV4_TRANSFER_LINKS = []string{
		"8.8.8.8",
		"8.8.4.4",
		"1.1.1.1",
	}
)

// map pin vfs for bpf to mount pinned maps
const (
	PINPATH  = "/sys/fs/bpf"
	CGROUPFS = "/sys/fs/cgroup"
)

const (
	TCX_KERNEL_SUPPORT_MAJOR_RELEASE = 6
	TCX_KERNEL_SUPPORT_PATCH_RELEASE = 6
	TCX_KERNEL_SUPPORT_SUB_RELEASE   = 10
)

// kernel skb makr from tc qdisc over netns filter or netfilter chain
const (
	REDIRECT_SKB_MARK = 0xff
)

const (
	BRIDGE_IPAM_IPV4_CIDR          = "10.200.0.0/24"
	BRIDGE_IPAM_IPV4_IP            = "10.200.0."
	BRIDGE_IPAM_MAL_TUNNEL_IPV4_IP = "10.210.0.0" // send to the router bridge gateway for now
)

const (
	DNS_EGRESS_PORT                   uint16 = 53
	DOT_EGRESS_PORT                   uint16 = 853
	DNS_EGRESS_MULTICAST_PORT         uint16 = 5353
	LLMNR_EGRESS_LOCAL_MULTICAST_PORT uint16 = 5355
)

const (
	DEFAULT_SIGKILL_MALICIOUS_EXFIL_THRESHOLD = 5
)

var (
	EXFIL_PROCESS_CACHE_CLEAN_INTERVAL              = time.Second * 10                          // use to prune the map which ensure the required
	EXFIL_PROCESS_CACHE_CLEAN_THRESHOLD             = DEFAULT_SIGKILL_MALICIOUS_EXFIL_THRESHOLD // ideally the c2 implant malware would starve and kill itself, but if keeps retrying the security node agent will kill the process, used for overlayed DNS over random UDP port
	EXFIL_PROCESS_CACHE_CLEAN_THRESHOLD_BENIGN_PORT = DEFAULT_SIGKILL_MALICIOUS_EXFIL_THRESHOLD // higher threshold compared to tunnelle c2 for random DNS tunnel which must be lower to stop breach asap

	EXFIL_PROCESS_CACHE_CLEAN_MALICIOUS_PORT_INGRESS_SNIF_THRESHOLD = 5
)

const (
	NODE_CONFIG_FILE = "config.yaml"
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
