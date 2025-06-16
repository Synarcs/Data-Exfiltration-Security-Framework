/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#include <linux/bpf.h>
#include <linux/version.h>

#include <bpf/bpf_helpers.h>
#include <stdbool.h>

#include "consts.h"

struct kill_proc_mal_payload {
    __u32 MalDetectedCount;
    __u32 dest_port;
};

struct exfil_security_egress_proc_mal {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32); // process id 
    __type(value, struct kill_proc_mal_payload);  // whether this process malicious transfer happened and all packets over this process must be dropped
    __uint(max_entries, 1 << 10);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} exfil_security_egress_proc_mal SEC(".maps");


struct exfil_security_egress_nsp_map_key {
    __u32 processId;
    __u16 dport;
};

struct exfil_security_egress_nsp_map {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1 << 10);
    __type(key, struct exfil_security_egress_nsp_map_key); // dport, procId count malicious transfer over the unqieu key fd detected from user space added in kernel over first transfer
    __type(value, __u32); // detected malicious count of packets on the dport
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} exfil_security_egress_nsp_map SEC(".maps");



// dynamic netpool l3 ipv4 filtering for any malicious traffic found to upstream servers 
#if L3_IPV4_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS
    struct exfil_security_egress_l3_ipv4_dynamic_netpool_c2_filter {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, 1 << 10);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
    } exfil_security_egress_l3_ipv4_dynamic_netpool_c2_filter SEC(".maps");
#endif 


#if L3_IPV6_DYNAMIC_KERNEL_NETPOOL_SECURITY_MALICIOUS_REMOTE_C2_SERVERS
    struct exfil_security_egress_l3_ipv6_dynamic_netpool_c2_filter {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __type(key, struct in6_addr);
        __type(value, __u8);
        __uint(map_flags, BPF_F_NO_PREALLOC);
        __uint(max_entries, 1 << 10);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
    } exfil_security_egress_l3_ipv6_dynamic_netpool_c2_filter SEC(".maps");
#endif 

struct exfil_security_tc_bridge_config_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // constant kernel key 
    __type(value, __u32);   // layer ifindex for the kenrle bridge route;
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} exfil_security_tc_bridge_config_map SEC(".maps");


/*
    If potential exfiltration is occuring over standard port, the kernel DPI runs in 2 modes
        1. Aggresive: Uses Live redirect of DNS traffic post deep parse / raw parse DNS in kernel 
        2. Passive: Uses clone redirect or passive redirect, but the node-agent in userspace and kernel 
                aggresivelly hunts for any malicious activity which may occur over consecurity packets send from the same malicious process

        Aggressive Mode:
            Adds some latency due to kernel redirect, and read from virtual netdev, rx queues in userspace bypass network stack
        Passive Mode:
            Does not add latency but the kernel DPI aggresively start hunting for malicious activity from the process referred as kernel espionage for tracking most activity of malicious process.

        The kernel DPI is vertically integrated with kernel syscall layer for performance
*/

struct exfil_kernel_config  {
    __u32 BridgeIndexId;
    __u32 NfNdpBridgeIndexId;
    __be32 RedirectIpv4;
    __be32 NfNdpBridgeRedirectIpv4;
    __u32 KernelTCSKBMark;
    __u8 IsAgressiveSec; // tells the kernel DPI to run the DNS DPI in aggresive mode,
} __attribute__((packed));


// kernel config map to load the config for the redirect links to egress and associated bridge if_index 
struct exfil_security_config_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct exfil_kernel_config);
    __uint(max_entries, 1 << 6);
} exfil_security_config_map SEC(".maps");

