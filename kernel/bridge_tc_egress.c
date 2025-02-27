// <!---------------------------
// Name: DNSObelisk
// File: bridge_tc_egress.c
// -----------------------------
// Author: Synarcs
// ---------------------------->

#include <linux/pkt_cls.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include <stdbool.h> 

#include "consts.h"
#include "utils.h"

#define EXFIL_SECURITY_PIN_DNS_EGRESS_PATH "/sys/fs/bpf/exfil_security_config_map"

// allow only traffic having the custom mark and stop any other packets over the bridge 
SEC("tc")
int bridge_egress_filter(struct __sk_buff *skb) {
	return bpf_redirect(0, BPF_F_INGRESS); // let kernel gc over the rx queue in kernel for the netdev link 
}


char __license[] SEC("license") = "Dual MIT/GPL";

