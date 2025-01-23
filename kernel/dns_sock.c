#include <linux/bpf.h>
#include <linux/ip.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include "dns.h"
#include "consts.h"
#include "utils.h"
#include "raw_proc.h"



SEC("sock")
int process(struct __sk_buff *skb) {
    
}


char __license[] SEC("license") = "MIT/GPL"; 