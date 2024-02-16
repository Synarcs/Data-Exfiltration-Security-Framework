//
// Created by synarcs on 2/16/24.
//
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") dnsBuffer = {
        .type = BPF_MAP_TYPE_LRU_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(__u64),
        .max_entries = 1 << 10,
};

// please delete the entry from the map once consumed from the user space
struct bpf_map_def SEC("maps") dns_event_buffer = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof (int),
        .value_size = sizeof (struct __domain_event),
        .max_entries = 1024,
};

