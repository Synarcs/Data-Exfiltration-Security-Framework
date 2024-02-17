#pragma once

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct dns_event {
    char eventname[100];
    int size;
};

struct bpf_map_def SEC("maps") dns_ring_buffer_events = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u64),
        .value_size = sizeof(sizeof( struct dns_event)),
        .max_entries = 1 << 10,
};