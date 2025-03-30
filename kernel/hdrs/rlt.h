#ifndef __RTL_H_ 
    #define __RTL_H_

#include <stdbool.h>

// RATE LIMITER 
#define RATE_LIMIT_VOLUME_TIME_WINDOW 10000000000
#define MAX_VOLUME_THRESHOLD 600000 
#define MAX_FREQUENCY_PER_SEC 100

#if DNS_RATE_LIMIT_TOCKEN_BUCKET 
    struct token_bucket_dns_rl {
        __u64 max_token; // max tokens the bucket can hold
        __u64 refill_tokens; // number of tokens can be refilled per refill interval 
        __u64 reflill_interval; // time in ns 
        struct bpf_timer timer;
    };

    struct token_bucket_dns_rl  {
        ___uint(type, BPF_MAP_TYPE_LRU_HASH);
        __type(key, __u16);  // token bucket hash map tied to a specific protocol to rate limit now for DNS
        __type(value, struct token_bucket_dns_rl);
        __uint(max_entries, 1 << 10); 
    } token_bucket_dns_rl SEC(".maps");
#endif

#endif