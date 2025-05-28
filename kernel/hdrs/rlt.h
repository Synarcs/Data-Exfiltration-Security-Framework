/* 
    Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

#ifndef __RTL_H_ 
    #define __RTL_H_

#include <linux/bpf.h>
#include <stdbool.h>

// RATE LIMITER 
#define RATE_LIMIT_VOLUME_TIME_WINDOW 10000000000
#define MAX_VOLUME_THRESHOLD 600000 
#define MAX_FREQUENCY_PER_SEC 100

// TB config for bucket of rate limiter 
#define MAX_TB_TOKEN_REFILL 10000
#define MIN_TB_TOKEN_CAP 0 

/*
    The core rate limit in the kernel will be useing EDT_BPF, with HTB and timer pinning to CPU
        to prevent true rate limiter in kernel for per packet processing over CPU 
*/

#if DNS_RATE_LIMIT_TOCKEN_BUCKET 
    struct token_bucket_dns_rl {
        struct bpf_timer timer;
        __u64 MaxTokens;  
        // __u64 reflill_interval; // assume the kernel for every second refills the bucket equal the maxtokens allowed to have rate limiter per sec 
        // in kernel the timer work over ns for ktime over a specifici cpu  hence after a second the time must be reset to match token capacity ensuring  uniform burst prevention
    };

    struct exfil_security_token_bucket_dns_rl  {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u16);  // token bucket hash map tied to a specific protocol to rate limit now for DNS
        __type(value, struct token_bucket_dns_rl);
        __uint(max_entries, 1); 
        __uint(map_flags, BPF_F_NO_PREALLOC);  // Required for maps with timers
    } exfil_security_token_bucket_dns_rl SEC(".maps");

    // hold the rate limiter window time analysis whether the clock timer has initiated 
    // only kernel will access and process this map to determine the timer is init over a specific CPU
    struct exfil_security_rtl_time_init {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u8);  // token bucket hash map tied to a specific protocol to rate limit now for DNS
        __type(value, __u8);
        __uint(max_entries, 1);
    } exfil_security_rtl_time_init SEC(".maps");

    #endif

#endif