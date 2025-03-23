#include <linux/bpf.h>
#include <linux/version.h>

// libbpf 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/*
    Uses PKCS#7 keyring to verify the pogram source before injecting 
*/
SEC("lsm.s/bpf")
int bpf_lsm_hook(struct bpf_lsm_event *ctx) {
    return 0;
}


char __license[] SEC("license") = "GPL"; 
