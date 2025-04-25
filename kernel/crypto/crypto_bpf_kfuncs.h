#ifndef __CRYPTO_BPF_KFUNCS_H
#define __CRYPTO_BPF_KFUNCS_H

#include <bpf/bpf_helpers.h>

extern struct bpf_key *bpf_lookup_user_key(__u32 ,__u64 ) __ksym;
extern struct bpf_key *bpf_lookup_system_key(__u64) __ksym;
extern void bpf_key_put(struct bpf_key *) __ksym;
extern int bpf_verify_pkcs7_signature(const struct bpf_dynptr *,
				                      const struct bpf_dynptr *,
				                      const struct bpf_key *)  __ksym;
#endif /* __BPF_KFUNCS_H */