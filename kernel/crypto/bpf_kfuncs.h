#ifndef __BPF_KFUNCS_H
#define __BPF_KFUNCS_H

struct bpf_key;
struct bpf_dynptr;

extern struct bpf_key *bpf_lookup_user_key(__u32 serial, __u32 flags) __weak __ksym;
extern struct bpf_key *bpf_lookup_system_key(__u64 id) __weak __ksym;
extern int bpf_verify_pkcs7_signature(struct bpf_dynptr *data_ptr,
                                      struct bpf_dynptr *sig_ptr,
                                      struct bpf_key *key) __weak __ksym;
extern void bpf_key_put(struct bpf_key *key) __weak __ksym;

#endif /* __BPF_KFUNCS_H */