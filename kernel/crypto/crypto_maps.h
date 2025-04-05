#ifndef __CRYPTOMAPS_H_
#define __CRYPTOMAPS_H_ 

#define KEY_SPEC_SESSION_KEYRING 1
#define MAX_DATA_SIZE (1024 * 1024)
#define MAX_SIG_SIZE 4096

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} keyring_map SEC(".maps");

struct original_data {
    __u8 data[MAX_DATA_SIZE];
    __u32 data_len;
    __u8 sig[MAX_SIG_SIZE];
    __u32 sig_len;
};

struct modified_sig {
    __u8 sig[MAX_SIG_SIZE];
    __u32 sig_len;
};

struct combined_buffer {
    __u8 data[MAX_DATA_SIZE + MAX_SIG_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct modified_sig);
} modified_signature SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct original_data);
} original_program SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct combined_buffer);
} combined_data_map SEC(".maps");

#endif /* __CRYPTOMAPS_H_ */