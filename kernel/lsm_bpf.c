/* Copyright (c) 2024-2025 Synarcs
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *   -----------------------------
 *    Author: Synarcs
 *    Data:   04/04/2025, 2:59:15 AM
 *   -----------------------------
*/


#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// #include "hdrs/vmlinux.h"

#include "crypto/crypto_maps.h"

#define MAX_DATA_SIZE (1024 * 1024)
#define MAX_SIG_SIZE 4096

#define USER_KEYRING_IDX 0
#define SYSTEM_KEYRING_IDX 1

extern struct bpf_key *bpf_lookup_user_key(u32 serial, u64 flags) __weak __ksym;
extern struct bpf_key *bpf_lookup_system_key(u64 id) __weak __ksym;
extern void bpf_key_put(struct bpf_key *key) __weak __ksym;

SEC("lsm.s/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    struct bpf_dynptr sig_ptr, orig_data_ptr, orig_sig_ptr, combined_data_ptr;
    struct modified_sig *mod_sig;
    struct original_data *orig_data;
    struct bpf_key *trusted_keyring;
    struct combined_buffer *combined_buf;
    __u32 insn_cnt;
    int ret, zero = 0;

    if (cmd != BPF_PROG_LOAD)
        return 0;

    mod_sig = bpf_map_lookup_elem(&modified_signature, &zero);
    if (!mod_sig)
        return -ENOENT;

    orig_data = bpf_map_lookup_elem(&original_program, &zero);
    if (!orig_data)
        return -ENOENT;

    combined_buf = bpf_map_lookup_elem(&combined_data_map, &zero);
    if (!combined_buf)
        return -ENOENT;

    ret = bpf_probe_read_kernel(&insn_cnt, sizeof(insn_cnt), &attr->insn_cnt);
    if (ret)
        goto out;

    if (mod_sig->sig_len > sizeof(mod_sig->sig) ||
        orig_data->data_len > sizeof(orig_data->data) ||
        orig_data->sig_len > sizeof(orig_data->sig) ||
        insn_cnt + orig_data->sig_len > sizeof(combined_buf->data))
        return -EINVAL;

    bpf_dynptr_from_mem(orig_data->data, orig_data->data_len, 0, &orig_data_ptr);
    orig_data->sig_len &= MAX_SIG_SIZE - 1;  // Bound to 1024 bytes for verifier
    bpf_dynptr_from_mem(orig_data->sig, orig_data->sig_len, 0, &orig_sig_ptr);

    // Copy program and original signature into combined buffer
    __u32 insn_len = insn_cnt * sizeof(struct bpf_insn);
    insn_len &= MAX_DATA_SIZE - 1;  // Bound for verifier
    ret = bpf_copy_from_user(combined_buf->data, insn_len, (void *)(unsigned long)attr->insns);
    if (ret) {
        bpf_printk("Failed to copy program: %d\n", ret);
        goto out;
    }

    // Ensure we stay within buffer bounds
    if (insn_len >= MAX_DATA_SIZE || orig_data->sig_len >= MAX_SIG_SIZE) {
        bpf_printk("Insufficient buffer size\n");
        ret = -E2BIG;
        goto out;
    }

    ret = bpf_probe_read_kernel(combined_buf->data + insn_len,
                               MAX_SIG_SIZE,
                               orig_data->sig);
    if (ret) {
        bpf_printk("Failed to copy original signature: %d\n", ret);
        goto out;
    }

    // Bound total size for verifier
    __u32 total_size = insn_len + orig_data->sig_len;
    if (total_size > MAX_DATA_SIZE + MAX_SIG_SIZE) {
        bpf_printk("Insufficient buffer size\n");
        ret = -E2BIG;
        goto out;
    }

    bpf_dynptr_from_mem(combined_buf->data, total_size, 0, &combined_data_ptr);
    __u32 mod_sig_size = mod_sig->sig_len & (MAX_SIG_SIZE - 1);
    bpf_dynptr_from_mem(mod_sig->sig, mod_sig_size, 0, &sig_ptr);

    __u32 user_keyring_serial = 0;
    __u32 system_keyring_id = 0;
    __u32 idx = USER_KEYRING_IDX;
    __u32 *keyring_serial = bpf_map_lookup_elem(&keyring_map, &idx);
    if (keyring_serial)
        user_keyring_serial = *keyring_serial;

    idx = SYSTEM_KEYRING_IDX;
    __u32 *system_keyring = bpf_map_lookup_elem(&keyring_map, &idx);
    if (system_keyring)
        system_keyring_id = *system_keyring;

    if (user_keyring_serial)
        trusted_keyring = bpf_lookup_user_key(user_keyring_serial, 0);
    else
        trusted_keyring = bpf_lookup_system_key(system_keyring_id);

    if (!trusted_keyring)
        return -ENOENT;

    ret = bpf_verify_pkcs7_signature(&orig_data_ptr, &orig_sig_ptr, trusted_keyring);
    if (ret) {
        bpf_printk("Failed to verify original signature\n");
        bpf_key_put(trusted_keyring);
        goto out;
    }

    ret = bpf_verify_pkcs7_signature(&combined_data_ptr, &sig_ptr, trusted_keyring);
    if (ret)
        bpf_printk("Failed to verify combined signature\n");

    bpf_key_put(trusted_keyring);

out:
    return ret;
}

char _license[] SEC("license") = "GPL";
