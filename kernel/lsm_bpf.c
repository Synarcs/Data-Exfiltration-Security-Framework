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
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "crypto/crypto_maps.h"
#include "crypto/crypto_bpf_kfuncs.h"

#define MAX_DATA_SIZE (1024 * 1024)
#define MAX_SIG_SIZE 4096

#define USER_KEYRING_IDX 0
#define SYSTEM_KEYRING_IDX 1


SEC("lsm.s/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size){

    if (cmd != 5)
        return 0;

    __u32 insn_cnt;
    struct bpf_dynptr dptr_org;
    struct bpf_dynptr dptr_org_sig;

    __u32 proc_id = bpf_get_current_pid_tgid() >> 32;
    __u32 thread_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    __u32 keyring_search_map_key = 0;

    __u32 * sign_keyring_id = bpf_map_lookup_elem(&exfil_security_keyring_map, &keyring_search_map_key);
    if (!sign_keyring_id) {
        return 0;
    }

    struct modified_sig *mod_data = bpf_map_lookup_elem(&exfil_security_modified_signature, &keyring_search_map_key);
    if (!mod_data)
        return 0;


    struct original_data *org_data = bpf_map_lookup_elem(&exfil_security_original_program, &keyring_search_map_key);
    if (!org_data)
        return 0;
    
    if (bpf_probe_read_kernel(&insn_cnt, sizeof(insn_cnt), &attr->insn_cnt) < 0) {
        return -EPERM;
    }

    if (mod_data->sig_len > sizeof(mod_data->sig) ||
            org_data->data_len > sizeof(org_data->data) ||
            org_data->sig_len > sizeof(org_data->sig))
        return -EINVAL;

    if (bpf_dynptr_from_mem(&org_data->data, org_data->data_len, 0, &dptr_org) < 0) {
        return -E2BIG;
    }
    org_data->sig_len &= MAX_SIG_SIZE - 1;

    if (bpf_dynptr_from_mem(&mod_data->sig, org_data->sig_len, 0, &dptr_org_sig) < 0) {
        return -E2BIG;
    }
    mod_data->sig_len &= MAX_SIG_SIZE - 1;


    struct bpf_key * trusted_keyring;

    // trusted_keyring = bpf_lookup_user_key(*sign_keyring_id, 0);
    // if (!trusted_keyring) {
    //     return -ENOENT;
    // }

    // TODO: Port the custom LSM security written to be integrated with the core kernel exfil security framework
    bpf_printk("the ebpf sign key found");
    bpf_printk("the lsm crypto verification hook called over BPF_PROG_LOAD kernel syscall %d ins ct %d, sig size %d", 
                        *sign_keyring_id, insn_cnt, org_data->sig_len);
    // bpf_key_put(trusted_keyring);

    return 0;
}


char _license[] SEC("license") = "GPL";
