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

SEC("lsm.s/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size){
    
    if (cmd != BPF_PROG_LOAD)
        return 0;

    __u32 proc_id = bpf_get_current_pid_tgid() >> 32;
    __u32 thread_id = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    __u32 keyring_search_map_key = 0;

    __u32 * sign_keyring_id = bpf_map_lookup_elem(&exfil_security_keyring_map, &keyring_search_map_key);
    if (!sign_keyring_id) {
        return 0;
    }
    bpf_printk("the lsm crypto verification hook called over BPF_PROG_LOAD kernel syscall %d", *sign_keyring_id);
    return 0;
}


char _license[] SEC("license") = "GPL";
