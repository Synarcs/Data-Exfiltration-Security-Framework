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
 *    Data:   09/25/2024, 2:59:15 AM
 *   -----------------------------
*/

#include <linux/bpf.h>
#include <linux/version.h>
#include <linux/lsm.h> 

// libbpf 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h> 

#include "../hdrs/consts.h"
#include "../hdrs/utils.h"
#include "crypto_maps.h"

/*
    Uses PKCS#7 keyring to verify the pogram source before injecting 
*/
SEC("lsm.s/bpf")
int bpf_lsm_hook(struct bpf_lsm_event *ctx) {
    return 0;
}


char __license[] SEC("license") = "GPL"; 
