#ifndef __VXLAN_H 
    #define  __VXLAN_H 

#include <linux/in.h>
#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
    
#include "consts.h"
#include "dns.h"

//  8 bit offset for the reserved (vxlan >> 24) & (VXLAND_I_OFFSET_BIT)
#define VXLAN_RD_VNI_FLAG 0x08
#define VXLAN_RESERVED_OFFSET_BITS_MASK 0xffffff

//    VXLAN Header:
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |R|R|R|R|I|R|R|R|            Reserved                           |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                VXLAN Network Identifier (VNI) |   Reserved    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct vxlanhdr {
    __u32 vx_flags;    /* VXLAN flags, covering header process flags */
    __u32 vx_vni;      /* 24-bit VXLAN Network Identifier  + Kernel Reserved flags*/
};

static
__always_inline __u8 __parse_vxlan_flag__hdr(void *transport_data, struct vxlanhdr *vxlan_hdr, void *data_end) {
    __u32 flags_vxlan_hdr = bpf_ntohl(vxlan_hdr->vx_flags);
    if (DEBUG) 
        bpf_printk("parsing the vxlan header %u", flags_vxlan_hdr);
    if ((void *) flags_vxlan_hdr + sizeof(__be32) > data_end) return 0;
    // an valid I sender flag set denoting sender for the vxlan packet 
    __u32 offset_vxlan_flags = flags_vxlan_hdr & VXLAN_RESERVED_OFFSET_BITS_MASK;
    if ((((flags_vxlan_hdr >> 24) & VXLAN_RD_VNI_FLAG) >> 3) == 1) return 1;

    return 0;
}

static 
__always_inline __u32 __parse_vxlan_vni_hdr(void *transport_payload, struct vxlanhdr *vxlan_hdr, void *data_end) {
    __u32 vni = bpf_ntohs(vxlan_hdr->vx_vni) >> 8;  

    __u32 resrvered = bpf_ntohs(vxlan_hdr->vx_vni) & 0xff;
    #ifdef DEBUG 
        bpf_printk("ADDR Resereved flag %d and VNI %d",resrvered, vni);
    #endif

    return vni;
}


#endif /* __VXLAN_H */ 


