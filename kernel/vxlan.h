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
    __be32 vx_flags;    /* VXLAN flags, covering header process flags */
    __be32 vx_vni;      /* 24-bit VXLAN Network Identifier  + Kernel Reserved flags*/
};

__u8 __parse_vxlan_flag__hdr(void *transport_data, struct vxlanhdr *vxlan_hdr, void *data_end) {
    __u32 flags_vxlan_hdr = bpf_ntohl(vxlan_hdr->vx_flags);
    if (DEBUG) 
        bpf_printk("parsing the vxlan header %u", flags_vxlan_hdr);
    if ((void *) flags_vxlan_hdr + sizeof(__be32) > data_end) return 0;
    // an valid I sender flag set denoting sender for the vxlan packet 
    __u32 ff = (flags_vxlan_hdr >> 24) & VXLAN_RD_VNI_FLAG;
    __u32 offset_vxlan_flags = flags_vxlan_hdr & VXLAN_RESERVED_OFFSET_BITS_MASK;
    if ((ff >> 3) == 1) return 1;

    return 0;
}


__u32 __parse_vxlan_vni_hdr(void *transport_payload, struct vxlanhdr *vxlan_hdr, void *data_end) {
    __u32 vxlan_vni = bpf_ntohl(vxlan_hdr->vx_vni);
    __u32 vni = vxlan_vni >> 8;  // upper bits for vni header 

    __u8 reserved = vxlan_vni & 0xf;
    if (!DEBUG) {
        bpf_printk("VNI: %d\n", vni);
    }
    return vni;
}


#endif /* __VXLAN_H */ 


