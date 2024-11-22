
#include "vmlinux.h"
#include <linux/bpf.h> 
#include <linux/if_ether.h> 
#include <linux/netdevice.h> 

// same kernel netfilter forward propogration hooks used in nf filter pkt drop kernel module 
struct bpf_nf_ctx {
    const struct nf_hook_state *state; 
    struct __sk_buff *skb;
};

struct nf_hook_state {
	__u8 hook;
	__u8 pf;
	struct net_device *in; // kernel ingress net_device link / port for virtualized bridge managed , pre routing
	struct net_device *out; // kernel egress net_device link / port for virtualized bridge managed interface
	struct sock *sk;
	struct net *net;
	int (*okfn)(struct net *, struct sock *, struct sk_buff *);
};