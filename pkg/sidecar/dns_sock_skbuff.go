package sidecar

import (
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func InjectKernelSocketFilters() error {
	// only injects all the sock_skb, sock_sock_ops, eBPF kernel programs inside the pod networking running all on the phsyical net_device
	// for traffic over virtual encap link inside pod tc noqueue direct-action filter is use as forward action filter for the tc no queue
	log.Println("Received Pod Mutation request Kernel Exfiltration guard eBPf sock programs in kernel")
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	handler, err := ebpf.LoadCollectionSpec(SOCK_SKB_FILTER)
	if err != nil {
		return err
	}

	for _, ebpfSockMaps := range handler.Maps {
		log.Println(ebpfSockMaps.Name, ebpfSockMaps.Type.String())
	}

	return nil
}
