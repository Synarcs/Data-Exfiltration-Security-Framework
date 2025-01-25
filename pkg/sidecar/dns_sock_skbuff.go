package sidecar

import (
	"fmt"
	"log"
	"os"
	"path"
	"sync"

	"github.com/cilium/ebpf/rlimit"
)

// guard the hook injection as atomic counter, an eBPF sockops filter in kernel cannot be injected multiple times since it applies global sock filter for entire pod network
var isInjectedKernelHooks bool = false
var injectKernelHookGaurd sync.Mutex

type InjectKernelSockPrograms struct {
}

// add the sock filters for the pod called by k8s mutation webhook on pod-create to ensure proper DNS security and DPI in kernel
// only injects all the sock_skb, sock_sock_ops, eBPF kernel programs inside the pod networking running all on the phsyical net_device
func InjectKernelSocketFilters() error {

	log.Println("Received Pod Mutation request Kernel Exfiltration guard eBPf sock programs in kernel")
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	injectKernelHookGaurd.Lock()
	defer injectKernelHookGaurd.Unlock()

	if !isInjectedKernelHooks {
		eBPFProgSockPath := path.Join(POD_EBPF_PROGRAM_MOUNT_PATH, SOCK_SKB_FILTER)
		if _, err := os.Stat(eBPFProgSockPath); err != nil {
			return fmt.Errorf("Error the eBPF program cannot be found %s", eBPFProgSockPath)
		}
		// handler, err := ebpf.LoadCollectionSpec(path.Join(POD_EBPF_PROGRAM_MOUNT_PATH, SOCK_SKB_FILTER))
		isInjectedKernelHooks = true
		return nil
	}

	return fmt.Errorf("SK_BUFF sock eBPF filters can be only injected once")
}

// remove the sock filters for the pod called by k8s mutation webhook on pod-delete to ensure proper cleanup
// filters sock runs in kernel and applies to all the container inside the pod, managed by single network ns in kernel
func DetachKernelSockFilters() error {

	return nil
}
