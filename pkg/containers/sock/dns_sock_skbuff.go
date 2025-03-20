package sock

/*
	Use bpf links to inject all kernel sock op programs from kernel skb_filter to kernel skb_ops cgroups etc
*/
import (
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"runtime"
	"sync"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// guard the hook injection as atomic counter, an eBPF sockops filter in kernel cannot be injected multiple times since it applies global sock filter for entire pod network
var isInjectedKernelHooks bool = false
var injectKernelHookGaurd sync.Mutex

type SockKernelProgs struct {
	Progs []*ebpf.Program
	Maps  []*ebpf.Map
	Links []*link.Link
}

func (sock *SockKernelProgs) InitEpfSockProg(ctx context.Context) (*ebpf.Collection, error) {
	handler, err := utils.ReadEbpfFromSpec(ctx, utils.SOCK_SKB_OP_CODE_EBPF)
	if err != nil {
		return nil, err
	}

	spec, err := ebpf.NewCollectionWithOptions(handler, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: utils.PINPATH,
		},
	})

	if err != nil {
		return nil, err
	}

	return spec, err
}

func (sock *SockKernelProgs) InjectKernelSockOps(ctx context.Context, bpfMountPath string, sockeBPFProg string) error {
	log.Println("Injecting the sock Ops for UDP sock trace for the current kernel not supporting task_comm in egress Tc ")

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("Cannot Inject programs when the parent context for node agent is cancelled %s", ctx.Err())
	}

	runtime.LockOSThread()
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	spec, err := sock.InitEpfSockProg(ctx)

	if err != nil {
		return err
	}
	defer spec.Close()

	prog := spec.Programs[utils.SOCK_OPS_PROC_UDP_TRACEPOINT]
	if prog == nil {
		panic("program not found")
	}

	cgroup, err := os.Open(utils.CGROUPFS)
	if err != nil {
		return err
	}
	defer cgroup.Close()

	cgroupSockOp, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: prog,
	})

	if err != nil {
		return err
	}

	sock.Progs = append(sock.Progs, prog)
	sock.Links = append(sock.Links, &cgroupSockOp) // fd for the kernel to inject the cgroup

	return nil
}

// add the sock filters for the pod called by k8s mutation webhook on pod-create to ensure proper DNS security and DPI in kernel
// only injects all the sock_skb, sock_sock_ops, eBPF kernel programs inside the pod networking running all on the phsyical net_device
func (sock *SockKernelProgs) InjectKernelSocketFilters(ctx context.Context, bpfMountPath string, sockeBPFProg string, isContainers bool) error {
	// check if this running over the older kernel

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("Cannot Inject programs when the parent context for node agent is cancelled %s", ctx.Err())
	}

	log.Println("Received Pod Mutation request Kernel Exfiltration guard eBPf sock programs in kernel")
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	injectKernelHookGaurd.Lock()
	defer injectKernelHookGaurd.Unlock()

	if !isInjectedKernelHooks {
		if isContainers {
			eBPFProgSockPath := path.Join(bpfMountPath, sockeBPFProg)
			if _, err := os.Stat(eBPFProgSockPath); err != nil {
				return fmt.Errorf("Error the eBPF program cannot be found %s", eBPFProgSockPath)
			}
			// handler, err := ebpf.LoadCollectionSpec(path.Join(POD_EBPF_PROGRAM_MOUNT_PATH, SOCK_SKB_FILTER))
			isInjectedKernelHooks = true
		}
		return nil
	}

	return fmt.Errorf("SK_BUFF sock eBPF filters can be only injected once")
}

// removes all the sock filters over sock and cgroup attached in kernel
func (sock *SockKernelProgs) DetachKernelSockProg(ctx context.Context) error {
	for _, link := range sock.Links {
		if link != nil {
			(*link).Close()
		}
	}

	// Close all programs
	for _, prog := range sock.Progs {
		if prog != nil {
			prog.Close()
		}
	}

	// the root kernel tc filter over egress unpin all the kernel maps to release all the fd over bpf fs
	return nil
}
