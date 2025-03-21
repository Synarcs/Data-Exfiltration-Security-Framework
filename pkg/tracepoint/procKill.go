package tracepoint

import (
	"context"
	"log"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// most of the tracepoints will be injected post injection of kernel TC filter egress classless qdisc
type ExfilSecTreacePoint struct {
	SecurityKernelTracePoints []*ebpf.Program
	SecurityKernelMaps        []*ebpf.Map
	TracePointLink            []*link.Link
}

func GenerateTracePointHandlers() *ExfilSecTreacePoint {
	return &ExfilSecTreacePoint{}
}

func (exf *ExfilSecTreacePoint) AttachTracePointHandlers(ctx context.Context, iface *netinet.NetIface) {
	log.Println("Attaching the kernel Tracepoints")

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err.Error())
	}

	handler, err := utils.ReadEbpfFromSpec(ctx, utils.TRACEPOINT_KERNEL_PROG)
	if err != nil {
		panic(err)
	}

	spec, err := ebpf.NewCollectionWithOptions(handler, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: utils.PINPATH,
		},
	})
	if err != nil {
		panic(err)
	}

	prog := spec.Programs[utils.TRACEPOINT_PROC_KILL_TRACEPOINT]
	if prog == nil {
		panic("program not found")
	}

	// Attach to sched:sched_process_exit tracepoint
	tp, err := link.Tracepoint("sched", "sched_process_exit", prog, nil)
	if err != nil {
		panic(err)
	}

	// Store links for cleanup
	exf.TracePointLink = append(exf.TracePointLink, &tp)
}

func (exf *ExfilSecTreacePoint) RemoveTracepoints() error {
	// clean tracepoint attached to kernel raw tracepoints
	for _, link := range exf.TracePointLink {
		if link != nil {
			if err := (*link).Close(); err != nil {
				return err
			}
		}
	}

	// Close all programs
	for _, prog := range exf.SecurityKernelTracePoints {
		if prog != nil {
			if err := prog.Close(); err != nil {
				return err
			}
		}
	}

	exf.TracePointLink = nil
	exf.SecurityKernelTracePoints = nil
	exf.SecurityKernelMaps = nil

	return nil
}
