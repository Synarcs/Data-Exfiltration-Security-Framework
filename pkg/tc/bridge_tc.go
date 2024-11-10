package tc

import (
	"context"
	"fmt"
	"log"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// kernel traffic control over the bridge for traffic routing
// the brdige is used for the ingress and egress traffic routing over all custom Network Namespaces and Interfaces created for Veth overlay DPI traffic
// TODO: convert to generics

func (tc *TCHandler) AttachTcHandlerIngressBridge(ctx *context.Context, prog *ebpf.Program, isEgress bool) error {

	for _, link := range tc.Interfaces.BridgeLinks {
		_, err := netlink.QdiscList(link)
		if err != nil {
			panic(err.Error())
		}

		log.Println("Attaching a qdisc handler for bridge interface")
		qdisc_clsact := &netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(0xffff, 0),
			},
		}
		if err := netlink.QdiscReplace(qdisc_clsact); err != nil {
			panic(err.Error())
		}

		var filter netlink.BpfFilter
		if !isEgress {
			filter = netlink.BpfFilter{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: link.Attrs().Index,
					Parent:    netlink.HANDLE_MIN_EGRESS,
					Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
					Protocol:  unix.ETH_P_ALL,
				},
				Fd:           prog.FD(),
				Name:         prog.String(),
				DirectAction: true,
			}
		} else {
			filter = netlink.BpfFilter{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: link.Attrs().Index,
					Parent:    netlink.HANDLE_MIN_EGRESS,
					Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
					Protocol:  unix.ETH_P_ALL,
				},
				Fd:           prog.FD(),
				Name:         prog.String(),
				DirectAction: true,
			}
		}

		if isEgress {
			log.Println("Attaching the qdis for egress traffic routing")
		} else {
			log.Println("Attaching the qdis for ingress traffic routing")
		}
		if err := netlink.FilterReplace(&filter); err != nil {
			log.Printf("Error attaching the qdisc handler for bridge over route direction %+v %v", err, isEgress)
			return err
		}
	}
	return nil
}

func (tc *TCHandler) TcHandlerEbfpProgBridge(ctx *context.Context, iface *netinet.NetIface) error {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("The ebpf node agent cannot reserve memory to load the ebpf program in kernel %+v", err)
	}

	handler, err := tc.ReadEbpfFromSpec(ctx, TC_EGRESS_BRIDGE_NETIFACE_INT)

	if err != nil {
		log.Printf("Error loading the ebpf program for tc ingress bridge %+v", err)
		return err
	}

	spec, err := ebpf.NewCollection(handler)
	if err != nil {
		log.Printf("error generating the collection from ebpf compiled sections %+v", err)
		return err
	}

	if !utils.DEBUG {
		log.Println(spec)
		for _, maps := range spec.Maps {
			log.Println("Bridge TC Handler Ingress ++", maps.String())
		}
	}

	if err := tc.AttachTcHandlerIngressBridge(ctx, spec.Programs[utils.TC_CONTROL_PROG_BRIDGE], false); err != nil {
		log.Printf("Error attaching the ebpf program for tc ingress bridge %+v", err)
		return err
	}

	return nil
}

func (tc *TCHandler) DetachHandlerBridge(ctx *context.Context) error {
	for _, link := range tc.Interfaces.BridgeLinks {
		err := netlink.QdiscDel(&netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
			},
		})
		if err != nil {
			fmt.Println("No Matching clsact desc found to delete")
		}
	}
	return nil
}
