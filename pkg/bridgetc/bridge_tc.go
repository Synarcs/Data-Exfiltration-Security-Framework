package bridgetc

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/crypto"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
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

type BridgeTCFilters struct {
	TCBridgeSocketMap *ebpf.Map
	Interfaces        *netinet.NetIface
	Hash              *crypto.Hash
}

func (btc *BridgeTCFilters) AttachTcHandler(ctx context.Context, prog *ebpf.Program, isEgress bool) error {

	for _, link := range btc.Interfaces.BridgeLinks {
		log.Println("Attaching TC qdisc to the interface ", link.Attrs().Name)
		_, err := netlink.QdiscList(link)
		if err != nil {
			panic(err.Error())
		}

		log.Println("Attaching a qdisc handler for the bridge")
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

		tcBridgeFilter := netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           prog.FD(),
			Name:         prog.String(),
			DirectAction: true,
		}

		if isEgress {
			tcBridgeFilter.FilterAttrs.Parent = netlink.HANDLE_MIN_EGRESS
		} else {
			tcBridgeFilter.FilterAttrs.Parent = netlink.HANDLE_MIN_INGRESS
		}

		if err := netlink.FilterReplace(&tcBridgeFilter); err != nil {
			panic(err.Error())
		}
	}
	return nil
}

func (btc *BridgeTCFilters) AttachTcHandlerIngressBridge(ctx context.Context, isEgress bool) {
	log.Println("Attaching the netfilter hook in kernel for ingress bridge PreRouting traffic")

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err.Error())
	}

	handler, err := utils.ReadEbpfFromSpec(ctx, utils.NF_EGRESS_BRIDGE_NETIFACE_INT)

	if errors.Is(ctx.Err(), context.Canceled) {
		log.Println("Tc Egress Handler Qdisc Attach Event cancelled due to root context cancellation ...")
		return
	}

	if err != nil {
		panic(err.Error())
	}

	spec, err := ebpf.NewCollection(handler)
	if err != nil {
		panic(err)
	}

	tcBridgeSkHash := spec.Maps[events.EXFIL_TC_BRIDGE_CONFIG_MAP]
	var tc_bridge_hash_key uint32 = 0

	if err := tcBridgeSkHash.Put(&tc_bridge_hash_key, &btc.Hash.SkbHash); err != nil {
		var defaultHash uint32 = utils.DEFAULT_SK_BUFF_NUONCE
		tcBridgeSkHash.Put(&tc_bridge_hash_key, &defaultHash)
	}

	var prog *ebpf.Program
	if isEgress {
		prog = spec.Programs[utils.TC_CONTROL_PROG_BRIDGE_INGRESS]
	} else {
		prog = spec.Programs[utils.TC_CONTROL_PROG_BRIDGE_EGRESS]
	}
	if prog == nil {
		if isEgress {
			panic(fmt.Errorf("No Required TC Hook found for DNS egress %s", utils.TC_CONTROL_PROG_BRIDGE_EGRESS))
		} else {
			panic(fmt.Errorf("No Required TC Hook found for DNS egress %s", utils.TC_CONTROL_PROG_BRIDGE_INGRESS))
		}
	}

	defer spec.Close()

	if err := btc.AttachTcHandler(ctx, prog, isEgress); err != nil {
		log.Println("Error attaching the clsact bpf qdisc for netdev")
		panic(err.Error())
	}

	if err := btc.AttachTcHandler(ctx, prog, isEgress); err != nil {
		log.Println("Error attaching the clsact bpf qdisc for netdev")
		panic(err.Error())
	}

	btc.TCBridgeSocketMap = spec.Maps[events.EXFIL_TC_BRIDGE_CONFIG_MAP]
	if btc.TCBridgeSocketMap == nil {
		panic(fmt.Errorf("No Required TC Bridge Socket Map found for %s", events.EXFIL_TC_BRIDGE_CONFIG_MAP))
	}

}

func (btc *BridgeTCFilters) DetachKernelBridgeTCFilters(ctx *context.Context) error {
	for _, link := range btc.Interfaces.BridgeLinks {
		err := netlink.QdiscDel(&netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
			},
		})
		if err != nil {
			log.Println("No Matching clsact desc found to delete")
			return err
		}
	}
	return nil
}
