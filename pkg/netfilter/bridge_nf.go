package netfilter

import (
	"context"
	"log"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/tc"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// kernel traffic control over the bridge for traffic routing
// the brdige is used for the ingress and egress traffic routing over all custom Network Namespaces and Interfaces created for Veth overlay DPI traffic
// TODO: convert to generics

type NetFilter struct {
	NfBridgeProg             *ebpf.Program
	NetfilterBridgeSocketMap *ebpf.Map
	Link                     link.Link
	Interfaces               *netinet.NetIface
}

func (nf *NetFilter) AttachTcHandlerIngressBridge(ctx context.Context, isEgress bool) error {
	log.Println("Attaching the netfilter hook in kernel for ingress bridge PreRouting traffic")

	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	handler, err := ebpf.LoadCollectionSpec(tc.NF_EGRESS_BRIDGE_NETIFACE_INT)
	if err != nil {
		log.Printf("error loading the netfilter program: %v", err)
		return err
	}

	var objs struct {
		NetfilterBridgeSocket    *ebpf.Program `ebpf:"bridge_classify"`
		NetfilterBridgeSocketMap *ebpf.Map     `ebpf:"exfil_nf_bridge_config_map"`
	}

	if err := handler.LoadAndAssign(&objs, nil); err != nil {
		log.Printf("error loading and assigning program: %v", err)
		return err
	}

	nf.NfBridgeProg = objs.NetfilterBridgeSocket
	nf.NetfilterBridgeSocketMap = objs.NetfilterBridgeSocketMap

	hookPoint := unix.NF_INET_PRE_ROUTING
	if isEgress {
		hookPoint = unix.NF_INET_POST_ROUTING
	}

	if len(nf.Interfaces.BridgeLinks) >= 1 {
		var nf_filter_const_key uint32 = 0
		var nf_bridgr_interface_if_index uint32 = uint32(nf.Interfaces.BridgeLinks[0].Attrs().Index)

		var nf_vns_bridge_config events.NetfilterMapConfig = events.NetfilterMapConfig{
			Bridge_if_index: nf_bridgr_interface_if_index,
			SKB_Mark:        utils.REDIRECT_SKB_MARK,
		}
		if err := nf.NetfilterBridgeSocketMap.Put(nf_filter_const_key, &nf_vns_bridge_config); err != nil {
			log.Printf("error inserting the netfilter bridge map: %v", err)
			return err
		}
	}
	nfLink, err := link.AttachNetfilter(link.NetfilterOptions{
		Program:        nf.NfBridgeProg,
		ProtocolFamily: unix.NFPROTO_IPV4,
		HookNumber:     uint32(hookPoint),
		Priority:       50, // Priority within hook for netfilter hook direction
	})

	if err != nil {
		log.Printf("Error attaching netfilter link: %v", err)
		return err
	}

	defer nf.NetfilterBridgeSocketMap.Clone()

	nf.Link = nfLink

	return nil
}

func (nf *NetFilter) DetachKernelBridgeNetfilterHook(ctx *context.Context) error {
	if nf.Link == nil {
		log.Println("The Kernel did not attacj the bridge netfilter hook for the ingress prerouting bridge")
		return nil
	}
	if err := nf.Link.Close(); err != nil {
		log.Println("error closing the netfilter link")
		return err
	}

	return nil
}
