/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package bridgetc

import (
	"context"
	"errors"
	"fmt"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/crypto"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils/agenterr"
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
	col               *ebpf.Collection
	globalErrorChan   chan agenterr.AgentError
}

// netlink brink links at the endpoint , and unique skb hash per netflow
func NewBridgeTCFilters(ifaceHandler *netinet.NetIface,
	hash *crypto.Hash, globalErrorChan chan agenterr.AgentError) *BridgeTCFilters {
	return &BridgeTCFilters{
		Hash:            hash,
		Interfaces:      ifaceHandler,
		globalErrorChan: globalErrorChan,
	}
}

// Attach Tc qdisc over prior legacy TC as clsact qdisc and ebpf filter
// TODO: add biderectional support for TCX and netkit  later over veth bridge pair on netdev for faster SKB enqueue and IRQ less overhead over moving SKB across netdev (east-west traffic)
func (btc *BridgeTCFilters) AttachTcHandler(ctx context.Context,
	prog *ebpf.Program, isEgress bool) error {
	if utils.VerifyTcxSupportEgressLink() {
		// TODO: the custom netdev and linux namespace must also support tcx over bridge netdev in kernel
		// return nil
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	for _, link := range btc.Interfaces.BridgeLinks {
		utils.Log("Attaching TC qdisc to the interface ", link.Attrs().Name)
		_, err := netlink.QdiscList(link)
		if err != nil {
			return err
		}

		utils.Log("Attaching a qdisc handler for the bridge")
		qdisc_clsact := &netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(0xffff, 0),
			},
		}
		if err := netlink.QdiscReplace(qdisc_clsact); err != nil {
			return err
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
			return err
		}
	}
	return nil
}

func (btc *BridgeTCFilters) AttachTcHandlerIngressBridge(ctx context.Context, isEgress bool) {
	utils.Log("Attaching the TC CLSACT qdisc for ingress bridge")

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err.Error())
	}

	handler, err := utils.ReadEbpfFromSpec(ctx, utils.NF_EGRESS_BRIDGE_NETIFACE_INT)

	if errors.Is(ctx.Err(), context.Canceled) {
		utils.Log("Tc Egress Handler Qdisc Attach Event cancelled due to root context cancellation ...")
		return
	}

	if err != nil {
		panic(err.Error())
	}

	spec, err := ebpf.NewCollectionWithOptions(handler, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: utils.PINPATH,
		},
	})

	btc.col = spec
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
		utils.Log("Error attaching the clsact bpf qdisc for netdev")
		btc.globalErrorChan <- agenterr.EmitNewError(
			err, "BRIDGE_TC", fmt.Sprintf("error attaching egress TC program on bridge interface %s", utils.TC_CONTROL_PROG_BRIDGE_EGRESS),
		)
		return
	}

	if err := btc.AttachTcHandler(ctx, prog, isEgress); err != nil {
		utils.Log("Error attaching the clsact bpf qdisc for netdev")
		btc.globalErrorChan <- agenterr.EmitNewError(
			err, "BRIDGE_TC", fmt.Sprintf("error attaching TC handler to the custom veth bridge %s", utils.TC_CONTROL_PROG_BRIDGE_INGRESS),
		)
		return
	}

	btc.TCBridgeSocketMap = spec.Maps[events.EXFIL_TC_BRIDGE_CONFIG_MAP]
	if btc.TCBridgeSocketMap == nil {
		btc.globalErrorChan <- agenterr.EmitNewError(
			fmt.Errorf("no Required TC Bridge Socket Map found for %s", events.EXFIL_TC_BRIDGE_CONFIG_MAP), "BRIDGE_TC", "",
		)
	}
}

func (btc *BridgeTCFilters) DetachKernelBridgeTCFilters(ctx *context.Context) error {
	defer btc.col.Close()

	for _, link := range btc.Interfaces.BridgeLinks {
		err := netlink.QdiscDel(&netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
			},
		})
		if err != nil {
			utils.Log("No Matching clsact desc found to delete")
			return err
		}
	}

	if err := utils.UnPinPinnedMaps(btc.col, []string{events.EXFIL_TC_BRIDGE_CONFIG_MAP}); err != nil {
		return err
	}

	return nil
}
