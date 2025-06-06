/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package xdp

import (
	"context"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	TC_INGRESS_ROOT_NETIFACE_INT = "xdp.o"
)

type XdpHandler struct {
	Interfaces *netinet.NetIface // phsycal interfaces which kernel supports
}

func NewXdpHandler(interfaces *netinet.NetIface) *XdpHandler {
	return &XdpHandler{
		Interfaces: interfaces,
	}
}

func (xdp *XdpHandler) LinkXdp() error {
	handler, err := ebpf.LoadCollectionSpec(TC_INGRESS_ROOT_NETIFACE_INT)

	if err != nil {
		utils.Logger.Fatal("error loading the xdp program over interface")
		return err
	}

	spec, err := ebpf.NewCollection(handler)
	if err != nil {
		utils.Logger.Fatal("error loading the xdp program over interface")
		return err
	}

	if len(spec.Programs) > 1 {
		utils.Log("Multiple programs found in the root collection")
	}
	if len(spec.Programs) == 0 {
		utils.Log("The Ebpf Bytecode is corrupt or malformed")
	}

	defer spec.Close()
	prog := spec.Programs[utils.XDP_CONTROL_PROG]
	defer prog.Close()

	for _, links := range xdp.Interfaces.PhysicalLinks {
		go func() {
			l, err := link.AttachXDP(link.XDPOptions{
				Program:   prog,
				Interface: links.Attrs().Index,
			})
			if err != nil {
				utils.Log("Error attaching the XDP program to the interface")
				panic(err.Error())
			}

			defer l.Close()
		}()
	}
	return nil
}

func (xdp *XdpHandler) XdpHandler(ctx *context.Context, iface *netinet.NetIface) error {
	return nil
}
