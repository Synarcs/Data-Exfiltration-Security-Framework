/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package kprobe

import (
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils/agenterr"
	"github.com/cilium/ebpf"
)

// implements support for wiregauard traffic netdev (encap creation hooks) for exfiltration over tunnels with advanced netdev devlink associated coorelation with the core exfil attempts

// core kernel introspection for wireguard tunnels
const (
	WG_DEV_OPEN  = "wg_open"
	WG_DEV_XMIT  = "wg_xmit"
	WG_DEV_CLOSE = "wg_close"
)

type WireguardKprobes struct {
	KprobesEDRAgentComm
	WireguardSockprog *ebpf.Program
}

func NewWgKprobes(globalErrorChannel chan<- *agenterr.AgentError, iface *netinet.NetIface) *WireguardKprobes {
	return &WireguardKprobes{
		KprobesEDRAgentComm: KprobesEDRAgentComm{
			GlobalErrorKernelChan: globalErrorChannel,
			Iface:                 iface,
		},
	}
}
