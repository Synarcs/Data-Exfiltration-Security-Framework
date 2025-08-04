/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package kprobe

import (
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
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
	WireguardSockprog *ebpf.Program
	Devlink           *netinet.NetIface // eBPF agent holding all link info collected from kernel using netlink
}

// TODO: WG kernel wireguard tunnel introspect eBPF agent co-related process information
func NewWgKprobes(globalErrorChannel chan error) *WireguardKprobes {
	return &WireguardKprobes{}
}
