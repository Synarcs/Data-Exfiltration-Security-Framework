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

type WireguardExfil struct {
	WireguardSockprog *ebpf.Program
	Devlink           *netinet.NetIface
}

func (wg *WireguardExfil) InitKernelWgHooks() error {
	return nil
}
