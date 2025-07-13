/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package netinet

import (
	"context"
	"net"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

// core bridge link utils to find free ipam disjoint from core netdev l3 addr
// use netlink to find discrete ipam over all briges and links on the device for discete IPAM over the virtual NS and bridges ofr the Deep scan

// TODO: create overlay networking  for overlay l3/l2 bridge (veth) balancing virtual network ns
type IpamBlock struct {
	CidrRange   net.IP
	SubnetRange int
	IsIpv4      bool
	Iface       *NetIface
}

func (ipam *NetIface) LookUpdiscreteIpv4(ctx context.Context) (*IpamBlock, error) {
	routes := ipam.AddrV4
	for _, route := range routes {
		utils.Log(route)
	}
	return nil, nil
}

func (ipam *NetIface) LookUpdiscreteIpv6(ctx context.Context) (*IpamBlock, error) {
	routes := ipam.AddrV4
	for _, route := range routes {
		utils.Log(route)
	}
	return nil, nil
}
