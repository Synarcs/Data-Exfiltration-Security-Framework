/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package conntrack

import (
	"net/netip"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
)

type ConntrackSock struct {
	ConntrackSock *conntrack.Conn
}

type ConntrackCleanEntry struct {
	SrcAddress netip.Addr
	DestAddres netip.Addr
	Protocol   uint8
	SrcPort    uint16
	Destport   uint16
}

func NewContrackSock(netns int) (*ConntrackSock, error) {
	c, err := conntrack.Dial(&netlink.Config{
		NetNS: 0,
	})
	if err != nil {
		utils.Log("Error Getting the the Contrack Netlink Socket")
		return nil, err
	}

	utils.Log("Init complete for Conntrack Socket over Netlink socket for Network Namespace ", netns)

	if utils.DEBUG {
		stats, _ := c.Stats()
		for _, stat := range stats {
			utils.Log("Successfully Booted with Kernel Conntrack Fd over Netlink sock", stat.String())
		}
	}

	return &ConntrackSock{
		ConntrackSock: c,
	}, nil
}

func (c *ConntrackSock) CleanCloneDanglingEntries(flowEntry *ConntrackCleanEntry) error {
	flow := conntrack.Flow{
		TupleOrig: conntrack.Tuple{
			IP: conntrack.IPTuple{
				SourceAddress:      flowEntry.SrcAddress, // IPv6 address
				DestinationAddress: flowEntry.DestAddres, // IPv6 address
			},
			Proto: conntrack.ProtoTuple{
				Protocol:        flowEntry.Protocol,
				SourcePort:      flowEntry.SrcPort,
				DestinationPort: flowEntry.Destport,
			},
		},
	}

	if utils.DEBUG {
		flows, _ := c.ConntrackSock.Dump(&conntrack.DumpOptions{})
		for _, flow := range flows {
			utils.Log("flow for the naetwork ns ", flow)
		}
	}

	if c.ConntrackSock == nil {
		utils.Log("Error ther con sock cannot be empty")
		return nil
	}
	if utils.DEBUG {
		utils.Log("Cleaning dest conntrack entry for the flow entry ", flowEntry)
	}
	if err := c.ConntrackSock.Delete(flow); err != nil {
		return err
	}
	return nil
}

func (c *ConntrackSock) CloseConntrackNetlinkSock() error {
	if err := c.ConntrackSock.Close(); err != nil {
		return err
	}
	return nil
}
