/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package netinet

import (
	"fmt"
	"log"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// TODO: Let the agent at the endpoint use the netlink socket for creatign spine, bridge and overlay network bridge topology
func (nf *NetIface) CreateNamespace(nsName string) {
	_, err := netns.NewNamed(nsName)
	if err != nil {
		utils.Logger.Fatalf("Failed to create namespace %s: %v", nsName, err)
	}
	utils.Log(fmt.Sprintf("Created namespace: %s\n", nsName))
}

func (nf *NetIface) AttachVethNamespace(veth, nsName string) error {
	nsHandle, _ := netns.GetFromName(nsName)

	defer nsHandle.Close()
	link, err := netlink.LinkByName(veth)

	if err != nil {
		utils.Logger.Printf("Failed to get link %s: %v", veth, err)
		return err
	}

	if err := netlink.LinkSetNsFd(link, int(nsHandle)); err != nil {
		log.Fatalf("Failed to set veth %s to namespace %s: %v", veth, nsName, err)
	}
	utils.Log(fmt.Sprintf("Set %s to namespace %s\n", veth, nsName))
	return nil
}

func (nf *NetIface) CreateBridge(bridgeName string) error {
	return nil
}
