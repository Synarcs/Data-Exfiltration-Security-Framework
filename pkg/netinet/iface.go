package netinet

import (
	"fmt"
	"log"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	NETNS_RNETLINK_EGREESS_DPI = "sx1"
	NETNS_RNETLINK_INGRESS_DPI = "sx2"

	NETNS_NETLINK_BRIDGE_DPI = "br0"
)

// each link has net_device virt / physical socket -> netlink -> netfilter -> contrack -> tc (classful / classless) -> xdp -> net_device
type NetIface struct {
	Links         []netlink.Link // netlink liks for all links on the device
	PhysicalLinks []netlink.Link // physical veth links with hardware mac and MTU as (1500)
	BridgeLinks   []netlink.Link // links created specifically for bridge kernel utils and DPI over bridge traffic
	LoopBackLinks []netlink.Link // loopback links
	Routes        map[string][]netlink.Route
}

func (nf *NetIface) ReadInterfaces() error {
	links, err := netlink.LinkList()
	if err != nil {
		log.Println(err)
		return err
	}
	customLinks := make([]netlink.Link, 0)

	for _, link := range links {
		if link.Attrs().Name == "enp0s1" {
			fmt.Println("found a link ", link.Attrs().Name)
			customLinks = append(customLinks, link)
		}
	}

	fmt.Println("the custom link to process are ", customLinks)
	nf.Links = links
	hardwareInterfaces, logicalInterfaces, bridgeInterfaces := nf.findLinkAddressByType()
	if len(hardwareInterfaces) > 0 {
		nf.PhysicalLinks = hardwareInterfaces
	}
	if len(logicalInterfaces) > 0 {
		nf.LoopBackLinks = logicalInterfaces
	}
	if len(bridgeInterfaces) > 0 {
		nf.BridgeLinks = bridgeInterfaces
	}
	return nil
}

func (nf *NetIface) ReadRoutes() error {

	for _, link := range nf.Links {
		routes, err := netlink.RouteList(link, unix.ETH_P_ALL)
		if err != nil {
			log.Println(err)
			return err
		}
		nf.Routes[link.Attrs().Name] = routes
	}
	return nil
}


func (nf *NetIface) findLinkAddressByType() ([]netlink.Link, []netlink.Link, []netlink.Link) {
	hardwardIntefaces := make([]netlink.Link, 0)
	loopBackInterface := make([]netlink.Link, 0) // ensure a single loopback for self loopback link
	bridgeInterfaces := make([]netlink.Link, 0)
	for _, link := range nf.Links {
		_, isEth := link.(*netlink.Device)
		attrs := link.Attrs()

		// Exclude virtual interfaces (e.g., loopback, bridge, vlan, etc.)
		isVirtual := attrs.OperState == netlink.OperNotPresent ||
			attrs.Flags&net.FlagLoopback != 0
			// attrs.Name == "lo"

		isLoopBack := attrs.EncapType == "loopback" || attrs.Name == "lo"
		if isEth && !isVirtual && !isLoopBack {
			hardwardIntefaces = append(hardwardIntefaces, link)
		}
		if isLoopBack {
			loopBackInterface = append(loopBackInterface, link)
		}
		if link.Attrs().Name == NETNS_NETLINK_BRIDGE_DPI {
			bridgeInterfaces = append(bridgeInterfaces, link)
		}
	}
	return hardwardIntefaces, loopBackInterface, bridgeInterfaces
}

func (nf *NetIface) GetNetworkNamespace(route string) (*netns.NsHandle, error) {
	var netHandle netns.NsHandle
	var err error
	if route == "egress" {
		netHandle, err = netns.GetFromName(NETNS_RNETLINK_EGREESS_DPI)
	} else {
		netHandle, err = netns.GetFromName(NETNS_RNETLINK_INGRESS_DPI)
	}
	if err != nil {
		// log.Fatalf("Error Mounting the required Netns for traffic Egress TC DPI")
		return nil, err
	}
	if !netHandle.IsOpen() {
		return nil, fmt.Errorf("Error the required Netns needs to be mounted and open to bridge")
	}

	defer netHandle.Close()
	return &netHandle, nil
}
