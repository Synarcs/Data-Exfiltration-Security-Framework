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
)

type NetIface struct {
	Links         []netlink.Link
	PhysicalLinks []netlink.Link
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
	hardwareInterfaces := nf.findPhysicalInterfaces()
	if len(hardwareInterfaces) > 0 {
		nf.PhysicalLinks = hardwareInterfaces
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

func (nf *NetIface) CreateNamespace(nsName string) {
	_, err := netns.NewNamed(nsName)
	if err != nil {
		log.Fatalf("Failed to create namespace %s: %v", nsName, err)
	}
	fmt.Printf("Created namespace: %s\n", nsName)
}

func (nf *NetIface) AttachVethNamespace(veth, nsName string) error {

	nsHandle, _ := netns.GetFromName(nsName)

	defer nsHandle.Close()
	link, err := netlink.LinkByName(veth)

	if err != nil {
		log.Printf("Failed to get link %s: %v", veth, err)
		return err
	}

	if err := netlink.LinkSetNsFd(link, int(nsHandle)); err != nil {
		log.Fatalf("Failed to set veth %s to namespace %s: %v", veth, nsName, err)
	}
	fmt.Printf("Set %s to namespace %s\n", veth, nsName)
	return nil
}

func (nf *NetIface) findPhysicalInterfaces() []netlink.Link {
	hardwardIntefaces := make([]netlink.Link, 0)
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
	}
	return hardwardIntefaces
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
