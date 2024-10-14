package netinet

import (
	"fmt"
	"log"
	"net"
	"strings"
	"syscall"

	"github.com/asavie/xdp"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

const (
	NETNS_RNETLINK_EGREESS_DPI = "sx1"
	NETNS_RNETLINK_INGRESS_DPI = "sx2"

	NETNS_NETLINK_BRIDGE_DPI = "br0"
)

const (
	NETNS_RNETLINK_EGREESS_DPI_INTERFACE = "sx1-eth0"
	NETNS_RNETLINK_INGRESS_DPI_INTERFACE = "sx2-eth0"
)

var Iface_Bridge_Subnets map[string]string = map[string]string{
	NETNS_RNETLINK_EGREESS_DPI_INTERFACE: "10.200.0.1",
	NETNS_RNETLINK_INGRESS_DPI_INTERFACE: "10.200.0.2",
}

// each link has net_device virt / physical socket -> netlink -> netfilter -> contrack -> tc (classful / classless) -> xdp -> net_device
type NetIface struct {
	Links                 []netlink.Link // netlink liks for all links on the device
	PhysicalLinks         []netlink.Link // physical veth links with hardware mac and MTU as (1500)
	BridgeLinks           []netlink.Link // links created specifically for bridge kernel utils and DPI over bridge traffic
	LoopBackLinks         []netlink.Link // loopback links
	Routes                map[string][]netlink.Route
	Addr                  map[string][]netlink.Addr
	PhysicalRouterGateway net.IP
}

func (nf *NetIface) ReadInterfaces() error {
	links, err := netlink.LinkList()
	if err != nil {
		log.Println(err)
		return err
	}
	customLinks := make([]netlink.Link, 0)

	for _, link := range links {
		if link.Attrs().Name == "enp0s1" || strings.Contains(link.Attrs().Name, "eth") || strings.Contains(link.Attrs().Name, "enp") || strings.Contains(link.Attrs().Name, "wla") {
			log.Println("Physical links on the Node ", link.Attrs().Name)
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

func (nf *NetIface) GetRootGateway() error {
	if len(nf.Routes) == 0 {
		return fmt.Errorf("No routes found")
	}
	var gw net.IP
	physicalLink := nf.PhysicalLinks[0].Attrs().Name
	for _, val := range nf.Routes[physicalLink] {
		gw = val.Gw
		break
	}
	nf.PhysicalRouterGateway = gw
	return nil
}

func (nf *NetIface) ReadRoutes() error {
	nf.Addr = make(map[string][]netlink.Addr)
	nf.Routes = make(map[string][]netlink.Route)
	for _, link := range nf.PhysicalLinks {
		routes, err := netlink.RouteList(link, unix.ETH_P_ALL)
		if err != nil {
			log.Println(err)
			return err
		}
		addr, err := netlink.AddrList(link, unix.ETH_P_ALL)
		if err != nil {
			log.Println(err)
			return err
		}
		nf.Addr[link.Attrs().Name] = addr
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

	return &netHandle, nil
}

func (nf *NetIface) GetRootNamespace() (*netns.NsHandle, error) {

	rootNs, err := netns.Get()
	if err != nil {
		log.Println("[x] Error Getting the Root Namespace")
		return nil, err
	}
	return &rootNs, nil
}

func (nf *NetIface) GetRootNamespacePcapHandle() (*pcap.Handle, error) {

	cap, err := pcap.OpenLive(nf.PhysicalLinks[0].Attrs().Name, int32(nf.PhysicalLinks[0].Attrs().MTU), true, pcap.BlockForever)
	return cap, err
}

func (nf *NetIface) GetRootNamespaceRawSocketFdXDP() (*xdp.Socket, error) {
	log.Println("[x] Creating XDP socket fd to send packet")
	_, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		log.Println("Error in opening a raw socket fd to the bridge socket")
		return nil, err
	}

	// use the egress transfer queue to send the packet on the physical port inside kernel to make directly reach the interface bypass the kernel network stack
	txQueueId, err := GetCurrentTXQueues(nf.PhysicalLinks[0].Attrs().Name)
	if err != nil {
		log.Println("Error in getting the tx TX queue id")
		return nil, err
	}
	log.Println("the tx queue id is ", txQueueId, nf.PhysicalLinks[0].Attrs().Index)

	xdpSock, err := xdp.NewSocket(nf.PhysicalLinks[0].Attrs().Index, txQueueId, nil)
	if err != nil {
		log.Println("Error in binding the AF_XDP Socket to TX Queues")
		return nil, err
	}

	return xdpSock, nil
}

func (nf *NetIface) GetRootNamespaceRawSocketFd() (*int, error) {
	log.Println("[x] Creating XDP socket fd to send packet")
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		log.Println("Error in opening a raw socket fd to the bridge socket")
		return nil, err
	}

	return &fd, nil
}

func (nf *NetIface) GetBridgePcapHandle() (*pcap.Handle, error) {
	cap, err := pcap.OpenLive(NETNS_NETLINK_BRIDGE_DPI, int32(nf.PhysicalLinks[0].Attrs().MTU), true, pcap.BlockForever)
	return cap, err
}
