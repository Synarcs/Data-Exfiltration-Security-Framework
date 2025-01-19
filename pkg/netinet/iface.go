package netinet

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/conntrack"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/asavie/xdp"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

const (
	NETNS_RNETLINK_EGREESS_DPI = "sx1"
	NETNS_RNETLINK_INGRESS_DPI = "sx2"

	NETNS_NETLINK_BRIDGE_DPI     = "br0"
	NETNS_RAW_NETLINK_BRIDGE_DPI = "nx-br0"
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
	Links         []netlink.Link // netlink liks for all links on the device
	PhysicalLinks []netlink.Link // physical veth links with hardware mac and MTU as (1500)
	BridgeLinks   []netlink.Link // links created specifically for bridge kernel utils and DPI over bridge traffic
	LoopBackLinks []netlink.Link // loopback links

	LinkMap map[string]bool
	// all the encapsulated packet links for tunnelling using packet encapsulation
	// most tunnelling link use kernel router netfilter forwarding via non control host for detection prevention
	PointPointTunVxLinks []netlink.Link

	RoutesV4 map[string][]netlink.Route
	RoutesV6 map[string][]netlink.Route

	AddrV4 map[string][]netlink.Addr
	AddrV6 map[string][]netlink.Addr

	PhysicalRouterGatewayV4 net.IP
	PhysicalRouterGatewayV6 net.IP

	PhysicalNodeBridgeIpv4 net.IP
	PhysicalNodeBridgeIpv6 net.IP

	ConnTrackNsHandles map[int]conntrack.ConntrackSock
}

func (nf *NetIface) ReadInterfaces() error {
	links, err := netlink.LinkList()
	if err != nil {
		log.Println(err)
		return err
	}
	customLinks := make([]netlink.Link, 0)

	for _, link := range links {
		if link.Type() == "device" && !strings.Contains(link.Attrs().Name, "lo") {
			log.Println("Physical links on the Node ", link.Attrs().Name, link.Type())
			customLinks = append(customLinks, link)
		}
	}

	log.Println("the custom link to process are ", customLinks)
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
	if len(nf.RoutesV4) == 0 && len(nf.RoutesV6) == 0 {
		return fmt.Errorf("No routes found")
	}
	var gw net.IP
	physicalLink := nf.PhysicalLinks[0].Attrs().Name
	for _, val := range nf.RoutesV4[physicalLink] {
		if val.Gw != nil {
			gw = val.Gw
			break
		}
	}

	dnsResolver, err := ReadPackageConfig()
	if err != nil {
		nf.PhysicalRouterGatewayV4 = gw.To4()
		nf.PhysicalRouterGatewayV6 = net.ParseIP(strings.Split(getRouterIPv6(), "%")[0]).To16()
	} else {
		if dnsResolver.Ipv4 != nil {
			nf.PhysicalRouterGatewayV4 = dnsResolver.Ipv4
		} else {
			nf.PhysicalRouterGatewayV4 = gw.To4()
		}
		if dnsResolver.Ipv6 != nil {
			nf.PhysicalRouterGatewayV6 = dnsResolver.Ipv6
		} else {
			nf.PhysicalRouterGatewayV6 = net.ParseIP(strings.Split(getRouterIPv6(), "%")[0]).To16()
		}
	}

	log.Println("the physical router gateway is ", nf.PhysicalRouterGatewayV4, nf.PhysicalRouterGatewayV6)
	return nil
}

func getRouterIPv6() string {
	conn, _ := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	defer conn.Close()

	// Create Router Solicitation message
	msg := icmp.Message{
		Type: ipv6.ICMPTypeRouterSolicitation,
		Code: 0,
		Body: &icmp.RawBody{},
	}

	// multicast broadcast to all router address in the network
	dst := net.ParseIP("ff02::2")
	wb, _ := msg.Marshal(nil)
	conn.WriteTo(wb, &net.IPAddr{IP: dst})

	// read the remote router solicitation requests
	rb := make([]byte, 1500)
	n, peer, _ := conn.ReadFrom(rb)

	rm, _ := icmp.ParseMessage(58, rb[:n])

	if rm.Type == ipv6.ICMPTypeRouterAdvertisement || rm.Type == ipv6.ICMPTypeCertificationPathSolicitation && !utils.DEBUG {
		log.Printf("Router solicitation received from: %v", peer.String())
	}

	return peer.String()
}

func (nf *NetIface) ReadRoutes() error {
	nf.AddrV4 = make(map[string][]netlink.Addr)
	nf.RoutesV4 = make(map[string][]netlink.Route)

	nf.AddrV6 = make(map[string][]netlink.Addr)
	nf.RoutesV6 = make(map[string][]netlink.Route)

	for _, link := range nf.PhysicalLinks {
		routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
		if err != nil {
			log.Println(err)
			return err
		}
		addr, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			log.Println(err)
			return err
		}

		// ipv6
		// getRouterIPv6()
		routesv6, err := netlink.RouteList(link, netlink.FAMILY_V6)
		if err != nil {
			log.Println(err)
			return err
		}

		addrv6, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			log.Println(err)
			return err
		}

		nf.AddrV4[link.Attrs().Name] = addr
		nf.RoutesV4[link.Attrs().Name] = routes

		if len(addr) > 0 {
			nf.PhysicalNodeBridgeIpv4 = addr[0].IP
		}

		nf.AddrV6[link.Attrs().Name] = addrv6
		nf.RoutesV6[link.Attrs().Name] = routesv6

		if len(addrv6) > 0 {
			nf.PhysicalNodeBridgeIpv6 = addrv6[0].IP
		}
	}
	return nil
}

func (iface *NetIface) FetchNewNetlinkPppSocket() netlink.Link {
	links, _ := netlink.LinkList()
	for _, link := range links {
		_, fd := iface.LinkMap[link.Attrs().Name]
		if !fd {
			flags := link.Attrs().Flags
			if utils.DEBUG {
				fmt.Println("the kernel link flags are ", flags)
			}
			if strings.Contains(flags.String(), "pointtopoint") {
				// attach the ppp socket tc hooks inside kernel
				log.Println("ppp socket detected attaching tc hooks", link.Attrs().Name, link.Attrs().Index)
				return link
			}
			iface.LinkMap[link.Attrs().Name] = true
		}
	}
	return nil
}

// in case if node agent crash and hte tunnel iface tuntap point to point is loaded in kernel
func (iface *NetIface) FindTunnelLinksOnBootUp() []netlink.Link {
	links, _ := netlink.LinkList()
	var tunnelLinks []netlink.Link = make([]netlink.Link, 0)

	for _, link := range links {
		// for the kernel p2p2 encap via l2/l3 pair of tun/tap interfaces
		if strings.Contains(link.Attrs().Flags.String(), "pointtopoint") {
			log.Println("Found a tunnel link ", link.Attrs().Name, "  ", link.Attrs().MTU)
			tunnelLinks = append(tunnelLinks, link)
		}
	}

	return tunnelLinks
}

func (nf *NetIface) findLinkAddressByType() ([]netlink.Link, []netlink.Link, []netlink.Link) {
	hardwardIntefaces := make([]netlink.Link, 0)
	loopBackInterface := make([]netlink.Link, 0) // ensure a single loopback for self loopback link
	bridgeInterfaces := make([]netlink.Link, 0)

	nf.LinkMap = make(map[string]bool)
	for _, link := range nf.Links {
		_, isEth := link.(*netlink.Device)

		nf.LinkMap[link.Attrs().Name] = true
		attrs := link.Attrs()

		if link.Attrs().Flags == net.FlagPointToPoint {
			// an possible tunnelling interface for packet processing
			log.Println("A Point to Point virtualized tunnelling link found ", link.Attrs().Name)
			continue
		} else {
			// Exclude virtual interfaces (e.g., loopback, bridge, vlan, etc.)
			isVirtual := attrs.OperState == netlink.OperNotPresent ||
				attrs.Flags&net.FlagLoopback != 0
				// attrs.Name == "lo"

			isLoopBack := (attrs.EncapType == "loopback" || attrs.Name == "lo" || link.Attrs().Flags&net.FlagLoopback != 0) && (link.Type() != "veth" && link.Type() != "device")
			if isEth && !isVirtual && !isLoopBack {
				hardwardIntefaces = append(hardwardIntefaces, link)
			}
			if isLoopBack {
				loopBackInterface = append(loopBackInterface, link)
			}
			if link.Attrs().Name == NETNS_NETLINK_BRIDGE_DPI {
				bridgeInterfaces = append(bridgeInterfaces, link) // append the kernel dpi bridge for netns rescan first
			} else if link.Attrs().Name == NETNS_RAW_NETLINK_BRIDGE_DPI {
				bridgeInterfaces = append(bridgeInterfaces, link) // append the kernel dpi bridge for raw rescan second
			}

		}

	}
	return hardwardIntefaces, loopBackInterface, bridgeInterfaces
}

func (nf *NetIface) GetVxlanTunnelInterfaces() (map[uint16]*netlink.Vxlan, error) {
	if len(nf.Links) == 0 {
		return nil, fmt.Errorf("Vxlan Tunnel Interfaces cannot be found use netlink soscket to read all net_devices on node")
	}

	var tunnelVxlanInterfaces map[uint16]*netlink.Vxlan = make(map[uint16]*netlink.Vxlan)
	for _, link := range nf.Links {
		if vxlan, ok := link.(*netlink.Vxlan); ok {
			tunnelVxlanInterfaces[uint16(vxlan.Port)] = vxlan
		}
	}

	return tunnelVxlanInterfaces, nil
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

func (nf *NetIface) ListRootnetlinkNetworkNamespaces() map[string]int {
	cmd := exec.Command("ip", "netns", "list")
	var buffer bytes.Buffer

	var stderr bytes.Buffer
	cmd.Stdout = &buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Println("The Node Agent lack permission to process NETLINK socket for ns")
		panic(err.Error())
	}

	if len(stderr.String()) > 0 {
		return nil
	}

	lines := strings.Split(buffer.String(), "\n")
	namespaces := make(map[string]int)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Split(line, " ")
		if len(parts) < 3 {
			continue
		}

		name := parts[0]
		idStr := strings.Trim(parts[len(parts)-1], "()id:")
		var id int
		_, err := fmt.Sscanf(idStr, "%d", &id)
		if err != nil {
			continue
		}
		namespaces[name] = id
	}
	return namespaces
}

func (nf *NetIface) GetAllNetworkNamespaces() (map[string]int, error) {

	// process raw RF_NETLINK kernel socket for biind process and return all ns and id (ip nentns list-id / ip netns list)
	if nsMap := nf.ListRootnetlinkNetworkNamespaces(); nsMap == nil {
		return nil, fmt.Errorf("Error cannot generate netns map for all network namspace")
	} else {
		nsMap["root"] = 0
		return nsMap, nil
	}
}

func (nf *NetIface) InitconnTrackSockHandles() error {
	nsHandles, err := nf.GetAllNetworkNamespaces()

	if err != nil {
		log.Panicln("Error getting tall the netwrk Handles ....")
	}
	var conntracknsHandles map[int]conntrack.ConntrackSock = make(map[int]conntrack.ConntrackSock)
	for _, id := range nsHandles {
		connTrackSock, err := conntrack.NewContrackSock(id) // init and ensure the conntrack kernel entries are cleaned for the root ns
		if err != nil {
			log.Printf("Error getting the NetLink socket for cleaning dangling conntrack entries for Root Network Namespace %v", connTrackSock)
			return err
		}
		conntracknsHandles[id] = *connTrackSock
	}
	nf.ConnTrackNsHandles = conntracknsHandles
	return nil
}

func (nf *NetIface) GetRootNamespacePcapHandle() (*pcap.Handle, error) {

	cap, err := pcap.OpenLive(nf.PhysicalLinks[0].Attrs().Name, int32(nf.PhysicalLinks[0].Attrs().MTU), true, pcap.BlockForever)
	cap.ZeroCopyReadPacketData()
	return cap, err
}

func (nf *NetIface) GetRootNamespacePcapHandleDuration(time time.Duration) (*pcap.Handle, error) {

	cap, err := pcap.OpenLive(nf.PhysicalLinks[0].Attrs().Name, int32(nf.PhysicalLinks[0].Attrs().MTU), true, time)
	cap.ZeroCopyReadPacketData()
	return cap, err
}

func (nf *NetIface) GetRootNamespaceRawSocketFdXDP() (*xdp.Socket, error) {
	log.Println("Creating XDP socket fd to send packet")
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
	log.Println("Creating AF_PACKET socket fd to send packet")
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

func (nf *NetIface) GetBridgePcapHandleClone() (*pcap.Handle, error) {
	cap, err := pcap.OpenLive(NETNS_RAW_NETLINK_BRIDGE_DPI, int32(nf.PhysicalLinks[0].Attrs().MTU), true, pcap.BlockForever)
	return cap, err
}
