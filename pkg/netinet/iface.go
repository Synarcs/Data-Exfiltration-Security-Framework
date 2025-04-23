package netinet

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/conntrack"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils/iowatchers"
	"github.com/asavie/xdp"
	"github.com/fsnotify/fsnotify"
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

// TODO: Replace with discrete IPAM  differring from the all netdev links at the endpoint
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

	VxlanLinks []netlink.Link
	LinkMap    map[string]bool
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

func NewNetIface() *NetIface {
	return &NetIface{}
}

func (nf *NetIface) ReadInterfaces(containered bool) error {
	links, err := netlink.LinkList()
	if err != nil {
		utils.Log(err)
		return err
	}
	customLinks := make([]netlink.Link, 0)

	for _, link := range links {
		if link.Type() == "device" && !strings.Contains(link.Attrs().Name, "lo") {
			utils.Log("Physical links on the Node ", link.Attrs().Name, link.Type())
			customLinks = append(customLinks, link)
		}
	}

	utils.Log("the custom link to process are ", customLinks)
	nf.Links = links
	nf.GetVxlanLinks()
	var hardwareInterfaces []netlink.Link
	var logicalInterfaces []netlink.Link
	var bridgeInterfaces []netlink.Link
	if containered {
		hardwareInterfaces, logicalInterfaces, bridgeInterfaces = nf.findLinkAddressByTypeContainer()
	} else {
		hardwareInterfaces, logicalInterfaces, bridgeInterfaces = nf.findLinkAddressByType()
	}
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

func (nf *NetIface) GetVxlanLinks() {
	for _, link := range nf.Links {
		if link.Type() == "vxlan" {
			nf.VxlanLinks = append(nf.VxlanLinks, link)
		}
	}
}

var sysetemdResolvedConfigUpdateGuard sync.Mutex

func (nf *NetIface) ConfigureAgentDnsServerConfig(dnsResolver *DnsResolverServer) {

	var gw net.IP
	physicalLink := nf.PhysicalLinks[0].Attrs().Name
	for _, val := range nf.RoutesV4[physicalLink] {
		if val.Gw != nil {
			gw = val.Gw
			break
		}
	}

	configCustomDefaultLocalgw := func(resolverConfig *DnsResolverServer) {
		if resolverConfig.Ipv4 != nil {
			nf.PhysicalRouterGatewayV4 = resolverConfig.Ipv4
		} else {
			nf.PhysicalRouterGatewayV4 = gw.To4()
		}
		if resolverConfig.Ipv6 != nil {
			nf.PhysicalRouterGatewayV6 = resolverConfig.Ipv6
		} else {
			nf.PhysicalRouterGatewayV6 = net.ParseIP(strings.Split(getRouterIPv6(), "%")[0]).To16()
		}
	}

	if dnsResolver == nil {
		hostResolverConfig, err := ReadDNSResolvedConf() // read config from file of systemd resolved
		if err != nil {
			nf.PhysicalRouterGatewayV4 = net.ParseIP(utils.GLOBAL_ROUTE_IPV4_TRANSFER_LINKS[0]).To4()
			nf.PhysicalRouterGatewayV6 = net.ParseIP(utils.GLOBAL_ROUTE_IPV6_TRANSFER_LINKS[0]).To16()
		}
		configCustomDefaultLocalgw(hostResolverConfig)
		return
	}
	configCustomDefaultLocalgw(dnsResolver)
}

func (nf *NetIface) UpdateAgentConfig(ev *fsnotify.Event) {
	utils.Log("received event for systemd-resolved config change:", ev.String())

	if !(ev.Has(fsnotify.Write) || ev.Has(fsnotify.Rename) || ev.Has(fsnotify.Create)) {
		// Only update on write, rename, or create events
		return
	}

	time.Sleep(time.Second) // wait atomic until file is modified and flushed to disk,  in case of vim, vim generates a temp swp file and then update original one
	sysetemdResolvedConfigUpdateGuard.Lock()
	defer sysetemdResolvedConfigUpdateGuard.Unlock()

	resolvedDnsChange, err := ReadDNSResolvedConf()
	if err != nil {
		// Suppress error: don't change agent config; agent is live with all eBPF programs loaded in kernel
		return
	}

	if resolvedDnsChange != nil {
		// ensure the flushed change to disk has new modified content
		nf.ConfigureAgentDnsServerConfig(resolvedDnsChange)
	}
}

// updates the root process for eBPF node agent in user space which injected all kernel programs over any changes on disk for systemd resolved
func (nf *NetIface) UpdateResolvedConfigForAgent(ctx context.Context) error {
	utils.Log("Starting the Inotify Systemd Resolved watcher")
	inotifywatcher, err := iowatchers.NewInotifySystemWatcher()

	doneChan := make(chan bool)
	if err != nil {
		return err
	}

	defer inotifywatcher.Close()
	go func() {
		for {
			select {
			case <-ctx.Done():
				doneChan <- true
				return
			case ev, cls := <-inotifywatcher.Events:
				if !cls {
					utils.Log("Channel for fs notify event closed")
					return
				}
				if ev.Op&fsnotify.Rename != 0 || ev.Op&fsnotify.Create != 0 {
					inotifywatcher.Remove(SYSTEMD_RESOLVED_PATH)
					inotifywatcher.Add(SYSTEMD_RESOLVED_PATH)
				}
				nf.UpdateAgentConfig(&ev)
			case err := <-inotifywatcher.Errors:
				doneChan <- true
				utils.Log("Channel for fs notify event error ", err.Error())
				return
			}
		}
	}()

	utils.Log("Adding FSNotify Watcher", SYSTEMD_RESOLVED_PATH)
	if err := inotifywatcher.Add(SYSTEMD_RESOLVED_PATH); err != nil {
		utils.Log("error adding watcher", SYSTEMD_RESOLVED_PATH)
		doneChan <- true
	}

	<-doneChan
	utils.Log("closing the watch func")
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
		utils.Logger.Printf("Router solicitation received from: %v", peer.String())
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
			utils.Log(err)
			return err
		}
		addr, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			utils.Log(err)
			return err
		}

		// ipv6
		// getRouterIPv6()
		routesv6, err := netlink.RouteList(link, netlink.FAMILY_V6)
		if err != nil {
			utils.Log(err)
			return err
		}

		addrv6, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			utils.Log(err)
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
				utils.Log("ppp socket detected attaching tc hooks", link.Attrs().Name, link.Attrs().Index)
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
		// for the kernel p2p encap via l2/l3 pair of tun/tap interfaces
		if strings.Contains(link.Attrs().Flags.String(), "pointtopoint") {
			utils.Log("Found a tunnel link ", link.Attrs().Name, "  ", link.Attrs().MTU)
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
			utils.Log("A Point to Point virtualized tunnelling link found ", link.Attrs().Name)
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

// container has veth pair to the host bridge for k8s mount to the CNI vnxlan bridge for docker its docker bridge
// physical interfaces are the host pair veth interface which attach to the bridge for l3 balancing l3 and l2 traffic for all pods in CNI subnet or docker ips on docker bridge
func (nf *NetIface) findLinkAddressByTypeContainer() ([]netlink.Link, []netlink.Link, []netlink.Link) {
	containerVethPairInterface := make([]netlink.Link, 0)
	utils.Log("Reading net links for container environments via netlink sockets")
	loopBackInterface := make([]netlink.Link, 0) // ensure a single loopback for self loopback link
	bridgeInterfaces := make([]netlink.Link, 0)

	nf.LinkMap = make(map[string]bool)

	for _, link := range nf.Links {

		nf.LinkMap[link.Attrs().Name] = true
		attrs := link.Attrs()
		if link.Attrs().Flags == net.FlagPointToPoint { // (tun/tap ppp tunnels cannot be there inside containers or POID intern networking CIDR)
			// an possible tunnelling interface for packet processing
			utils.Log("A Point to Point virtualized tunnelling link found ", link.Attrs().Name)
			continue
		} else {
			isLoopbackType := attrs.EncapType == "loopback" ||
				attrs.Name == "lo" ||
				link.Attrs().Flags == net.FlagLoopback

			isNotVirtualDevice := link.Type() != "veth" &&
				link.Type() != "device"

			isLoopBack := isLoopbackType && !isNotVirtualDevice

			// for now assume container runtime internal physical interface is eth0, and containers only have one physical interface attached to veth bridge for CNI or docker bridge
			if attrs.Name == "eth0" {
				fmt.Println("inteface physical name ", attrs.Name)
				containerVethPairInterface = append(containerVethPairInterface, link) // (always fixed docker networking and any k8s CNI uses this for veth pair for l2, l3 routing inside cotnianer / pod network)
			}
			if isLoopBack {
				fmt.Println("loopback iface name ", attrs.Name)
				loopBackInterface = append(loopBackInterface, link)
			}

			// hanle all the container ns for their pod traffic
			if link.Attrs().Name == NETNS_NETLINK_BRIDGE_DPI {
				bridgeInterfaces = append(bridgeInterfaces, link) // append the kernel dpi bridge for netns rescan first
			} else if link.Attrs().Name == NETNS_RAW_NETLINK_BRIDGE_DPI {
				bridgeInterfaces = append(bridgeInterfaces, link) // append the kernel dpi bridge for raw rescan second
			}
		}
	}
	return containerVethPairInterface, loopBackInterface, bridgeInterfaces
}

func (nf *NetIface) GetVxlanTunnelInterfaces() (map[uint16]*netlink.Vxlan, error) {
	if len(nf.Links) == 0 {
		return nil, fmt.Errorf("Vxlan Tunnel Interfaces cannot be found use netlink soscket to read all net_devices on node")
	}

	var tunnelVxlanInterfaces map[uint16]*netlink.Vxlan = make(map[uint16]*netlink.Vxlan)
	for _, link := range nf.Links {
		if vxlan, ok := link.(*netlink.Vxlan); ok {
			if vxlan.Group == nil || vxlan.SrcAddr == nil {
				continue
			}
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
		utils.Log("[x] Error Getting the Root Namespace")
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
		utils.Log("The Node Agent lack permission to process NETLINK socket for ns")
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
		utils.Logger.Error("Error getting tall the netwrk Handles ....")
	}
	var conntracknsHandles map[int]conntrack.ConntrackSock = make(map[int]conntrack.ConntrackSock)
	for _, id := range nsHandles {
		connTrackSock, err := conntrack.NewContrackSock(id) // init and ensure the conntrack kernel entries are cleaned for the root ns
		if err != nil {
			utils.Logger.Printf("Error getting the NetLink socket for cleaning dangling conntrack entries for Root Network Namespace %v", connTrackSock)
			return err
		}
		conntracknsHandles[id] = *connTrackSock
	}
	nf.ConnTrackNsHandles = conntracknsHandles
	return nil
}

// uses the first default pcap handle from the host physical netlink (net_device) and seclect bpf filter for live sniff
func (nf *NetIface) GetRootNamespacePcapHandle() (*pcap.Handle, error) {
	cap, err := pcap.OpenLive(nf.PhysicalLinks[0].Attrs().Name, int32(nf.PhysicalLinks[0].Attrs().MTU), true, pcap.BlockForever)
	cap.ZeroCopyReadPacketData()
	return cap, err
}

// opens pcap handle over cusotm netlink  (net_device), runs over zero copy to read packet from rx queues of netdev with no overhead of data copy over in userspace
func (nf *NetIface) GetPcapHandleoverNetDev(link netlink.Link) (*pcap.Handle, error) {
	cap, err := pcap.OpenLive(link.Attrs().Name, int32(link.Attrs().MTU), true, pcap.BlockForever)
	cap.ZeroCopyReadPacketData()
	return cap, err
}

// opens pcap handle over cusotm (net_device) through name, runs over zero copy to read packet from rx queues of netdev with no overhead of data copy over in userspace
func (nf *NetIface) GetPcapHandleoverNetDevByName(link string, mtu int32) (*pcap.Handle, error) {
	cap, err := pcap.OpenLive(link, mtu, true, pcap.BlockForever)
	cap.ZeroCopyReadPacketData()
	return cap, err
}

// opens pcap handle over cusotm netlink  (net_device for sniff over custom duration time
func (nf *NetIface) GetPcapHandleoverNetDevDuration(link netlink.Link, duration time.Duration) (*pcap.Handle, error) {
	cap, err := pcap.OpenLive(link.Attrs().Name, int32(link.Attrs().MTU), true, duration)
	cap.ZeroCopyReadPacketData()
	return cap, err
}

func (nf *NetIface) GetRootNamespacePcapHandleDuration(time time.Duration) (*pcap.Handle, error) {

	cap, err := pcap.OpenLive(nf.PhysicalLinks[0].Attrs().Name, int32(nf.PhysicalLinks[0].Attrs().MTU), true, time)
	cap.ZeroCopyReadPacketData()
	return cap, err
}

func (nf *NetIface) GetRootNamespaceRawSocketFdXDP() (*xdp.Socket, error) {
	utils.Log("Creating XDP socket fd to send packet")
	_, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		utils.Log("Error in opening a raw socket fd to the bridge socket")
		return nil, err
	}

	// use the egress transfer queue to send the packet on the physical port inside kernel to make directly reach the interface bypass the kernel network stack
	txQueueId, err := GetCurrentTXQueues(nf.PhysicalLinks[0].Attrs().Name)
	if err != nil {
		utils.Log("Error in getting the tx TX queue id")
		return nil, err
	}
	utils.Log("the tx queue id is ", txQueueId, nf.PhysicalLinks[0].Attrs().Index)

	xdpSock, err := xdp.NewSocket(nf.PhysicalLinks[0].Attrs().Index, txQueueId, nil)
	if err != nil {
		utils.Log("Error in binding the AF_XDP Socket to TX Queues")
		return nil, err
	}

	return xdpSock, nil
}

func (nf *NetIface) GetRootNamespaceRawSocketFd() (*int, error) {
	utils.Log("Creating AF_PACKET socket fd to send packet")
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		utils.Log("Error in opening a raw socket fd to the bridge socket")
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
	cap.ZeroCopyReadPacketData()
	return cap, err
}
