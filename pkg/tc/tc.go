package tc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type TCHandler struct {
	Interfaces   []netlink.Link
	Prog         *ebpf.Program    // ebpf program for tc with clsact class BPF_PROG_TYPE_CLS_ACT
	TcCollection *ebpf.Collection // ebpf tc program collection order spec
	DnsPacketGen *model.DnsPacketGen
}

const (
	TC_EGRESS_ROOT_NETIFACE_INT   = "tc.o"
	TC_EGRESS_BRIDGE_NETIFACE_INT = "bridge.o"
)

func GenerateDnsParserModelUtils(ifaceHandler *netinet.NetIface) *model.DnsPacketGen {
	return &model.DnsPacketGen{
		IfaceHandler: ifaceHandler,
	}
}

func (tc *TCHandler) ReadEbpfFromSpec(ctx *context.Context, ebpfProgCode string) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(ebpfProgCode)
	if err != nil {
		return nil, err
	}
	return spec, nil
}

func (tc *TCHandler) CreateDPIInterfaceTc(ctx *context.Context) error {
	log.Println("Creating the TC ingress monitor for the DPI")

	fd, err := netlink.LinkByName(utils.TC_INGRESS_MONITOR_MAP)
	if err == nil {
		fmt.Println("Link already exists with name ", utils.TC_INGRESS_MONITOR_MAP)
		netlink.LinkDel(fd)
	}

	err = netlink.LinkAdd(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: utils.TC_INGRESS_MONITOR_MAP,
			MTU:  1500,
		},
	})

	if err != nil {
		log.Fatalf("error Setting up the Link for DPI used for egress redirection to Ingress")
		return err
	}

	link, err := netlink.LinkByName(utils.TC_INGRESS_MONITOR_MAP)
	if err := netlink.LinkSetUp(link); err != nil {
		fmt.Println("error setting the monitoring link for kernel")
		return err
	}

	if err != nil {
		log.Fatal("Error finding the link with name ", utils.TC_INGRESS_MONITOR_MAP)
		return err
	}

	err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
		Protocol:  unix.ETH_P_ALL,
		Scope:     unix.RT_SCOPE_UNIVERSE,
		Priority:  1,
		Table:     254,
	})

	if err != nil {
		fmt.Println("Error Adding the route for the ingress monitor redirected traffic control qdisc")
		return err
	}

	return nil
}

func (tc *TCHandler) AttachTcHandler(ctx *context.Context, prog *ebpf.Program) error {

	for _, link := range tc.Interfaces {
		log.Println("Attaching TC qdisc to the interface ", link.Attrs().Name)
		_, err := netlink.QdiscList(link)
		if err != nil {
			panic(err.Error())
		}

		log.Println("Attaching a qdisc handler")
		qdisc_clsact := &netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(0xffff, 0),
			},
		}
		if err := netlink.QdiscReplace(qdisc_clsact); err != nil {
			panic(err.Error())
		}

		filter := netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    netlink.MakeHandle(1, 0),
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           prog.FD(),
			Name:         prog.String(),
			DirectAction: true,
		}

		if netlink.FilterReplace(&filter); err != nil {
			panic(err.Error())
		}
	}
	return nil
}

func (tc *TCHandler) TcHandlerEbfpProg(ctx *context.Context, iface *netinet.NetIface) {
	log.Println("Attaching a kernel Handler for the TC CLS_Act Qdisc")
	handler, err := tc.ReadEbpfFromSpec(ctx, TC_EGRESS_ROOT_NETIFACE_INT)

	if err != nil {
		panic(err.Error())
	}

	spec, err := ebpf.NewCollection(handler)
	if err != nil {
		panic(err.Error())
	}

	defer spec.Close()

	if len(spec.Programs) > 1 {
		fmt.Println("Multiple programs found in the root collection")
	}
	if len(spec.Programs) == 0 {
		fmt.Println("The Ebpf Bytecode is corrupt or malformed")
	}

	prog := spec.Programs[utils.TC_CONTROL_PROG]

	if prog == nil {
		panic(fmt.Errorf("No Required TC Hook found for DNS egress"))
	}
	tc.Prog = prog
	tc.TcCollection = spec

	if err := tc.AttachTcHandler(ctx, prog); err != nil {
		fmt.Println("Error attaching the clsact bpf qdisc for netdev")
		panic(err.Error())
	}

	ringBuffer, err := ringbuf.NewReader(spec.Maps["dns_ring_events"])

	if err != nil {
		panic(err.Error())
	}

	defer ringBuffer.Close()

	fmt.Println(spec.Maps, spec.Programs, " prog info ", prog.FD(), prog.String())

	// go func() {
	for {
		if utils.DEBUG {
			fmt.Println("polling the ring buffer", "using th map", spec.Maps["dns_ring_events"])
		}
		record, err := ringBuffer.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			panic(err.Error())
		}
		var event events.DnsEvent
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			log.Fatalf("Failed to parse event: %v", err)
		}

		// No further conversion is needed; values are already in host byte order
		if utils.DEBUG {
			fmt.Printf("PID: %d, SrcIP: %s, DstIP: %s, SrcPort: %d, DstPort: %d\n",
				event.PID, utils.ParseIp(event.SrcIP), utils.ParseIp(event.DstIP), event.SrcPort, event.DstPort)
			fmt.Printf("Payload Size: %d, UDP Frame Size: %d\n", event.PayloadSize, event.UdpFrameSize)
		}
	}
	// }()
	// tcHandler.AttachTcHandler(&ctx, prog)
}

func (tc *TCHandler) TCHandlerEbpfProgBridge(ctx *context.Context, iface *netinet.NetIface) error {
	handler, err := tc.ReadEbpfFromSpec(ctx, TC_EGRESS_ROOT_NETIFACE_INT)
	if err != nil {
		return err
	}

	spec, err := ebpf.NewCollection(handler)
	if err != nil {
		return err
	}

	for _, maps := range spec.Maps {
		fmt.Println(maps.String())
	}
	return nil
}

func (tc *TCHandler) processDNSCaptureForDPI(packet gopacket.Packet, ifaceHandler *netinet.NetIface, handler *pcap.Handle) error {

	eth := packet.Layer(layers.LayerTypeEthernet)
	var isIpv4 bool
	var isUdp bool
	if eth == nil {
		return fmt.Errorf("no ethernet layer")
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	// ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	ipPacket := ipLayer.(*layers.IPv4)
	if ipPacket != nil {
		isIpv4 = true
		if utils.DEBUG {
			fmt.Println("current packet checksum", ipPacket.Checksum)
		}
	} else {
		ipv6Packet := ipLayer.(*layers.IPv6)
		if ipv6Packet != nil {
			isIpv4 = false
		}
	}
	if utils.DEBUG {
		log.Println("packet L3 and L4 ", isIpv4, isUdp)
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	udpPacket := udpLayer.(*layers.UDP)
	if udpPacket != nil {
		isUdp = true
	} else {
		tcpPacket := tcpLayer.(*layers.TCP)
		if tcpPacket != nil {
			isUdp = false
		}
	}
	// init conside for pcap over udp dg only for now
	dnsLayer := packet.Layer(layers.LayerTypeDNS)

	dnsMapRedirectMap := tc.TcCollection.Maps["exfil_security_egress_redirect_map"]
	configMap := tc.TcCollection.Maps["exfil_security_config_map"]
	if configMap != nil {
	}

	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		fmt.Println("Question count ", dns.QDCount, "Answer count", dns.ANCount, "Packet id is ", dns.ID)

		var dns_packet_id uint16 = uint16(dns.ID)
		var ip_layer3_checksum uint16
		err := dnsMapRedirectMap.Lookup(&dns_packet_id, &ip_layer3_checksum)
		if err != nil {
			fmt.Println("Required redirected packet id is not found in the map", err)
		} else {
			fmt.Println("found the required key from BPF Hash fd ", uint16(ip_layer3_checksum))
		}
		if dns.QDCount > 0 {
			for _, qd := range dns.Questions {
				fmt.Println(string(qd.Name), qd.Class, qd.Type)
			}
		}
		if dns.ARCount > 0 {
			for _, ar := range dns.Authorities {
				fmt.Println(string(ar.Name), ar.Class, ar.Type, ar.TTL)
			}
		}
		if dns.ANCount > 0 {
			for _, an := range dns.Answers {
				fmt.Println(string(an.Data), an.String())
			}
		}
		// debug kernel redirection packet for egress route via a bpf_id_redirect
		// if err != nil {
		// a valid packet found from the process redirect map for DPI and kernel redirect scan
		tc.DnsPacketGen.GeneratePacket(eth, ipLayer, udpLayer, dnsLayer, ip_layer3_checksum, handler)
		// }
		// fmt.Println(dns.Questions, dns.Answers)
	}

	return nil
}

func (tc *TCHandler) ProcessSniffDPIPacketCapture(ifaceHandler *netinet.NetIface, prog *ebpf.Program) error {
	fmt.Println("called here for process Invoke")

	rootNs, err := netns.Get()
	if err != nil {
		panic(err.Error())
	}

	defer rootNs.Close()

	nsHandle, err := ifaceHandler.GetNetworkNamespace("egress")

	if err != nil {
		log.Println(err.Error())
		return err
	}

	defer nsHandle.Close()
	defer rootNs.Close()

	if len(ifaceHandler.PhysicalLinks) > 0 {
		log.Println("Processing of multiple Physical links")
	}

	fmt.Println(nsHandle.UniqueId(), nsHandle.String())

	// // change the namespace for kernel pcap open
	// if err := netns.Set(*nsHandle); err != nil {
	// 	log.Println("error changing the Network Namespace")
	// 	panic(err)
	// }

	cap, err := pcap.OpenLive(utils.NETNS_NETLINK_BRIDGE_DPI, int32(ifaceHandler.PhysicalLinks[0].Attrs().MTU), true, pcap.BlockForever)
	if err != nil {
		fmt.Println("error opening packet capture over hte interface from kernel")
		return err
	}
	defer cap.Close()

	if err := cap.SetBPFFilter("udp and port 53"); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	packets := gopacket.NewPacketSource(cap, cap.LinkType())
	for packet := range packets.Packets() {
		tc.processDNSCaptureForDPI(packet, ifaceHandler, cap)
	}
	return nil
}

func (tc *TCHandler) DetachHandler(ctx *context.Context) error {
	for _, link := range tc.Interfaces {
		err := netlink.QdiscDel(&netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(0xffff, 0),
			},
		})
		if err != nil {
			fmt.Println("No Matching clsact desc found to delete")
		}
	}
	return nil
}
