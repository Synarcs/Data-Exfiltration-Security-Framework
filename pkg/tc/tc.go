package tc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"runtime"
	"strings"
	"time"

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
	Interfaces    []netlink.Link
	Prog          *ebpf.Program    // ebpf program for tc with clsact class BPF_PROG_TYPE_CLS_ACT
	TcCollection  *ebpf.Collection // ebpf tc program collection order spec
	DnsPacketGen  *model.DnsPacketGen
	ConfigChannel chan interface{}
}

const (
	TC_EGRESS_ROOT_NETIFACE_INT   = "tc.o"
	TC_EGRESS_BRIDGE_NETIFACE_INT = "bridge.o"
)

// a single channel for all go routines to poll kernel evetsn for dns traffic
var ringBufferChannel chan interface{} = make(chan interface{})

func GenerateDnsParserModelUtils(ifaceHandler *netinet.NetIface) *model.DnsPacketGen {
	xdpSocketFd, err := ifaceHandler.GetRootNamespaceRawSocketFdXDP()

	if err == nil {
		log.Println("[x] Using the raw packet with AF_PACKET Fd")

		return &model.DnsPacketGen{
			IfaceHandler:        ifaceHandler,
			SockSendFdInterface: ifaceHandler.PhysicalLinks,
			XdpSocketSendFd:     xdpSocketFd,
			SocketSendFd:        nil,
		}
	} else {
		log.Println("Error Binding the XDP Socket Physical driver lacking support")
		fd, err := ifaceHandler.GetRootNamespaceRawSocketFd()

		if err != nil {
			log.Fatalln("Error fetching the raw socket fd for the socket")
			panic(err.Error())
		}

		return &model.DnsPacketGen{
			IfaceHandler:        ifaceHandler,
			SockSendFdInterface: ifaceHandler.PhysicalLinks,
			SocketSendFd:        fd,
			XdpSocketSendFd:     nil,
		}
	}
}

func (tc *TCHandler) ReadEbpfFromSpec(ctx *context.Context, ebpfProgCode string) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(ebpfProgCode)
	if err != nil {
		return nil, err
	}
	return spec, nil
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

		if err := netlink.FilterReplace(&filter); err != nil {
			panic(err.Error())
		}
	}
	return nil
}

func (tc *TCHandler) PollRingBuffer(ctx *context.Context, ebpfMap *ebpf.Map) {
	log.Println("Go Routine polling the kernel map ", ebpfMap)

	ringBuffer, err := ringbuf.NewReader(ebpfMap)

	if err != nil {
		panic(err.Error())
	}

	defer ringBuffer.Close()

	for {
		if utils.DEBUG {
			log.Println("polling the ring buffer", "using th map", ebpfMap)
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
			log.Printf("PID: %d, SrcIP: %s, DstIP: %s, SrcPort: %d, DstPort: %d\n",
				event.PID, utils.ParseIp(event.SrcIP), utils.ParseIp(event.DstIP), event.SrcPort, event.DstPort)
			log.Printf("Payload Size: %d, UDP Frame Size: %d\n", event.PayloadSize, event.UdpFrameSize)
		}
	}
}

func (tc *TCHandler) TcHandlerEbfpProg(ctx *context.Context, iface *netinet.NetIface) {
	log.Println("Attaching a kernel Handler for the TC CLS_Act Qdisc")
	handler, err := tc.ReadEbpfFromSpec(ctx, TC_EGRESS_ROOT_NETIFACE_INT)

	if err != nil {
		panic(err.Error())
	}

	spec, err := ebpf.NewCollection(handler)
	if err != nil {
		panic(err)
	}

	defer spec.Close()

	// the node agent does not expect tail calls to the kernel ebpf programs over other network layers
	if len(spec.Programs) > 1 {
		log.Println("Multiple programs found in the root collection")
	}
	if len(spec.Programs) == 0 {
		log.Println("The Ebpf Bytecode is corrupt or malformed")
	}

	prog := spec.Programs[utils.TC_CONTROL_PROG]

	if prog == nil {
		panic(fmt.Errorf("No Required TC Hook found for DNS egress"))
	}
	tc.Prog = prog
	tc.TcCollection = spec

	if err := tc.AttachTcHandler(ctx, prog); err != nil {
		log.Println("Error attaching the clsact bpf qdisc for netdev")
		panic(err.Error())
	}

	for _, maps := range spec.Maps {
		if strings.Contains(maps.String(), "exfil_security_egress_drop_ring_buff") {
			// an ring event buffer
			if utils.DEBUG {
				fmt.Println("[x] Spawning Go routine to pool the ring buffer ", maps.String())
			}
			go tc.PollRingBuffer(ctx, maps)
		}
	}

	if utils.DEBUG {
		fmt.Println(spec.Maps, spec.Programs, " prog info ", prog.FD(), prog.String())
	}
	tc.ProcessSniffDPIPacketCapture(iface, nil)
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

	if utils.DEBUG {
		for _, maps := range spec.Maps {
			fmt.Println(maps.String())
		}
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
	configMap := tc.TcCollection.Maps[events.EXFIL_SECURITY_KERNEL_CONFIG_MAP]
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

		if !utils.DEBUG {
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
	log.Println("Loading the Packet Capture over Socket DD")

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	rootNs, err := netns.Get()
	if err != nil {
		panic(err.Error())
	}

	defer rootNs.Close()

	ns, err := netns.GetFromName("sx1")

	// nsHandle, err := ifaceHandler.GetNetworkNamespace("egress")

	if err != nil {
		log.Println(err.Error())
		return err
	}

	defer ns.Close()

	processPcapFilterHandler := func(linkInterface netlink.Link, errorChannel chan<- error) {
		cap, err := pcap.OpenLive(netinet.NETNS_NETLINK_BRIDGE_DPI, int32(linkInterface.Attrs().MTU), true, pcap.BlockForever)
		if err != nil {
			fmt.Println("error opening packet capture over hz,te interface from kernel")
			errorChannel <- err
		}
		defer cap.Close()

		if err := cap.SetBPFFilter("udp dst port 53"); err != nil {
			log.Fatalf("Error setting BPF filter: %v", err)
		}

		packets := gopacket.NewPacketSource(cap, cap.LinkType())
		for packet := range packets.Packets() {
			fmt.Println("sniff the packet over the kernel namespace", packet.Layers())
			go tc.processDNSCaptureForDPI(packet, ifaceHandler, cap)
		}
	}

	errorChannel := make(chan error, len(ifaceHandler.PhysicalLinks))

	if len(ifaceHandler.PhysicalLinks) > 1 {
		log.Println("Processing of multiple Physical links")

		for iface := 0; iface < len(ifaceHandler.PhysicalLinks); iface++ {
			go processPcapFilterHandler(ifaceHandler.PhysicalLinks[iface], errorChannel)
		}
	} else {
		processPcapFilterHandler(ifaceHandler.PhysicalLinks[0], errorChannel)
	}

	go func() {
		for {
			select {
			case paylaod, ok := <-errorChannel:
				{
					if !ok {
						return
					}
					fmt.Println(paylaod.Error())
				}
			default:
				time.Sleep(time.Second * 1)
			}
		}
	}()
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
