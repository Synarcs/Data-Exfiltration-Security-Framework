package tc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
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
	"golang.org/x/sys/unix"
)

type TCHandler struct {
	Interfaces      []netlink.Link
	Prog            *ebpf.Program    // ebpf program for tc with clsact class BPF_PROG_TYPE_CLS_ACT
	TcCollection    *ebpf.Collection // ebpf tc program collection order spec
	DnsPacketGen    *model.DnsPacketGen
	OnnxLoadedModel *model.OnnxModel
}

const (
	TC_EGRESS_ROOT_NETIFACE_INT   = "tc.o"
	TC_EGRESS_BRIDGE_NETIFACE_INT = "bridge.o"
)

// init AF_PACKET, AF_XDP socket for the kernel
var (
	INIT_KERNEL_SOCKET = true
)

// a builder facotry for the tc load and process all tc egress traffic over the different filter chain which node agent is running
func GenerateTcEgressFactory(iface netinet.NetIface, onnxModel *model.OnnxModel) TCHandler {
	return TCHandler{
		Interfaces:      iface.PhysicalLinks,
		DnsPacketGen:    model.GenerateDnsParserModelUtils(&iface, onnxModel),
		OnnxLoadedModel: onnxModel,
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

	}
}

func (tc *TCHandler) PollMonitoringMaps(ctx *context.Context, ebpfMap *ebpf.Map) error {

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

	configMap := tc.TcCollection.Maps[events.EXFILL_SECURITY_KERNEL_CONFIG_MAP]
	if configMap != nil {
		for index, link := range iface.PhysicalLinks {

			var redirectIpv4 events.ExfilKernelConfig = events.ExfilKernelConfig{
				BridgeIndexId: uint32(iface.BridgeLinks[0].Attrs().Index),
				RedirectIpv4:  utils.GenerateBigEndianIpv4(utils.GetIpv4AddressUserSpaceDpIString(index + 1)),
			}
			err := configMap.Put(uint32(link.Attrs().Index), redirectIpv4)
			if err != nil {
				panic(err.Error())
			}
		}
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

	if INIT_KERNEL_SOCKET {
		tc.ProcessSniffDPIPacketCapture(iface, nil)
		INIT_KERNEL_SOCKET = false
	}
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

func (tc *TCHandler) ProcessEachPacket(packet gopacket.Packet, ifaceHandler *netinet.NetIface, handler *pcap.Handle) error {

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

	if isIpv4 {
		fmt.Println(ipPacket)
		// if !(ipPacket.DstIP.String() == utils.GetIpv4AddressUserSpaceDpIString(1)) {
		// 	log.Println("The Bridge is only meant for DPI pf suspicious and malicious DNS traffic")
		// 	return fmt.Errorf("packet is not destined for the userspace DPI on the bridge Interface")
		// } else if !(ipPacket.DstIP.String() == utils.GetIpv4AddressUserSpaceDpIString(2)) {
		// 	log.Println("The Bridge is only meant for DPI pf suspicious and malicious DNS traffic")
		// 	return fmt.Errorf("packet is not destined for the userspace DPI on the bridge Interface")
		// }
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
	dnsMapRedirectMap := tc.TcCollection.Maps[events.EXFILL_SECURITY_EGRESS_REDIRECT_MAP]
	dnsMapRedirectVerify := tc.TcCollection.Maps[events.EXFILL_SECURITY_EGRESS_REDIRECT_TC_VERIFY_MAP]

	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)

		var dns_packet_id uint16 = uint16(dns.ID)
		var ip_layer3_checksum_kernel_ts events.DPIRedirectionKernelMap // granualar timining control over the redirection from kernel

		err := dnsMapRedirectMap.Lookup(&dns_packet_id, &ip_layer3_checksum_kernel_ts)
		if err != nil {
			fmt.Println("Required redirected packet id is not found in the map", err, dnsMapRedirectMap)
		} else {
			log.Println("found the required key from BPF Hash fd ", ip_layer3_checksum_kernel_ts.Checksum, time.Unix(0, int64(ip_layer3_checksum_kernel_ts.Kernel_timets)))

			timeVal := events.DPIRedirectionTimestampVerify{
				Kernel_timets:           ip_layer3_checksum_kernel_ts.Kernel_timets,
				UserSpace_Egress_Loaded: 1,
			}

			if err := dnsMapRedirectVerify.Put(timeVal.Kernel_timets, timeVal.UserSpace_Egress_Loaded); err != nil {
				log.Println("Error updating the timestamp kernel values for egress traffic")
				return err
			}
		}

		tc.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, udpLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum, handler, true)
	}

	return nil
}

func (tc *TCHandler) ProcessPcapFilterHandler(linkInterface netlink.Link, ifaceHandler *netinet.NetIface,
	errorChannel chan<- error, isUdp bool, isStandardPort bool) error {

	cap, err := pcap.OpenLive(netinet.NETNS_NETLINK_BRIDGE_DPI, int32(linkInterface.Attrs().MTU), true, pcap.BlockForever)
	if err != nil {
		fmt.Println("error opening packet capture over hz,te interface from kernel")
		errorChannel <- err
	}
	defer cap.Close()

	if (isUdp || !isUdp) && isStandardPort {
		// runs over br netfilter layer on iptables
		if isUdp {
			log.Println("Generated Egress Packet Listener to parse DNS packets from kernel over the UDP Layer")
		} else {
			log.Println("Generated Egress Packet Listener to parse DNS packets from kernel over the TCP Layer")
		}
		if err := cap.SetBPFFilter("udp dst port 53 or tcp dst port 53"); err != nil {
			log.Fatalf("Error setting BPF filter: %v", err)
		}
	} else if !isUdp && !isStandardPort {
		err := "Not Implemented for non stard port DPI for DNS with no support for ebpf from kernel"
		return fmt.Errorf("err %s", err)
	}

	packets := gopacket.NewPacketSource(cap, cap.LinkType())
	for packet := range packets.Packets() {
		go tc.ProcessEachPacket(packet, ifaceHandler, cap)
	}
	return nil
}

func (tc *TCHandler) ProcessSniffDPIPacketCapture(ifaceHandler *netinet.NetIface, prog *ebpf.Program) error {
	log.Println("Loading the Packet Capture over Socket DD")

	errorChannel := make(chan error, len(ifaceHandler.PhysicalLinks))

	if len(ifaceHandler.PhysicalLinks) > 1 {
		log.Println("Processing of multiple Physical links")

		for iface := 0; iface < len(ifaceHandler.PhysicalLinks); iface++ {
			go tc.ProcessPcapFilterHandler(ifaceHandler.PhysicalLinks[0], ifaceHandler, errorChannel, true, true)
			go tc.ProcessPcapFilterHandler(ifaceHandler.PhysicalLinks[0], ifaceHandler, errorChannel, false, true)
		}
	} else {
		// TODO: Need a fix over go routing getting empty or non valid bad fd for the map
		tc.ProcessPcapFilterHandler(ifaceHandler.PhysicalLinks[0], ifaceHandler, errorChannel, true, true)
		// go tc.ProcessPcapFilterHandler(ifaceHandler.PhysicalLinks[0], ifaceHandler, errorChannel, false, true)
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
