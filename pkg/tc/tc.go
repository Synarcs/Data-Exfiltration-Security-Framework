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
	Interfaces      *netinet.NetIface
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
		Interfaces:      &iface,
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

	for _, link := range tc.Interfaces.PhysicalLinks {
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
				Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
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

func (tc *TCHandler) PollRingBuffer(ctx *context.Context, ebpfEvents *ebpf.Map) {
	log.Println("Go Routine polling the kernel map ", ebpfEvents)

	ringBuffer, err := ringbuf.NewReader(ebpfEvents)

	if err != nil {
		panic(err.Error())
	}

	defer ringBuffer.Close()

	for {
		if utils.DEBUG {
			log.Println("polling the ring buffer", "using th map", ebpfEvents)
		}
		record, err := ringBuffer.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			panic(err.Error())
		}

		var event events.DnsEvent
		if utils.CpuArch() == "arm64" {
			log.Println("Polling the ring buffer for the arm arch")
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}
			log.Println("dns Event polled from kernel non standard port", event)
		} else {
			log.Println("Polling the ring buffer for the x86 big endian systems")
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}
			log.Println("dns Event polled from kernel non standard port", event)
		}
		go tc.streamRedirectCountStatusPayload(event)
	}
}

func (tc *TCHandler) PollMonitoringMaps(ctx *context.Context, ebpfMap *ebpf.Map, errorEventChannel chan error) error {
	var KernelPacketRedirectCount uint16 = 0
	for {
		var KernelRedirectPacketCount uint32 = 0
		if err := ebpfMap.Lookup(KernelPacketRedirectCount, &KernelRedirectPacketCount); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			} else {
				log.Println("Error polling metric for redirected kernel count", err)
				errorEventChannel <- err
			}
		}
		if utils.DEBUG {
			log.Println("The current Redirected count of packets is ", ebpfMap.String(), KernelRedirectPacketCount)
		}
		events.ExportPromeEbpfExporterEvents(KernelRedirectPacketCount)
		time.Sleep(time.Second)
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

	// populate the limit map from the kernel
	dnsLimitsMap := tc.TcCollection.Maps[events.EXFILL_SECURITY_KERNEL_DNS_LIMITS_MAP]
	if dnsLimitsMap != nil {
		// grab the fd from the kernel process to load the egress filter map limit

		for index, limit := range events.DNS_LIMITS_CONFIG {
			err := dnsLimitsMap.Put(
				index, limit)
			if err != nil {
				log.Println("error loading the dns limits in kernel Default in Kernel Loaded BPF object")
			}
		}

		if utils.DEBUG {
			log.Println("The Node Agent loaded the dns limits in Kernel successfully")
		}
	}

	errMapPollChannel := make(chan error)
	for _, maps := range spec.Maps {
		// process all the maps which needs to monitoted or polled from kernel for events without explicity events for ring buffer
		if strings.Contains(maps.String(), "exfil_security_egrees_redirect_ring_buff_non_standard_port") {
			// an ring event buffer
			if utils.DEBUG {
				fmt.Println("[x] Spawning Go routine to pool the ring buffer ", maps.String())
			}
			go tc.PollRingBuffer(ctx, maps)
		}
		if strings.Contains(maps.String(), events.EXFOLL_SECURITY_KERNEL_REDIRECT_COUNT_MAP) || strings.Contains(maps.String(), events.EXFILL_SECURITY_EGRESS_REDIRECT_KERNEL_DROP_COUNT_MAP) {
			go tc.PollMonitoringMaps(ctx, maps, errMapPollChannel)
		}
	}

	go func() {
		for {
			select {
			case pollError, ok := <-errMapPollChannel:
				if !ok {
					log.Fatal("Channel closed for polling kernel events")
				}
				log.Println("Error polling kernel events", pollError)
			default:
				time.Sleep(time.Second)
			}
		}
	}()

	if INIT_KERNEL_SOCKET {
		tc.ProcessSniffDPIPacketCapture(iface, nil)
		INIT_KERNEL_SOCKET = false
	}
}

func (tc *TCHandler) streamRedirectCountStatusPayload(payload interface{}) error {
	currTime := time.Now().GoString()

	events.ExportPromeEbpfExporterEvents(struct {
		Time          string
		redirectCount interface{}
	}{
		Time:          currTime,
		redirectCount: payload,
	})

	return nil
}

func (tc *TCHandler) ProcessEachPacket(packet gopacket.Packet, ifaceHandler *netinet.NetIface, handler *pcap.Handle) error {

	eth := packet.Layer(layers.LayerTypeEthernet)
	var isIpv4 bool
	var isUdp bool
	if eth == nil {
		return fmt.Errorf("no ethernet layer")
	}

	var ipPacket *layers.IPv4
	var ipv6Packet *layers.IPv6

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipv6Packet = (packet.Layer(layers.LayerTypeIPv6)).(*layers.IPv6)
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
		isIpv4 = false
	} else {
		ipPacket = (packet.Layer(layers.LayerTypeIPv4)).(*layers.IPv4)
		isIpv4 = true
		if utils.DEBUG {
			fmt.Println("current packet checksum", ipPacket.Checksum)
		}
	}

	if utils.DEBUG {
		log.Println("packet L3 and L4 ", isIpv4, isUdp)
	}

	transportLayer := packet.Layer(layers.LayerTypeUDP)
	var dnsLengthTcp uint16 = 0
	var dnsTcpPayload []byte

	var tcpCheck bool = false
	if transportLayer != nil {
		udpPacket := transportLayer.(*layers.UDP)
		if udpPacket != nil {
			isUdp = true
		} else {
			panic(fmt.Errorf("the packet is malformed"))
		}
	} else {
		transportLayer = packet.Layer(layers.LayerTypeTCP)
		tcpPacket := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

		if tcpPacket != nil {
			isUdp = false
		} else {
			panic(fmt.Errorf("the packet is malformed"))
		}
		payload := tcpPacket.Payload

		fmt.Println("found tcp packet for domain dest port 53 ", tcpPacket, isUdp, isIpv4, payload)

		if len(payload) < 2 {
			log.Println("errror ", len(payload))
			return fmt.Errorf("TCP payload too short for dns parsing")
		}

		dnsLengthTcp = binary.BigEndian.Uint16(payload[0:2])

		log.Println("The DNs packet parsdd over tcp transport with length ", dnsLengthTcp)
		dnsTcpPayload = payload[2:]
		tcpCheck = true
	}

	// init conside for pcap over udp dg only for now

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	dnsMapRedirectMap := tc.TcCollection.Maps[events.EXFILL_SECURITY_EGRESS_REDIRECT_MAP]
	dnsMapRedirectVerify := tc.TcCollection.Maps[events.EXFILL_SECURITY_EGRESS_REDIRECT_TC_VERIFY_MAP]

	if isIpv4 {
		ipv4Address := ipPacket.DstIP.To4().String()
		if !(ipv4Address == utils.GetIpv4AddressUserSpaceDpIString(1) || ipv4Address == utils.GetIpv4AddressUserSpaceDpIString(2)) {
			log.Println("The Bridge is only meant for DPI pf suspicious or Malicious DNS traffic")
			return fmt.Errorf("packet is not destined for the userspace DPI on the bridge Interface")
		}

		if ipv4Address == utils.GetIpv4AddressUserSpaceDpIString(2) {
			// packet is malicious found from kernel and link redirected and no further DPI should be done on user space
			events.HandleKernelDroppedPacket(
				dnsLayer, isIpv4, isUdp, "DNS",
			)
			return nil
		}

		// control plane event streaming via kafka / flink to a message broker
		go tc.streamRedirectCountStatusPayload(&dnsLayer)
	} else {
		ipv6Address := ipv6Packet.DstIP.To16().String()

		if ipv6Address == utils.MALICIOUS_NETNS_IPV6 {
			events.HandleKernelDroppedPacket(
				dnsLayer, isIpv4, isUdp, "DNS",
			)

			return nil
		}

		go tc.streamRedirectCountStatusPayload(&dnsLayer)
		// TODO: ipv6 processing for the pacekt capture
	}

	isIpv6 := !isIpv4

	processVeifyKernelDnsTS := func(dns_packet_id uint16, ip_layer3_checksum_kernel_ts events.DPIRedirectionKernelMap) error {

		err := dnsMapRedirectMap.Lookup(&dns_packet_id, &ip_layer3_checksum_kernel_ts)
		if err != nil {
			fmt.Println("Required redirected packet id is not found in the map", err, dnsMapRedirectMap)
		} else {
			if utils.DEBUG {
				log.Println("found the required key from BPF Hash fd ", ip_layer3_checksum_kernel_ts.Checksum, time.Unix(0, int64(ip_layer3_checksum_kernel_ts.Kernel_timets)))
			}

			if isIpv6 {
				// support for ipv6
				if ip_layer3_checksum_kernel_ts.Checksum != uint16(utils.DEFAULT_IPV6_CHECKSUM_MAP) {
					log.Println("Error in Ipv6 header checksum verification ipv6 has no default checksum")
				}
			}
			timeVal := events.DPIRedirectionTimestampVerify{
				Kernel_timets:           ip_layer3_checksum_kernel_ts.Kernel_timets,
				UserSpace_Egress_Loaded: 1,
			}

			if err := dnsMapRedirectVerify.Put(timeVal.Kernel_timets, timeVal.UserSpace_Egress_Loaded); err != nil {
				log.Println("Error updating the timestamp kernel values for egress traffic")
				return err
			}
		}
		return nil
	}

	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)

		var dns_packet_id uint16 = uint16(dns.ID)
		var ip_layer3_checksum_kernel_ts events.DPIRedirectionKernelMap // granualar timining control over the redirection from kernel

		if err := processVeifyKernelDnsTS(dns_packet_id, ip_layer3_checksum_kernel_ts); err != nil {
			log.Printf("Error verify the UDP packet time from kernel %+v", err)
		}

		if isIpv4 && isUdp {
			tc.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum, handler, true, isIpv4, isUdp)
			// ipv4 and udp
		}
		if !isIpv4 && isUdp {
			// ipv6 and udp
			tc.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum, handler, true, isIpv4, isUdp)
		}

	} else if tcpCheck {
		dns := &layers.DNS{}

		err := dns.DecodeFromBytes(dnsTcpPayload, gopacket.NilDecodeFeedback)
		if err != nil {
			log.Println("Error decoding the dns packet over the tcp stream", err)
			return err
		}

		var dns_packet_id uint16 = uint16(dns.ID)
		var ip_layer3_checksum_kernel_ts events.DPIRedirectionKernelMap // granualar timining control over the redirection from kernel

		if err := processVeifyKernelDnsTS(dns_packet_id, ip_layer3_checksum_kernel_ts); err != nil {
			log.Printf("Error processing the dns packet over tcp stream %+v", err)
		}

		if isIpv4 && !isUdp {
			// ipv4 and tcp
			fmt.Println("called here for redirect over tcp")
			tc.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum, handler, true, isIpv4, isUdp)
		}
		if !isIpv4 && !isUdp {
			// ipv6 and tcp
			tc.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum, handler, true, isIpv4, isUdp)
		}
	}

	return nil
}

func (tc *TCHandler) ProcessPcapFilterHandler(linkInterface netlink.Link, ifaceHandler *netinet.NetIface,
	errorChannel chan<- error, isStandardPort bool) error {

	cap, err := pcap.OpenLive(netinet.NETNS_NETLINK_BRIDGE_DPI, int32(linkInterface.Attrs().MTU), true, pcap.BlockForever)
	if err != nil {
		fmt.Println("error opening packet capture over hz,te interface from kernel")
		errorChannel <- err
	}
	defer cap.Close()

	if isStandardPort {
		// runs over br netfilter layer on iptables
		log.Println("Generated Egress Packet Listener to parse DNS packets from kernel over the UDP Layer and TCP Layer for the DNS protocol")
		if err := cap.SetBPFFilter("udp dst port 53 or tcp dst port 53"); err != nil {
			log.Fatalf("Error setting BPF filter: %v", err)
		}
	} else if !isStandardPort {

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
			go tc.ProcessPcapFilterHandler(ifaceHandler.PhysicalLinks[0], ifaceHandler, errorChannel, true)
			go tc.ProcessPcapFilterHandler(ifaceHandler.PhysicalLinks[0], ifaceHandler, errorChannel, true)
		}
	} else {
		// TODO: Need a fix over go routing getting empty or non valid bad fd for the map
		tc.ProcessPcapFilterHandler(ifaceHandler.PhysicalLinks[0], ifaceHandler, errorChannel, true)
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
	// used for removal of tc qdisc and all nested filters to parent qdisc class/ classless filter form all the host interfacee
	for _, link := range tc.Interfaces.PhysicalLinks {
		err := netlink.QdiscDel(&netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
			},
		})
		if err != nil {
			fmt.Println("No Matching clsact desc found to delete")
		}
	}
	return nil
}
