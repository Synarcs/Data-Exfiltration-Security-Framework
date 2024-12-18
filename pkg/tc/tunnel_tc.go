package tc

// DPI over the clone redirect over tc from kernel done via the tc layer

import (
	"errors"
	"log"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCCloneTunnel struct {
	IfaceHandler             *netinet.NetIface
	GlobalKernelErrorChannel chan bool
	PhysicalTcInterface      *TCHandler
	StreamClient             *events.StreaClient
}

func GenerateTcTunnelFactory(tc *TCHandler, iface *netinet.NetIface, globalErrorChannel chan bool,
	streamClient *events.StreaClient) *TCCloneTunnel {
	return &TCCloneTunnel{
		IfaceHandler:             iface,
		GlobalKernelErrorChannel: globalErrorChannel,
		PhysicalTcInterface:      tc,
		StreamClient:             streamClient,
	}
}

func (tun *TCCloneTunnel) SniffPacketsForTunnelDPI() {
	handler, err := tun.IfaceHandler.GetBridgePcapHandleClone()

	if err != nil {
		log.Printf("Error while sniffing packets on the interface %s", netinet.NETNS_RAW_NETLINK_BRIDGE_DPI)
		tun.GlobalKernelErrorChannel <- true
	}

	defer handler.Close()

	if err := handler.SetBPFFilter("udp or tcp"); err != nil {
		log.Println("Error while setting the bpf filter")
		tun.GlobalKernelErrorChannel <- true
	}

	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())

	sniffTunnelErr := make(chan interface{})

	go func() {
		for {
			select {
			case msg, ok := <-sniffTunnelErr:
				if !ok {
					return
				}
				log.Println("Received an error while sniffing the packets over the veth bridge in kernel redirected non standard packet clone", msg)
			default:
				time.Sleep(time.Second)
			}
		}
	}()

	ebpfMap := tun.PhysicalTcInterface.TcCollection.Maps[events.EXFIL_SECURITY_EGRESS_RECONNISANCE_MAP_SCAN]

	for packet := range packetSource.Packets() {
		go tun.ProcessTunnelHandlerPackets(packet, ebpfMap, sniffTunnelErr)
	}
}

func (tun *TCCloneTunnel) EnsureTransportTunnelPortMapUpdate(tunnelMap *ebpf.Map,
	destPort uint16, fetchEvent *events.ExfilRawPacketMirror,
	erroChannel chan interface{}, isBenign bool) {

	if isBenign {
		fetchEvent.IsPacketRescanedAndMalicious = uint8(0)
		if err := tunnelMap.Put(uint16(destPort), fetchEvent); err != nil {
			log.Println("Error in updating the map for this benign found packet", err)
			/// the kernel will always ensure the key exist in gthe lru map before it even rich the user space for this bridge to sniff upon
			erroChannel <- struct {
				Err string
			}{
				Err: "Error in updating the map for this benign found packet",
			}
		}
	} else {
		fetchEvent.IsPacketRescanedAndMalicious = uint8(1)
		if err := tunnelMap.Put(uint16(destPort), fetchEvent); err != nil {
			log.Println("Error in updating the map for this benign found packet", err)
			erroChannel <- struct {
				Err string
			}{
				Err: "Error in updating the map for this malicious  found packet for kernel to drop pakcet on next packet transfer ",
			}
		}
	}
}

func (tun *TCCloneTunnel) ProcessTunnelHandlerPackets(packet gopacket.Packet, ebpfMap *ebpf.Map, errorChannel chan interface{}) {
	if utils.DEBUG {
		log.Println("called the sniffer for packet")
	}

	if ebpfMap == nil {
		log.Println("Error the map parsed for tunneled c2c other socket is null")
		errorChannel <- struct {
			Err string
		}{
			Err: "The kernel ebpf map for tun is nil",
		}
		return
	}

	processRemoteInferTunnel := func() (bool, error) {
		return false, nil
	}

	parseUdpEncap := func(l3ip *layers.IPv4, l3ipv6 *layers.IPv6) bool {
		if l3ip != nil {
			status, err := processRemoteInferTunnel()
			if err != nil {
				errorChannel <- struct {
					Err string
				}{
					Err: "The kernel has not cloned the packet from tc layer",
				}
			}
			return status
		} else {
			udp := layers.UDP{}
			if err := udp.DecodeFromBytes(l3ip.Payload, gopacket.NilDecodeFeedback); err != nil {
				return false
			}
		}
		return false
	}

	isPackEncapsulated := func(dnsPacket *layers.DNS, transportPayload []byte) bool {
		if dnsPacket == nil {
			return false
		}

		// vxland tunnel encap is always over udp vlan id based port whole packet encap

		eth := layers.EtherIP{}

		if err := eth.DecodeFromBytes(transportPayload, gopacket.NilDecodeFeedback); err != nil {
			return false
		}

		l3Payload := eth.Payload

		ipv4 := layers.IPv4{}
		ipv6 := layers.IPv6{}

		if err := ipv4.DecodeFromBytes(l3Payload, gopacket.NilDecodeFeedback); err != nil {
			// no t a ipv4 encap vxlan packet
			return false
		}
		if err := ipv6.DecodeFromBytes(l3Payload, gopacket.NilDecodeFeedback); err != nil {
			return false
		}
		return parseUdpEncap(nil, &ipv6)
	}

	// this will always exist since the kenrel will only allow a l4 packet to reach to this bridge in user space via netfilter
	packetTransportLayer := packet.TransportLayer()
	if packetTransportLayer == nil {
		if utils.DEBUG {
			log.Println("the packet does not have a transport layer")
		}
		// runtime chekc although this would never ever happen since the l4 is always checked in kernel
		// not event a dns packet
		return
	}

	udpPack := packet.Layer(layers.LayerTypeUDP)
	tcpPack := packet.Layer(layers.LayerTypeTCP)

	transportPayload := packetTransportLayer.LayerPayload()
	if len(transportPayload) < 12 {
		if utils.DEBUG {
			log.Println("error while parsing the packet from kernel has header lenght to small")
		}
		// the kernel already have marked this as 0 no need to process anything
		// cannot be a dns packet
		return
	}

	dns := &layers.DNS{}

	err := dns.DecodeFromBytes(transportPayload, gopacket.NilDecodeFeedback)
	if err != nil {
		if utils.DEBUG {
			log.Println("error while parsing the packet from kernel")
		}
		return // not a dns packet
	}

	// Check for DNS layer directly
	if utils.DEBUG {
		log.Println("Received a DNS packet for tunnel .....")
	}
	// a tunneled dns packet overlay over the protocol

	if udpPack != nil {
		destPort := udpPack.(*layers.UDP).DstPort
		var destPortGenType uint16 = uint16(destPort)
		var event events.ExfilRawPacketMirror
		if err := ebpfMap.Lookup(&destPortGenType, &event); err != nil {

			if errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Println("The malware c2c agent is retrying to tunnel c2c exfiltrated traffic over ", destPort)
			} else {
				errorChannel <- struct {
					Err string
				}{
					Err: "The kernel has not cloned the packet from tc layer",
				}
			}
			return
		}

		if isPackEncapsulated(dns, transportPayload) {
			return
		}
		event.IsPacketRescanedAndMalicious = uint8(1)
		features, err := model.ProcessDnsFeatures(dns, true)

		if err != nil {
			log.Println("err is ", err)

			errorChannel <- struct {
				Err string
			}{
				Err: "Error while processing the dns packet features extraction for the malicious tunnel dns traffic over random port from kernel",
			}
		}

		tun.EnsureTransportTunnelPortMapUpdate(ebpfMap, destPortGenType, &event, errorChannel, false)

		for _, feature := range features {
			go events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(feature), &tun.IfaceHandler.PhysicalNodeBridgeIpv4, "DNS", int(destPort))
			go tun.StreamClient.MarshallThreadEvent(feature)
		}

		// the tunnel metric event for other non stanard port monitor from kernel
		go events.ExportPromeEbpfExporterEvents[events.Malicious_Non_Stanard_Transfer](events.Malicious_Non_Stanard_Transfer{
			Src_port:       int(event.SrcPort),
			Dest_port:      int(event.DstPort),
			IsUDPTransport: true,
		})

	} else {
		destPort := tcpPack.(*layers.TCP).DstPort
		var destPortGenType uint16 = uint16(destPort)
		// kernel will take care to process and set the packet type when kernel redirect iva link clone to the userspace
		var event events.ExfilRawPacketMirror
		log.Println("the dest port for packet transfer is ", uint16(destPort))
		if err := ebpfMap.Lookup(&destPortGenType, &event); err != nil {
			log.Printf("The kernel has not cloned the packet from tc layer")
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				errorChannel <- struct {
					Err string
				}{
					Err: "The kernel has not cloned the packet from tc layer",
				}
			} else {
				log.Println("The malware c2c agent is retrying to tunnel c2c exfiltrated traffic over ", destPort)
			}
			return
		}

		features, err := model.ProcessDnsFeatures(dns, true)
		if err != nil {
			errorChannel <- struct {
				Err string
			}{
				Err: "Error while processing the dns packet features extraction for the malicious tunnel dns traffic over random port from kernel",
			}
		}

		tun.EnsureTransportTunnelPortMapUpdate(ebpfMap, destPortGenType, &event, errorChannel, false)

		for _, feature := range features {
			go events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(feature), &tun.IfaceHandler.PhysicalNodeBridgeIpv4, "DNS", int(destPort))
		}

		go events.ExportPromeEbpfExporterEvents[events.Malicious_Non_Stanard_Transfer](events.Malicious_Non_Stanard_Transfer{
			Src_port:       int(event.SrcPort),
			Dest_port:      int(event.DstPort),
			IsUDPTransport: false,
		})
	}
}
