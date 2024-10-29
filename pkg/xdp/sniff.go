package xdp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
)

type IngressSniffHandler struct {
	IfaceHandler    *netinet.NetIface
	Ctx             context.Context
	OnnxLoadedModel *model.OnnxModel
	DnsFeatures     *model.DNSFeatures
	DnsPacketGen    *model.DnsPacketGen
}

// a builder facotry for the tc load and process all tc egress traffic over the different filter chain which node agent is running
func GenerateTcIngressFactory(iface netinet.NetIface, onnxModel *model.OnnxModel) IngressSniffHandler {
	return IngressSniffHandler{
		IfaceHandler:    &iface,
		DnsPacketGen:    model.GenerateDnsParserModelUtils(&iface, onnxModel),
		OnnxLoadedModel: onnxModel,
	}
}

func (ing *IngressSniffHandler) ProcessEachPacket(packet gopacket.Packet, ifaceHandler *netinet.NetIface, handler *pcap.Handle) error {

	eth := packet.Layer(layers.LayerTypeEthernet)
	var isIpv4 bool
	var isUdp bool
	if eth == nil {
		return fmt.Errorf("no ethernet layer")
	}

	// var ipPacket *layers.IPv4
	// var ipv6Packet *layers.IPv6

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		isIpv4 = false
	} else {
		isIpv4 = true
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

	dnsLayer := packet.Layer(layers.LayerTypeDNS)

	if dnsLayer != nil {
		_, _ = dnsLayer.(*layers.DNS)

		var ip_layer3_checksum_kernel_ts events.DPIRedirectionKernelMap // granualar timining control over the redirection from kernel

		if isIpv4 && isUdp {
			ing.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum, handler, true, isIpv4, isUdp)
			// ipv4 and udp
		}
		if !isIpv4 && isUdp {
			// ipv6 and udp
			ing.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum, handler, true, isIpv4, isUdp)
		}

	} else if tcpCheck {
		dns := &layers.DNS{}

		err := dns.DecodeFromBytes(dnsTcpPayload, gopacket.NilDecodeFeedback)
		if err != nil {
			log.Println("Error decoding the dns packet over the tcp stream", err)
			return err
		}

		var ip_layer3_checksum_kernel_ts events.DPIRedirectionKernelMap // granualar timining control over the redirection from kernel

		if isIpv4 && !isUdp {
			// ipv4 and tcp
			ing.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum, handler, true, isIpv4, isUdp)
		}
		if !isIpv4 && !isUdp {
			// ipv6 and tcp
			ing.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum, handler, true, isIpv4, isUdp)
		}
	}
	return nil
}

func (ing *IngressSniffHandler) SniffEgressForC2C() error {
	var errorChannel chan error = make(chan error)
	log.Println("Sniffing Ingress traffic for potential malicious remote C@C commands")

	// do deep lexcial analysis of the packet over the ingress for the response action set
	processPcapFilterHandlerIngress := func(linkInterface netlink.Link,
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
				log.Println("Generated Ingress Packet Listener to parse DNS packets from kernel over the UDP Layer")
			} else {
				log.Println("Generated Ingress Packet Listener to parse DNS packets from kernel over the TCP Layer")
			}
			if err := cap.SetBPFFilter("udp dst port 53 or tcp dst port 53"); err != nil {
				log.Fatalf("Error setting BPF filter: %v", err)
			}
		} else if !isUdp && !isStandardPort {
			err := "Not Implemented for non stard port DPI for DNS with no support for ebpf from kernel"
			return fmt.Errorf("err %s", err)
		}

		packets := gopacket.NewPacketSource(cap, cap.LinkType())
		for _ = range packets.Packets() {
			// go ing.ProcessEachPacket(pack, ing.IfaceHandler, cap)
		}
		return nil
	}

	for _, val := range ing.IfaceHandler.PhysicalLinks {
		go processPcapFilterHandlerIngress(val, errorChannel, true, true)
	}

	go func() {
		for {
			select {
			case err, close := <-errorChannel:
				if !close {
					return
				}
				if err != nil {
					panic(err.Error())
				}
			default:
				time.Sleep(time.Second)
			}
		}
	}()
	return nil
}
