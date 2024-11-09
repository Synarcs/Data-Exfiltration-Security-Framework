package model

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/asavie/xdp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
)

type DnsParserActions interface{}

type DnsParser struct {
}

type DnsPacketGen struct {
	IfaceHandler        *netinet.NetIface
	SockSendFdInterface []netlink.Link
	SocketSendFd        *int
	XdpSocketSendFd     *xdp.Socket
	OnnxModel           *OnnxModel
}

type CombinedFeatures []DNSFeatures

func (d *DnsPacketGen) GenerateDnsPacket(dns layers.DNS) layers.DNS {
	return layers.DNS{
		BaseLayer:    layers.BaseLayer{},
		ID:           dns.ID,
		QR:           dns.QR,
		OpCode:       dns.OpCode,
		AA:           dns.AA,
		TC:           dns.TC,
		RD:           dns.RD,
		RA:           dns.RA,
		Z:            dns.Z,
		ResponseCode: dns.ResponseCode,
		QDCount:      dns.QDCount,
		ANCount:      dns.ANCount,
		NSCount:      dns.NSCount,
		ARCount:      dns.ARCount,
		Questions:    dns.Questions,
		Answers:      dns.Answers,
		Authorities:  dns.Authorities,
		Additionals:  dns.Additionals,
	}
}

// only use for l3 -> ipv4 and l4 -> udp
func (d *DnsPacketGen) EvaluateGeneratePacket(ethLayer, networkLayer, transportLayer, dnsLayer gopacket.Layer,
	l3_bpfMap_checksum uint16, handler *pcap.Handle, isEgress bool, isIpv4, isUdp bool) error {

	st := time.Now().Nanosecond()
	if utils.DEBUG {
		log.Println("[x] Recrafting the entire DNS packet")
	}
	ethernet := ethLayer.(*layers.Ethernet)

	var ipv4 *layers.IPv4
	var ipv6 *layers.IPv6

	if isIpv4 {
		ipv4 = networkLayer.(*layers.IPv4)
		ipv4.DstIP = d.IfaceHandler.PhysicalRouterGatewayV4
		ipv4.Checksum = l3_bpfMap_checksum
	} else {
		ipv6 = networkLayer.(*layers.IPv6)
		// TODO: Need a fix the router not sending solicitation ra response
		ipv6.DstIP = net.ParseIP("fe80::cc08:faff:fe26:a064").To16()
	}

	var udpPacket *layers.UDP
	var tcpPacket *layers.TCP

	if isUdp {
		udpPacket = transportLayer.(*layers.UDP)
	} else {
		tcpPacket = transportLayer.(*layers.TCP)
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		log.Println("Error parsing the dns header return")
		return fmt.Errorf("error parsing DNS layer")
	}

	if utils.DEBUG {
		fmt.Println("src ip is", ipv4.SrcIP.To4(), "dest ip ", ipv4.DstIP.To4())
		fmt.Println("src port is", udpPacket.SrcPort, "dest port ", udpPacket.DstPort)
	}

	features, err := ProcessDnsFeatures(dns, isEgress)

	if err != nil {
		log.Println("Error generating the features over the packet", err)
		return err
	}

	isBenign := d.OnnxModel.Evaluate(features, "DNS", isEgress)

	if !isBenign {
		log.Println("Malicious DNS Exfiltrated Qeury Found Dropping the packet")
		// add the tld and domain information in packet malicious map for local cache
		var castFeature events.DNSFeatures = events.DNSFeatures(features[0])
		events.ExportMaliciousEvents(castFeature)
		return nil
	}

	if utils.DEBUG {
		log.Println("Packet Found benign after Deep Lexical Scan Resending the packet")
	}

	dnsPacket := d.GenerateDnsPacket(*dns)

	buffer := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if isIpv4 && isUdp {
		// ipv4 and udp
		udpPacket.SetNetworkLayerForChecksum(ipv4)
		if err := gopacket.SerializeLayers(buffer, opts, ethernet, ipv4, udpPacket, &dnsPacket); err != nil {
			log.Println("Error reconstructing the DNS packet", err)
			return err
		}
	} else if !isIpv4 && isUdp {
		// ipv6 and udp
		opts.ComputeChecksums = false
		udpPacket.SetNetworkLayerForChecksum(ipv6)
		if err := gopacket.SerializeLayers(buffer, opts, ethernet, ipv6, udpPacket, &dnsPacket); err != nil {
			log.Println("Error reconstructing the DNS packet", err)
			return err
		}
	} else if isIpv4 && !isUdp {
		// ipv4 and tcp
		tcpPacket.SetNetworkLayerForChecksum(ipv4)
		fmt.Println("tcp packet", tcpPacket)
		if err := gopacket.SerializeLayers(buffer, opts, ethernet, ipv4, tcpPacket, &dnsPacket); err != nil {
			log.Println("Error reconstructing the DNS packet", err)
			return err
		}
	} else if !isIpv4 && !isUdp {
		// ipv6 and tcp
		opts.ComputeChecksums = false
		tcpPacket.SetNetworkLayerForChecksum(ipv6)
		if err := gopacket.SerializeLayers(buffer, opts, ethernet, ipv6, tcpPacket, &dnsPacket); err != nil {
			log.Println("Error reconstructing the DNS packet", err)
			return err
		}
	}

	if utils.DEBUG {
		// serialize := time.Now().Nanosecond()
		log.Println("time took to serialize the whole packet", time.Now().Nanosecond()-st)
	}
	outputPacket := buffer.Bytes()
	outputPacketLen := len(outputPacket)

	if d.XdpSocketSendFd == nil {
		// first check and bind the xdp kernel socket to tx queue for the interface
		sockAddr := syscall.SockaddrLinklayer{
			Protocol: syscall.ETH_P_ALL,
			Ifindex:  d.SockSendFdInterface[0].Attrs().Index,
		}

		// need this to be replaced with xdp
		if err := syscall.Sendto(*d.SocketSendFd, outputPacket, 0, &sockAddr); err != nil {
			return err
		}
	} else {
		// inject the packet directly into the tx queue for the xdp bypassing the entire linux kernel network stack
		// eventually free up some of the bpf maps in tc from the kernel space

		fx := d.XdpSocketSendFd.GetDescs(d.XdpSocketSendFd.NumFreeTxSlots())
		for i := range fx {
			fx[i].Len = uint32(outputPacketLen)
		}
		trxCount := d.XdpSocketSendFd.Transmit(fx)
		log.Println("Transmitted framecount is ", trxCount)
	}

	return nil
}
