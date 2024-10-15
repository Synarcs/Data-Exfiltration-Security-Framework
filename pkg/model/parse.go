package model

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

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
		Authorities:  dns.Additionals,
		Additionals:  dns.Additionals,
	}
}

// only use for l3 -> ipv4 and l4 -> udp
func (d *DnsPacketGen) EvaluateGeneratePacket(ethLayer, ipLayer, udpLayer, dnsLayer gopacket.Layer,
	l3_bpfMap_checksum uint16, handler *pcap.Handle, isEgress bool) error {

	st := time.Now().Nanosecond()
	if utils.DEBUG {
		log.Println("[x] Recrafting the entire DNS packet")
	}
	ethernet := ethLayer.(*layers.Ethernet)

	ipv4 := ipLayer.(*layers.IPv4)

	// do feature engineering

	// gw := net.IP(d.IfaceHandler.PhysicalRouterGateway)

	ipv4.DstIP = net.IP{192, 168, 64, 1}
	ipv4.Checksum = l3_bpfMap_checksum

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		log.Println("Error parsing the dns header return")
		return fmt.Errorf("error parsing DNS layer")
	}

	udpPacket := udpLayer.(*layers.UDP)
	udpPacket.SetNetworkLayerForChecksum(ipv4)

	if utils.DEBUG {
		fmt.Println("src ip is", ipv4.SrcIP.To4(), "dest ip ", ipv4.DstIP.To4())
		fmt.Println("src port is", udpPacket.SrcPort, "dest port ", udpPacket.DstPort)
	}

	features, err := ProcessDnsFeatures(dns, isEgress)

	if err != nil {
		log.Println("Error generating the features over the packet", err)
		return err
	}

	isBenign := d.OnnxModel.Evaluate(features, "DNS")

	if !isBenign {
		log.Println("Malicious DNS Exfiltrated Qeury Found Dropping the packet")
		// add the tld and domain information in packet malicious map for local cache
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

	if err := gopacket.SerializeLayers(buffer, opts, ethernet, ipv4, udpPacket, &dnsPacket); err != nil {
		log.Println("Error reconstructing the DNS packet", err)
		return err
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
