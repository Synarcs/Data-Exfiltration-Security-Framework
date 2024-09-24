package model

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type DnsParserActions interface{}

type DnsParser struct {
}

type DnsPacketGen struct {
	IfaceHandler *netinet.NetIface
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
func (d *DnsPacketGen) GeneratePacket(ethLayer, ipLayer, udpLayer, dnsLayer gopacket.Layer,
	l3_bpfMap_checksum uint16, handler *pcap.Handle) error {

	st := time.Now().Nanosecond()
	log.Println("[x] Recrafting the entire DNS packet")
	ethernet := ethLayer.(*layers.Ethernet)

	ipv4 := ipLayer.(*layers.IPv4)
	ipv4.DstIP = net.IP{192, 168, 1, 1}
	ipv4.Checksum = l3_bpfMap_checksum
	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		log.Println("Error parsing the dns header return")
		return fmt.Errorf("error parsing DNS layer")
	}

	udpPacket := udpLayer.(*layers.UDP)

	dnsPacket := d.GenerateDnsPacket(*dns)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: false,
	}
	if err := gopacket.SerializeLayers(buffer, opts, ethernet, ipv4, udpPacket, &dnsPacket); err != nil {
		log.Println("Error reconstructing the DNS packet")
		return err
	}

	serialize := time.Now().Nanosecond()
	log.Println("time took to serialize the whole packet", time.Now().Nanosecond()-st)
	outputPacket := buffer.Bytes()

	if err := handler.WritePacketData(outputPacket); err != nil {
		log.Println("Error writing packet to pcap file")
		return err
	}

	log.Println("time took to send the whole packet", time.Now().Nanosecond()-serialize)
	return nil
}
