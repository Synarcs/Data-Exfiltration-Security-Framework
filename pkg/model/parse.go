package model

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

type DnsParserActions interface{}

type DnsParser struct {
}

type DnsPacketGen struct{}

func (d *DnsPacketGen) GenerateDnsPacket(ipLayer, udpLayer, dnsLayer gopacket.Layer) *dns.Msg {
	dnsPacket := dns.Msg{}

	dns, err := dnsLayer.(*layers.DNS)
	if err {
		log.Println("Error parsing the dns header return")
		return nil
	}
	if dns != nil {
		dnsPacket.Id = dns.ID
		dnsPacket.RecursionDesired = dns.QR
		dnsPacket.RecursionAvailable = dns.QR
		dnsPacket.Opcode = int(dns.OpCode)
		dnsPacket.Response = dns.QR
	} else {
		log.Println("Error in parsing the DNS packet address")
	}
	return nil

}
