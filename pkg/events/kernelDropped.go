package events

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func HandleKernelDroppedPacket(dnsLayer gopacket.Layer, isIpv4, isUdp bool, protocol string) error {

	switch protocol {
	case "DNS":
		dnsPacket := dnsLayer.(*layers.DNS)
		log.Println("the malicious packet found in kernel redirecetd for monitoring is ", dnsPacket)
	default:
		log.Println("The Protocol not supported for threat streaming of teh message")
	}
	if dnsLayer != nil {
	}
	return nil

}
