package events

import (
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func HandleKernelDroppedPacket(dnsLayer gopacket.Layer, isIpv4, isUdp bool, protocol string) error {

	switch protocol {
	case "DNS":
		dnsPacket := dnsLayer.(*layers.DNS)
		utils.Log("the malicious packet found in kernel redirecetd for monitoring is ", dnsPacket)
	default:
		utils.Log("The Protocol not supported for threat streaming of teh message")
	}
	if dnsLayer != nil {
	}
	return nil

}
