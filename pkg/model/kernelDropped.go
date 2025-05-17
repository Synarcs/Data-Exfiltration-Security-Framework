package model

import (
	"context"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func HandleKernelDroppedPacket[T events.Protocol](
	ctx context.Context, dnsLayer gopacket.Layer, isIpv4, isUdp bool, protocol T,
	nodeIface *netinet.NetIface) {

	if err := ctx.Done(); err != nil {
		return
	}

	switch protocol {
	case T(events.DNS):
		dnsPacket := dnsLayer.(*layers.DNS)
		kernelDroppedFeatures, err := ProcessDnsFeatures(dnsPacket, true)
		if err != nil {
			return
		}
		for _, feature := range kernelDroppedFeatures {
			go events.ExportMaliciousEvents(events.DNSFeatures(feature), &nodeIface.PhysicalNodeBridgeIpv4, events.DNS, 53, nil)
		}
		if dnsPacket.QDCount >= 1 {
			for _, maliciousQuest := range dnsPacket.Questions {
				utils.Log("the malicious packet found in kernel redirecetd for monitoring is ", string(maliciousQuest.Name))
			}
		}
	default:
		utils.Log("The Protocol not supported for threat streaming of teh message")
	}
}
