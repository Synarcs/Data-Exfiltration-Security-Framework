package actions

import (
	"reflect"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
)

// will be be invoked by the stream events post consumed events from controller to reprogram data plane
// this is meant to reporgram the kernel TC egress classification based on the security policy enforced by controller

type EventAckKernelFilter struct {
	EgresseBPFKernelTCCollection        *ebpf.Collection
	EgresseBPFKernelTCCollectionProgram *ebpf.Program
	NetIface                            *netinet.NetIface
}

func (ev *EventAckKernelFilter) UpdateKernelTCFilterEgressDNSLimits(dynamicKernelFeatureUpdate *events.DNSKernelFeatureLimits) error {
	// the collection would have been initalized from the main gorountine to only start consuming events post the root kernel eBPF programs are injected
	dnsLimitsMap := ev.EgresseBPFKernelTCCollection.Maps[events.EXFILL_SECURITY_KERNEL_DNS_LIMITS_MAP]

	// update the limits
	if dnsLimitsMap != nil {

		val := reflect.ValueOf(dynamicKernelFeatureUpdate)

		for i := 0; i < val.NumField(); i++ {
			limitVal := uint32(val.Field(i).Uint())
			err := dnsLimitsMap.Update(
				i, limitVal, ebpf.UpdateAny,
			)
			if err != nil {
				utils.Log("error loading the dns limits in kernel Default in Kernel Loaded BPF object")
				return err
			}
		}
	}
	return nil
}
