package xdp

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
)

type IngressSniffHandler struct {
	IfaceHandler *netinet.NetIface
	Ctx          context.Context
}

func (ing *IngressSniffHandler) SniffEgressForC2C() error {
	var errorChannel chan error = make(chan error)
	log.Println("Sniffing Ingress traffic for potential malicious remote C@C commands")

	// do deep lexcial analysis of the packet over the ingress for the response action set
	processPcapFilterHandlerIngress := func(linkInterface netlink.Link,
		errorChannel chan<- error, isUdp bool, isStandardPort bool) {
		cap, err := pcap.OpenLive(netinet.NETNS_NETLINK_BRIDGE_DPI, int32(linkInterface.Attrs().MTU), true, pcap.BlockForever)
		if err != nil {
			fmt.Println("error opening packet capture over hz,te interface from kernel")
			errorChannel <- err
		}
		defer cap.Close()

		if isUdp && isStandardPort {
			// runs over br netfilter layer on iptables
			if err := cap.SetBPFFilter("udp dst port 53"); err != nil {
				log.Fatalf("Error setting BPF filter: %v", err)
			}
		} else if !isUdp && isStandardPort {
			if err := cap.SetBPFFilter("tcp dst port 53"); err != nil {
				log.Fatalf("Error setting BPF filter: %v", err)
			}
		} else if !isUdp && !isStandardPort {
			err := "Not Implemented for non stard port DPI for DNS with no support for ebpf from kernel"
			fmt.Errorf("err %s", err)
		}

		packets := gopacket.NewPacketSource(cap, cap.LinkType())
		for _ = range packets.Packets() {
		}
	}

	for _, val := range ing.IfaceHandler.PhysicalLinks {
		go processPcapFilterHandlerIngress(val, errorChannel, true, true)
		go processPcapFilterHandlerIngress(val, errorChannel, false, true)

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
