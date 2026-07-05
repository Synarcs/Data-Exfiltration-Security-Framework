/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package tc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/vishvananda/netlink"
)

var sniffPortUspaceLock sync.RWMutex = sync.RWMutex{}

var vniPackTransferCount map[int]int = make(map[int]int)

type VxlandEncapListner struct{}

// use this to send an sig kill for pcap to clean packet socket over bpf from kernel sed for sniffing, especially cleaning the fd  from the map
var (
	dport_tunnel_pcap                 map[uint16]chan bool = make(map[uint16]chan bool)
	dport_tunnel_pcap_rwlock          sync.RWMutex
	isdport_chan_cleaned_sniff        map[uint16]chan bool = make(map[uint16]chan bool)
	isdport_chan_cleaned_sniff_rwlock sync.RWMutex
)

const (
	POLL_TICKER_VXLAN_DURATION      = 10 * time.Minute // poll the vxlan encap tunnel every 10 minute interval
	POLL_TICKER_VXLAN_PCAP_DURATION = 5 * time.Minute  // poll the pcap handle over every 5 minute interval
)

func (tc *TCHandler) ExportVxlanTunnelDnsTrafficMetric(vni int, srcPort uint16, dstPort uint16,
	dnsPacket *layers.DNS) {
	sniffPortUspaceLock.Lock()
	defer sniffPortUspaceLock.Unlock()
	if _, fd := vniPackTransferCount[vni]; !fd {
		vniPackTransferCount[vni] = 1
	} else {
		vniPackTransferCount[vni] += 1
	}

	getAllDomainsINEncapDNs := func() []string {
		var domains []string
		if dnsPacket.QDCount > 0 {
			// all question record for dns added
			for _, questions := range dnsPacket.Questions {
				domains = append(domains, string(questions.Name))
			}
		}
		if dnsPacket.ARCount > 0 {
			// auth encap dns
			for _, auth := range dnsPacket.Authorities {
				domains = append(domains, string(auth.Name))
			}
		}
		if dnsPacket.NSCount > 0 {
			// additional encap dns
			for _, ns := range dnsPacket.Additionals {
				domains = append(domains, string(ns.Name))
			}
		}
		return domains
	}

	// get the active live net_device fetched from netlink socket running vxlan encapsulation
	vxlanTunnelInterface, err := tc.GetTunnelLinkInterfaceInfo(dstPort)
	if err != nil {
		// dont emit event, since the vxlan tunnel is gone and netlink cannot find vxlan interface with the udp dst port
		utils.Log("The Required Dst UDP port vxlan tunnel net_device not found", err)
		return
	}

	events.ExportPromeEbpfExporterEvents[events.VxlanEncapKenrelEvent](events.VxlanEncapKenrelEvent{
		Vni:                   uint32(vxlanTunnelInterface.VxlanId),
		Udp_src_port:          srcPort,
		Udp_dst_port:          dstPort,
		L3_tunnel_address:     vxlanTunnelInterface.Group.String(), // pass the endpoint of tunnel on c2 exfil machine
		L2_tunnel_mac_address: "",                                  // also get the roo mac address from the link on device for remote vtep
		Domains:               getAllDomainsINEncapDNs(),
	})
}

func (tc *TCHandler) VerifyVTEPDestPortRange(portLow, portHigh, port int) bool {
	if portHigh == portLow || (portLow == 0 && portHigh == 0) {
		return false
	}
	return true
}

// let the kernel eBPF egress TC know for the physical netdev is carrying an encap traffic for deep DPI to prevent any breakc, or c2 commands
func (tc *TCHandler) PopulateVTEPUDPDestPorts() error {
	for ifIndex, vxlanNetdev := range tc.Interfaces.VxlanLinks {
		if !tc.VerifyVTEPDestPortRange(vxlanNetdev.PortLow, vxlanNetdev.PortHigh, vxlanNetdev.Port) {
			utils.Log("the custom dst port transfer for vxlan link configured :: ", vxlanNetdev)
		} else {
			for port := vxlanNetdev.PortLow; port <= vxlanNetdev.PortHigh; port++ {
				utils.Log("range port configured for netdev if_index over vxlan ", ifIndex, vxlanNetdev.PortLow, vxlanNetdev.PortHigh)
			}
		}
	}
	return nil
}

func (tc *TCHandler) GetTunnelLinkInterfaceInfo(dstPort uint16) (*netlink.Vxlan, error) {

	// TODO: optimize this
	// kerel use dest  port for vxlan encap over ht the link and it should be there on the net_device matching a vxlan
	for _, vxlanNetdev := range tc.Interfaces.VxlanLinks {
		if !tc.VerifyVTEPDestPortRange(vxlanNetdev.PortLow, vxlanNetdev.PortHigh, vxlanNetdev.Port) {
			// kernel vvxlan_xmit_skb defailts to 4789
			if vxlanNetdev.Port == int(dstPort) {
				return vxlanNetdev, nil
			}
		} else if vxlanNetdev.PortLow <= int(dstPort) && vxlanNetdev.PortHigh >= int(dstPort) {
			return vxlanNetdev, nil
		}
	}
	utils.Log("Error getting the vxlan tunnel interfaces", dstPort)
	return nil, fmt.Errorf("Error getting the vxlan tunnel interfaces")
}

func (tc *TCHandler) UpdateVxlanDestPortTransferMapDrop(dstPort uint16, ebpfMap *ebpf.Map) error {
	var blockFlag uint8 = 1 // tells kernel egress clsact tc fitler to start dropping vlxand encap tunnel dns packet and repeat DPI process
	if err := ebpfMap.Put(&dstPort, &blockFlag); err != nil {
		return fmt.Errorf("Error updating the ebPF map with the malicious drop flag for kernel top drop packets in egress TC %+v", err)
	}
	return nil
}

func (tc *TCHandler) DeepScanVxlanPacketencap(pack gopacket.Packet, ebpfMap *ebpf.Map) error {
	udp := pack.Layer(layers.LayerTypeUDP)
	if udp == nil {
		// not possible since this is encap vxlan packet from kernel trace but ensure there is no null check over pack
		return nil
	}

	udpPacket := udp.(*layers.UDP)
	payload := udpPacket.Payload

	vxlanPacket := gopacket.NewPacket(
		payload,
		layers.LayerTypeVXLAN,
		gopacket.Default,
	)

	vxlanLayer := vxlanPacket.Layer(layers.LayerTypeVXLAN)
	if vxlanLayer != nil {
		vxlanPacket := vxlanLayer.(*layers.VXLAN)
		innerPacket := gopacket.NewPacket(
			vxlanPacket.LayerPayload(),
			layers.LayerTypeEthernet,
			gopacket.Default,
		)

		isDnsLayerPresent := false
		if udpLayer := innerPacket.Layer(layers.LayerTypeUDP); udpLayer != nil {
			srcPort := udpLayer.(*layers.UDP).SrcPort
			dstPort := udpLayer.(*layers.UDP).DstPort
			if layer := innerPacket.Layer(layers.LayerTypeDNS); layer != nil {
				dnsLayer := layer.(*layers.DNS)
				utils.Log("Sniffed DNS traffic over vxlan encap ", dnsLayer)
				tc.ExportVxlanTunnelDnsTrafficMetric(int(vxlanPacket.VNI), uint16(srcPort), uint16(dstPort), dnsLayer)
				if err := tc.UpdateVxlanDestPortTransferMapDrop(uint16(dstPort), ebpfMap); err != nil {
					utils.Log(err.Error())
				}
				isDnsLayerPresent = true
			}
		} else if tcpLayer := innerPacket.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			srcPort := udpLayer.(*layers.TCP).SrcPort
			dstPort := udpLayer.(*layers.TCP).DstPort
			if layer := innerPacket.Layer(layers.LayerTypeDNS); layer != nil {
				dnsLayer := layer.(*layers.DNS)
				utils.Log("Sniffed DNS traffic over vxlan encap ", dnsLayer)
				tc.ExportVxlanTunnelDnsTrafficMetric(int(vxlanPacket.VNI), uint16(srcPort), uint16(dstPort), dnsLayer)
				if err := tc.UpdateVxlanDestPortTransferMapDrop(uint16(dstPort), ebpfMap); err != nil {
					utils.Log(err.Error())
				}
				isDnsLayerPresent = true
			}
		}
		if !isDnsLayerPresent {
			utils.Log("Sniffed traffic over VNI for vxlan encap, no DNS encap in vxlan packed", vxlanPacket.VNI)
		} else {
			utils.Log("Sniffed traffic over VNI for vxlan, contains DNS encap in vxlan", vxlanPacket.VNI)
		}
	}

	return nil
}

func (tc *TCHandler) getdportchanRLock(event *events.DPIVxlanKernelEncapEvent) chan bool {
	isdport_chan_cleaned_sniff_rwlock.RLock()
	defer isdport_chan_cleaned_sniff_rwlock.Unlock()
	return isdport_chan_cleaned_sniff[event.Transport_Dest_Port]
}

// Ensure there are cancellable context or deadline to ensure optimized controlled over go routines and their cancellation
func (tc *TCHandler) SniffPcapVxlanTrafficPort(
	event *events.DPIVxlanKernelEncapEvent,
	ebpfMap *ebpf.Map,
) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	dport_tunnel_pcap_rwlock.Lock()
	if _, fd := dport_tunnel_pcap[event.Transport_Dest_Port]; fd {
		// there is already an pcap live handler snifing traffic over pcap
		dport_tunnel_pcap_rwlock.Unlock()
		return nil
	}
	dport_tunnel_pcap_rwlock.Lock()

	defer func() {
		utils.Log("free the port for next sniff")
		dport_tunnel_pcap[event.Transport_Dest_Port] <- true
		dport_tunnel_pcap_rwlock.Unlock()
	}()

	dport_tunnel_pcap[event.Transport_Dest_Port] = make(chan bool)
	// for now get the root physical based on egress if_index  later ensure it maps to skb egress link from kernel
	utils.Log("Init Pcap hanle to live sniff for deep user-sapce inspacetion for any exfil traffic in vxlan encap", event)

	// start sniffing the traffic and make sure any vxlan traffi sniff parses l7 exfiltrated payload for dns
	pcapHandle, err := tc.Interfaces.GetRootNamespacePcapHandle()

	time.AfterFunc(POLL_TICKER_VXLAN_DURATION, func() {
		utils.Log("Closing the pcap handle for vxlan encap traffic over udp port and release block", event.Transport_Dest_Port)
		pcapHandle.Close() // closes after userspace stops polling over pcap bpf filter
	})

	if err != nil {
		utils.Logger.Printf("Error getting root namespace pcap handle %v", err)
	}
	// parse the header DPI for vxlan encap
	utils.Log("Using the kernel filter for bpf ", fmt.Sprintf("udp dst port %d", event.Transport_Dest_Port))
	if err := pcapHandle.SetBPFFilter(fmt.Sprintf("udp dst port %d", event.Transport_Dest_Port)); err != nil {
		utils.Logger.Printf("Error opening the pcap handling on udp port for vxlan transfer %d", event.Transport_Dest_Port)
		return err
	}

	packets := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

	for pack := range packets.Packets() {
		if utils.DEBUG {
			utils.Log("Sniffing the udp service port for vxlan encap packets from kernel ebpf ring event ", pack.Layers())
		}
		go tc.DeepScanVxlanPacketencap(pack, ebpfMap)
	}

	return nil
}

func (tc *TCHandler) PollVxlanRingBuffer(ctx context.Context, ebpfMap *ebpf.Map) error {

	vxlanEncapMap := tc.TcCollection.Maps[events.EXFIL_SECURITY_EGRESS_VXLAN_ENCAP_DROP]
	if vxlanEncapMap == nil {
		utils.Logger.Printf("Cannot poll the nil map from kernel for an empty Vxlan or non init ring buff")
		return nil
	}

	ringbuffer, err := ringbuf.NewReader(vxlanEncapMap)
	if err != nil {
		return err
	}

	defer ringbuffer.Close()

	closeSniffSignalHandler := func(event *events.DPIVxlanKernelEncapEvent) {
		var rxPollerLock chan bool = tc.getdportchanRLock(event)

		for {
			select {
			case <-rxPollerLock:
				// we dont need mutex here since kernel own multiple fd per socket and at a time its not possible we sniff over same socket across multiple goroutines
				// cannot deadlock due to released lock prevent each dport fd starvation
				dport_tunnel_pcap_rwlock.Lock()
				close(dport_tunnel_pcap[event.Transport_Dest_Port])
				delete(dport_tunnel_pcap, event.Transport_Dest_Port)
				dport_tunnel_pcap_rwlock.Unlock()

				isdport_chan_cleaned_sniff_rwlock.Lock()
				isdport_chan_cleaned_sniff[event.Transport_Dest_Port] = make(chan bool)
				isdport_chan_cleaned_sniff[event.Transport_Dest_Port] <- true
				isdport_chan_cleaned_sniff_rwlock.Unlock()
			default:
				time.Sleep(time.Second)
			}
		}
	}

	// kernel make sure the event is emitted with epoll internally to submit event to user space via ring buffer
	for {
		record, err := ringbuffer.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			// likely the ring buff closed or there is a padding issue for reing buff value read
			break
		}

		var event events.DPIVxlanKernelEncapEvent
		if utils.CpuArch() == "arm64" || utils.CpuArch() == "amd64" {
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
				continue
			}

			var rxPollerLock chan bool = tc.getdportchanRLock(&event)

			utils.Log("Polled an kernel event for vxlan encap from the kernel ringbuffer ", event.Transport_Dest_Port)
			select {
			case <-rxPollerLock:
				// it mean the sniff channel was cleaned post sniff interval
				// start interval based sniffing again to sniff vxlan port for any vxlan encap traffic

				isdport_chan_cleaned_sniff_rwlock.Lock()
				close(isdport_chan_cleaned_sniff[event.Transport_Dest_Port])
				delete(isdport_chan_cleaned_sniff, event.Transport_Dest_Port)
				isdport_chan_cleaned_sniff_rwlock.Unlock()

				go tc.SniffPcapVxlanTrafficPort(&event, ebpfMap)
			default:
				if _, fd := dport_tunnel_pcap[event.Transport_Dest_Port]; !fd {
					utils.Log("Start sniffing the port for vxlan encap traffic since the interval clean not found in map")
					go tc.SniffPcapVxlanTrafficPort(&event, ebpfMap)
				}
			}
			go closeSniffSignalHandler(&event)
		} else {
			utils.Log("Polling the ring buffer for the x86 big endian systems")
			err = binary.Read(bytes.NewReader(record.RawSample), binary.BigEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}

			var rxPollerLock chan bool = tc.getdportchanRLock(&event)

			utils.Log("Polled an kernel event for vxlan encap from the kernel ringbuffer ", event.Transport_Dest_Port)
			select {
			case <-rxPollerLock:
				// it mean the sniff channel was cleaned post sniff interval
				// start interval based sniffing again to sniff vxlan port for any vxlan encap traffic

				isdport_chan_cleaned_sniff_rwlock.Lock()
				close(isdport_chan_cleaned_sniff[event.Transport_Dest_Port])
				delete(isdport_chan_cleaned_sniff, event.Transport_Dest_Port)
				isdport_chan_cleaned_sniff_rwlock.Unlock()

				go tc.SniffPcapVxlanTrafficPort(&event, ebpfMap)
			default:
				if _, fd := dport_tunnel_pcap[event.Transport_Dest_Port]; !fd {
					utils.Log("Start sniffing the port for vxlan encap traffic since the interval clean not found in map")

					go tc.SniffPcapVxlanTrafficPort(&event, ebpfMap)
				}
			}
			go tc.SniffPcapVxlanTrafficPort(&event, ebpfMap)
			utils.Log("Vxland Event polled from kernel non standard port init sniff to ensure the port is not exfiltrating data", event)
		}
	}

	return nil
}
