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

var sniffPortUspaceLock sync.Mutex = sync.Mutex{}

var vniPackTransferCount map[int]int = make(map[int]int)

type VxlandEncapListner struct{}

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
		log.Println("The Required Dst UDP port vxlan tunnel net_device not found", err)
		return
	}

	// TODO: emit and encap tunnel prometheus event detection for vxlan
	events.ExportPromeEbpfExporterEvents[events.VxlanEncapKenrelEvent](events.VxlanEncapKenrelEvent{
		Vni:                   uint32(vxlanTunnelInterface.VxlanId),
		Udp_src_port:          srcPort,
		Udp_dst_port:          dstPort,
		L3_tunnel_address:     vxlanTunnelInterface.Group.String(), // pass the endpoint of tunnel on c2 exfil machine
		L2_tunnel_mac_address: "",                                  // also get the roo mac address from the link on device for remote vtep
		Domains:               getAllDomainsINEncapDNs(),
	})
}

func (tc *TCHandler) GetTunnelLinkInterfaceInfo(dstPort uint16) (*netlink.Vxlan, error) {
	encapTunnelVtepLinks, err := tc.Interfaces.GetVxlanTunnelInterfaces()
	if err != nil {
		log.Println("Error getting the vxlan tunnel interfaces", err)
		return nil, err
	}

	// kerel use dest  port for vxlan encap over ht the link and it should be there on the net_device matching a vxlan
	if vxlanLink, fd := encapTunnelVtepLinks[dstPort]; !fd {
		log.Println("Error getting the vxlan tunnel interfaces", err)
		return nil, fmt.Errorf("Error getting the vxlan tunnel interfaces")
	} else {
		return vxlanLink, nil
	}
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
		log.Println("Sniffed traffic over VNI for vxlan encap ", vxlanPacket.VNI)
		innerPacket := gopacket.NewPacket(
			vxlanPacket.LayerPayload(),
			layers.LayerTypeEthernet,
			gopacket.Default,
		)

		if udpLayer := innerPacket.Layer(layers.LayerTypeUDP); udpLayer != nil {
			srcPort := udpLayer.(*layers.UDP).SrcPort
			dstPort := udpLayer.(*layers.UDP).DstPort
			if layer := innerPacket.Layer(layers.LayerTypeDNS); layer != nil {
				dnsLayer := layer.(*layers.DNS)
				log.Println("Sniffed DNS traffic over vxlan encap ", dnsLayer)
				tc.ExportVxlanTunnelDnsTrafficMetric(int(vxlanPacket.VNI), uint16(srcPort), uint16(dstPort), dnsLayer)
				if err := tc.UpdateVxlanDestPortTransferMapDrop(uint16(dstPort), ebpfMap); err != nil {
					log.Println(err.Error())
				}
			}
		} else if tcpLayer := innerPacket.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			srcPort := udpLayer.(*layers.UDP).SrcPort
			dstPort := udpLayer.(*layers.UDP).DstPort
			if layer := innerPacket.Layer(layers.LayerTypeDNS); layer != nil {
				dnsLayer := layer.(*layers.DNS)
				log.Println("Sniffed DNS traffic over vxlan encap ", dnsLayer)
				tc.ExportVxlanTunnelDnsTrafficMetric(int(vxlanPacket.VNI), uint16(srcPort), uint16(dstPort), dnsLayer)
				if err := tc.UpdateVxlanDestPortTransferMapDrop(uint16(dstPort), ebpfMap); err != nil {
					log.Println(err.Error())
				}
			}
		}
	}

	return nil
}

// Ensure there are cancellable context or deadline to ensure optimized controlled over go routines and their cancellation
func (tc *TCHandler) SniffPcapVxlanTrafficPort(event *events.DPIVxlanKernelEncapEvent,
	controlChannelMap map[uint16]chan bool, isdport_chan_cleaned_sniff map[uint16]chan bool, ebpfMap *ebpf.Map) error {
	runtime.LockOSThread()

	if _, fd := controlChannelMap[event.Transport_Dest_Port]; fd {
		// there is already an pcap live handler snifing traffic over pcap
		log.Println("Error Please before init sniff over this packet ensure the packeet is added in sniff map channel")
		return nil
	}
	controlChannelMap[event.Transport_Dest_Port] = make(chan bool)
	// for now get the root physical based on egress if_index  later ensure it maps to skb egress link from kernel
	log.Println("Init Pcap hanle to live sniff for deep user-sapce inspacetion for any exfil traffic in vxlan encap", event)

	// start sniffing the traffic and make sure any vxlan traffi sniff parses l7 exfiltrated payload for dns
	pcapHandle, err := tc.Interfaces.GetRootNamespacePcapHandle()

	time.AfterFunc(POLL_TICKER_VXLAN_DURATION, func() {
		log.Println("Closing the pcap handle for vxlan encap traffic over udp port and release block", event.Transport_Dest_Port)
		pcapHandle.Close() // closes after userspace stops polling over pcap bpf filter
	})

	if err != nil {
		log.Printf("Error getting root namespace pcap handle %v", err)
	}
	// parse the header DPI for vxlan encap
	log.Println("Using the kernel filter for bpf ", fmt.Sprintf("udp dst port %d", event.Transport_Dest_Port))
	if err := pcapHandle.SetBPFFilter(fmt.Sprintf("udp dst port %d", event.Transport_Dest_Port)); err != nil {
		log.Printf("Error opening the pcap handling on udp port for vxlan transfer %d", event.Transport_Dest_Port)
		return err
	}

	packets := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

	for pack := range packets.Packets() {
		if utils.DEBUG {
			log.Println("Sniffing the udp service port for vxlan encap packets from kernel ebpf ring event ", pack.Layers())
		}
		go tc.DeepScanVxlanPacketencap(pack, ebpfMap)
	}
	defer func() {
		log.Println("free the port for next sniff")
		controlChannelMap[event.Transport_Dest_Port] <- true
	}()

	return nil
}

func (tc *TCHandler) PollVxlanRingBuffer(ctx context.Context, ebpfMap *ebpf.Map) error {

	vxlanEncapMap := tc.TcCollection.Maps[events.EXFIL_SECURITY_EGRESS_VXLAN_ENCAP_DROP]
	if vxlanEncapMap == nil {
		log.Printf("Cannot poll the nil map from kernel for an empty Vxlan or non init ring buff")
		return nil
	}

	// use this to send an sig kill for pcap to clean packet socket over bpf from kernel sed for sniffing, especially cleaning the fd  from the map
	var dport_tunnel_pcap map[uint16]chan bool = make(map[uint16]chan bool)
	var isdport_chan_cleaned_sniff map[uint16]chan bool = make(map[uint16]chan bool)

	ringbuffer, err := ringbuf.NewReader(vxlanEncapMap)
	if err != nil {
		return err
	}

	closeSniffSignalHandler := func(event *events.DPIVxlanKernelEncapEvent, closeSniffSignalMap map[uint16]chan bool) {
		// runs as the root cleanup sock event to ensure the associated fd are cleaned from the kernel
		for {
			select {
			case <-closeSniffSignalMap[event.Transport_Dest_Port]:
				// we dont need mutex here since kernel own multiple fd per socket and at a time its not possible we sniff over same socket across multiple goroutines
				close(closeSniffSignalMap[event.Transport_Dest_Port])
				delete(closeSniffSignalMap, event.Transport_Dest_Port)
				isdport_chan_cleaned_sniff[event.Transport_Dest_Port] = make(chan bool)
				isdport_chan_cleaned_sniff[event.Transport_Dest_Port] <- true
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
			panic(err.Error())
		}

		var event events.DPIVxlanKernelEncapEvent
		if utils.CpuArch() == "arm64" {
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}

			log.Println("Polled an kernel event for vxlan encap from the kernel ringbuffer ", event.Transport_Dest_Port)
			select {
			case <-isdport_chan_cleaned_sniff[event.Transport_Dest_Port]:
				// it mean the sniff channel was cleaned post sniff interval
				// start interval based sniffing again to sniff vxlan port for any vxlan encap traffic
				close(isdport_chan_cleaned_sniff[event.Transport_Dest_Port])
				delete(isdport_chan_cleaned_sniff, event.Transport_Dest_Port)
				go tc.SniffPcapVxlanTrafficPort(&event, dport_tunnel_pcap, isdport_chan_cleaned_sniff, ebpfMap)
			default:
				if _, fd := dport_tunnel_pcap[event.Transport_Dest_Port]; !fd {
					log.Println("Start sniffing the port for vxlan encap traffic since the interval clean not found in map")
					go tc.SniffPcapVxlanTrafficPort(&event, dport_tunnel_pcap, isdport_chan_cleaned_sniff, ebpfMap)
				}
			}
			go closeSniffSignalHandler(&event, dport_tunnel_pcap)
		} else {
			log.Println("Polling the ring buffer for the x86 big endian systems")
			err = binary.Read(bytes.NewReader(record.RawSample), binary.BigEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}

			log.Println("Polled an kernel event for vxlan encap from the kernel ringbuffer ", event.Transport_Dest_Port)
			select {
			case <-isdport_chan_cleaned_sniff[event.Transport_Dest_Port]:
				// it mean the sniff channel was cleaned post sniff interval
				// start interval based sniffing again to sniff vxlan port for any vxlan encap traffic
				go tc.SniffPcapVxlanTrafficPort(&event, dport_tunnel_pcap, isdport_chan_cleaned_sniff, ebpfMap)
			default:
				if _, fd := dport_tunnel_pcap[event.Transport_Dest_Port]; !fd {
					go tc.SniffPcapVxlanTrafficPort(&event, dport_tunnel_pcap, isdport_chan_cleaned_sniff, ebpfMap)
				}
			}
			go tc.SniffPcapVxlanTrafficPort(&event, dport_tunnel_pcap, isdport_chan_cleaned_sniff, ebpfMap)
			log.Println("Vxland Event polled from kernel non standard port init sniff to ensure the port is not exfiltrating data", event)
		}
	}
}
