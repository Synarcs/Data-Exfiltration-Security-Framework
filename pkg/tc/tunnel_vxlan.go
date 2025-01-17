package tc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"runtime"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type VxlandEncapListner struct{}

const (
	POLL_TICKER_VXLAN_DURATION      = 10 * time.Minute // poll the vxlan encap tunnel every 10 minute interval
	POLL_TICKER_VXLAN_PCAP_DURATION = 5 * time.Minute  // poll the pcap handle over every 5 minute interval
)

func (tc *TCHandler) DeepScanVxlanPacketencap(pack gopacket.Packet) error {
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
		log.Println("All the packet layers for encap vxlan packet is ", vxlanPacket, vxlanPacket.BaseLayer)
	}

	return nil
}

func (tc *TCHandler) SniffPcapVxlanTrafficforVxlanEncap(ctx context.Context,
	pcapHandle *pcap.Handle, exfilEvent *events.DPIVxlanKernelEncapEvent) error {

	if err := pcapHandle.SetBPFFilter(fmt.Sprintf("udp dest port %d", exfilEvent.Transport_Dest_Port)); err != nil {
		log.Printf("Error opening the pcap handling on udp port for vxlan transfer %d", exfilEvent.Transport_Dest_Port)
		return err
	}

	packets := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

	for pack := range packets.Packets() {
		log.Println("Sniffing the udp service port for vxlan encap packets from kernel ebpf ring event ", pack.Layers())
		tc.DeepScanVxlanPacketencap(pack)
	}

	defer pcapHandle.Close()
	return nil
}

// Ensure there are cancellable context or deadline to ensure optimized controlled over go routines and their cancellation
func (tc *TCHandler) SniffPcapVxlanTrafficPort(event *events.DPIVxlanKernelEncapEvent,
	controlChannelMap map[uint16]chan bool, isdport_chan_cleaned_sniff map[uint16]chan bool) error {
	runtime.LockOSThread()
	if _, fd := controlChannelMap[event.Transport_Dest_Port]; fd {
		// there is already an pcap live handler snifing traffic over pcap
		return nil
	}
	controlChannelMap[event.Transport_Dest_Port] = make(chan bool)
	// for now get the root physical based on egress if_index  later ensure it maps to skb egress link from kernel
	log.Println("Init Pcap hanle to live sniff for deep user-sapce inspacetion for any exfil traffic in vxlan encap", event)

	ctx := context.Background()

	// start sniffing the traffic and make sure any vxlan traffi sniff parses l7 exfiltrated payload for dns
	pcahandle, err := tc.Interfaces.GetRootNamespacePcapHandleDuration(POLL_TICKER_VXLAN_PCAP_DURATION)
	if err != nil {
		log.Printf("Error getting root namespace pcap handle %v", err)
	}
	// parse the header DPI for vxlan encap
	tc.SniffPcapVxlanTrafficforVxlanEncap(ctx, pcahandle, event)

	defer func() {
		pcahandle.Close() // closes after userspace stops polling over pcap bpf filter
		controlChannelMap[event.Transport_Dest_Port] <- true
	}()

	return nil
}

func (tc *TCHandler) PollVxlanRingBuffer(ctx context.Context, ebpfMpa *ebpf.Map) error {

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
			log.Println("Polling the ring buffer for the arm arch")
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}

			select {
			case <-isdport_chan_cleaned_sniff[event.Transport_Dest_Port]:
				// it mean the sniff channel was cleaned post sniff interval
				// start interval based sniffing again to sniff vxlan port for any vxlan encap traffic
				delete(isdport_chan_cleaned_sniff, event.Transport_Dest_Port)
				go tc.SniffPcapVxlanTrafficPort(&event, dport_tunnel_pcap, isdport_chan_cleaned_sniff)
			default:
				if _, fd := dport_tunnel_pcap[event.Transport_Dest_Port]; !fd {
					log.Println("Start sniffing the port for vxlan encap traffic since the interval clean not found in map")
					go tc.SniffPcapVxlanTrafficPort(&event, dport_tunnel_pcap, isdport_chan_cleaned_sniff)
				}
			}
			go closeSniffSignalHandler(&event, dport_tunnel_pcap)
			log.Println("Vxland Event polled from kernel non standard port init sniff to ensure the port is not exfiltrating data", event)
		} else {
			log.Println("Polling the ring buffer for the x86 big endian systems")
			err = binary.Read(bytes.NewReader(record.RawSample), binary.BigEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}
			select {
			case <-isdport_chan_cleaned_sniff[event.Transport_Dest_Port]:
				// it mean the sniff channel was cleaned post sniff interval
				// start interval based sniffing again to sniff vxlan port for any vxlan encap traffic
				go tc.SniffPcapVxlanTrafficPort(&event, dport_tunnel_pcap, isdport_chan_cleaned_sniff)
			default:
				if _, fd := dport_tunnel_pcap[event.Transport_Dest_Port]; !fd {
					go tc.SniffPcapVxlanTrafficPort(&event, dport_tunnel_pcap, isdport_chan_cleaned_sniff)
				}
			}
			go tc.SniffPcapVxlanTrafficPort(&event, dport_tunnel_pcap, isdport_chan_cleaned_sniff)
			log.Println("Vxland Event polled from kernel non standard port init sniff to ensure the port is not exfiltrating data", event)
		}
	}
}
