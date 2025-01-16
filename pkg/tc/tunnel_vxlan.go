package tc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type VxlandEncapListner struct {
}

func (tc *TCHandler) SniffPcapVxlanTrafficPort(event *events.DPIVxlanKernelEncapEvent,
	controlChannelMap map[uint32]chan bool) error {
	// for now get the root physical based on egress if_index  later ensure it maps to skb egress link from kernel
	log.Println("Init Pcap hanle to live sniff for deep user-sapce inspacetion for any exfil traffic in vxlan encap", event)

	pcahandle, err := tc.Interfaces.GetRootNamespacePcapHandleDuration(time.Minute * 1)
	if err != nil {
		log.Printf("Error getting root namespace pcap handle %v", err)
		return err
	}
	defer pcahandle.Close()

	return nil
}

func (tc *TCHandler) PollVxlanRingBuffer(ctx context.Context, ebpfMpa *ebpf.Map) error {

	vxlanEncapMap := tc.TcCollection.Maps[events.EXFIL_SECURITY_EGRESS_VXLAN_ENCAP_DROP]
	if vxlanEncapMap == nil {
		log.Printf("Cannot poll the nil map from kernel for an empty Vxlan or non init ring buff")
		return nil
	}

	// use this to send an sig kill for pcap to clean packet socket over bpf from kernel sed for sniffing
	var dport_tunnel_pcap map[uint32]chan bool = make(map[uint32]chan bool)

	ringbuffer, err := ringbuf.NewReader(vxlanEncapMap)
	if err != nil {
		return err
	}

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
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}
			go tc.SniffPcapVxlanTrafficPort(&event, dport_tunnel_pcap)
			log.Println("Vxland Event polled from kernel non standard port init sniff to ensure the port is not exfiltrating data", event)
		} else {
			log.Println("Polling the ring buffer for the x86 big endian systems")
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}
			go tc.SniffPcapVxlanTrafficPort(&event, dport_tunnel_pcap)
			log.Println("Vxland Event polled from kernel non standard port init sniff to ensure the port is not exfiltrating data", event)
		}
	}
}
