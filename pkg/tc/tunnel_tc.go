package tc

// this is mainly used to process
import (
	"fmt"
	"log"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCCloneTunnel struct {
	IfaceHandler             *netinet.NetIface
	GlobalKernelErrorChannel chan bool
	PhysicalTcInterface      *TCHandler
}

func GenerateTcTunnelFactory(tc *TCHandler, iface *netinet.NetIface, globalErrorChannel chan bool) *TCCloneTunnel {
	return &TCCloneTunnel{
		IfaceHandler:             iface,
		GlobalKernelErrorChannel: globalErrorChannel,
		PhysicalTcInterface:      tc,
	}
}

func (tun *TCCloneTunnel) SniffPacketsForTunnelDPI() {
	handler, err := tun.IfaceHandler.GetBridgePcapHandleClone()

	if err != nil {
		log.Printf("Error while sniffing packets on the interface %s", netinet.NETNS_RAW_NETLINK_BRIDGE_DPI)
		tun.GlobalKernelErrorChannel <- true
	}

	defer handler.Close()

	if err := handler.SetBPFFilter("udp or tcp"); err != nil {
		log.Println("Error while setting the bpf filter")
		tun.GlobalKernelErrorChannel <- true
	}

	packetSource := gopacket.NewPacketSource(handler, handler.LinkType())

	sniffTunnelErr := make(chan interface{})

	ebpfMap := tun.PhysicalTcInterface.TcCollection.Maps[events.EXFIL_SECURITY_EGRESS_RECONNISANCE_MAP_SCAN]

	for packet := range packetSource.Packets() {
		go tun.ProcessTunnelHandlerPackets(packet, ebpfMap, sniffTunnelErr)
	}
}

func (tun *TCCloneTunnel) ProcessTunnelHandlerPackets(packet gopacket.Packet, ebpfMap *ebpf.Map, errorChannel chan interface{}) {

	if ebpfMap == nil {
		errorChannel <- struct {
			Err string
		}{
			Err: "The kernel ebpf map for tun is nil",
		}
		return
	}

	// Check for DNS layer directly
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		// a tunneled dns packet overlay over the protocol

		udpPack := packet.Layer(layers.LayerTypeUDP)

		if udpPack != nil {
			destPort := udpPack.(*layers.UDP).DstPort
			var event events.ExfilRawPacketMirror
			if err := ebpfMap.Lookup(destPort, event); err != nil {
				log.Printf("The kernel has not cloned the packet from tc layer")
				errorChannel <- struct {
					Err string
				}{
					Err: "The kernel has not cloned the packet from tc layer",
				}
				return
			}
			event.IsPacketRescanedAndMalicious = uint8(1)
			if err := ebpfMap.Update(
				uint32(destPort), event, 0,
			); err != nil {
				log.Printf("The kernel has not cloned the packet from tc layer")
				errorChannel <- struct {
					Err string
				}{
					Err: "The kernel has not cloned the packet from tc layer",
				}
			}
			go events.ExportPromeEbpfExporterEvents[events.Malicious_Non_Stanard_Transfer](events.Malicious_Non_Stanard_Transfer{
				Src_port:       int(event.SrcPort),
				Dest_port:      int(event.DstPort),
				IsUDPTransport: true,
			})
		} else {
			tcpPack := packet.Layer(layers.LayerTypeTCP)
			destPort := tcpPack.(*layers.TCP).DstPort
			// kernel will take care to process and set the packet type when kernel redirect iva link clone to the userspace
			var event events.ExfilRawPacketMirror
			if err := ebpfMap.Lookup(destPort, event); err != nil {
				log.Printf("The kernel has not cloned the packet from tc layer")
				errorChannel <- struct {
					Err string
				}{
					Err: "The kernel has not cloned the packet from tc layer",
				}
				return
			}
			event.IsPacketRescanedAndMalicious = uint8(1)
			if err := ebpfMap.Update(
				uint32(destPort), event, 0,
			); err != nil {
				log.Printf("The kernel has not cloned the packet from tc layer")
				errorChannel <- struct {
					Err string
				}{
					Err: "The kernel has not cloned the packet from tc layer",
				}
			}
			go events.ExportPromeEbpfExporterEvents[events.Malicious_Non_Stanard_Transfer](events.Malicious_Non_Stanard_Transfer{
				Src_port:       int(event.SrcPort),
				Dest_port:      int(event.DstPort),
				IsUDPTransport: false,
			})
		}
		fmt.Printf("Found DNS packet - ID: %d\n", dns.ID)
		return
	}

}
