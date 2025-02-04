package model

import (
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/conntrack"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type DnsParserActions interface{}

type DnsPacketGen struct {
	IfaceHandler        *netinet.NetIface
	SockSendFdInterface []netlink.Link
	SocketSendFd        *int
	XdpSocketSendFd     *xdp.Socket
	OnnxModel           *OnnxModel
	StreamClient        *stream.StreamProducer
}

var maliciousExfilProcessCount map[uint32]int = make(map[uint32]int)
var maliciousProcCountguard sync.RWMutex = sync.RWMutex{}

// works as a bridge between kernel netdev (tc) layer and kernel syscall layer eBPF hooks to kill if multiple malicious count found
type ProcessInfo struct {
	ProcessId uint32
	ThreadId  uint32
}

type CombinedFeatures []DNSFeatures

func IncrementMaliciousProcCountLocalCache(procId uint32) {
	maliciousProcCountguard.Lock()
	defer maliciousProcCountguard.Unlock()
	if ct, fd := maliciousExfilProcessCount[procId]; !fd {
		maliciousExfilProcessCount[procId] = 1
	} else {
		if ct > utils.EXFIL_PROCESS_CACHE_CLEAN_THRESHOLD {
			log.Printf("The exfiltration attempt by process %d exceed the limit sending sigkill", procId)
			delete(maliciousExfilProcessCount, procId)
		} else {
			maliciousExfilProcessCount[procId]++
		}
	}
}

func LogMaliciousProcCountLocalCache() {
	if utils.DEBUG {
		maliciousProcCountguard.RLock()
		defer maliciousProcCountguard.RUnlock()
		if len(maliciousExfilProcessCount) == 0 {
			return
		}

		for procId, count := range maliciousExfilProcessCount {
			log.Println("The process trying to exfiltrate data detected with count ", procId, count)
		}
	}
}

func GetCurrentLoggedExfiltratedProcessids() map[uint32]int {
	maliciousProcCountguard.RLock()
	defer maliciousProcCountguard.RUnlock()
	return maliciousExfilProcessCount
}

// Re packet send gen ensure removal of stale conntrack entries to reserved cokernel memory and prevent the conntrack table to grow
func (d *DnsPacketGen) CleanStaleOlderPacketRescheduleConnEntry(customNsFdHandle *int, conntrackEntry *conntrack.ConntrackCleanEntry) error {
	if customNsFdHandle != nil {
		connSockHandle, fd := d.IfaceHandler.ConnTrackNsHandles[int(netns.NsHandle(*customNsFdHandle))]
		if !fd {
			return fmt.Errorf("The Conntrack Map not initialized correctly lacking Fd for the conntrack over if_index", *customNsFdHandle)
		}
		if utils.DEBUG {
			log.Println("clean the stale entry for conntrack ", connSockHandle)
		}
		return nil
	}

	connSockHandle, fd := d.IfaceHandler.ConnTrackNsHandles[0]
	if !fd {
		log.Println("The Required Root namespace not found make sure the Netns map si initiated properly .. ")
		return nil
	}
	if err := connSockHandle.CleanCloneDanglingEntries(conntrackEntry); err != nil {
		if utils.DEBUG {
			// the conntrack internally use the base netfilter layer from kernel if the required conntrack table has no entry and nil value is returned
			log.Println("Error removing the staled conntrack entry", err.Error())
		}
	}
	return nil
}

func (d *DnsPacketGen) GenerateDnsPacket(dns layers.DNS, customNsFdHandle *int) layers.DNS {
	return layers.DNS{
		ID:           dns.ID,
		QR:           dns.QR,
		OpCode:       dns.OpCode,
		AA:           dns.AA,
		TC:           dns.TC,
		RD:           dns.RD,
		RA:           dns.RA,
		Z:            dns.Z,
		ResponseCode: dns.ResponseCode,
		QDCount:      dns.QDCount,
		ANCount:      dns.ANCount,
		NSCount:      dns.NSCount,
		ARCount:      dns.ARCount,
		Questions:    dns.Questions,
		Answers:      dns.Answers,
		Authorities:  dns.Authorities,
		Additionals:  dns.Additionals,
	}
}

func (d *DnsPacketGen) EvalOverallPacketProcessTime(dns layers.DNS, spec *ebpf.Collection) {

	redirectTimeMap := spec.Maps[events.EXFILL_SECURITY_EGRESS_REDIRECT_LOOP_TIME]
	if redirectTimeMap != nil {
		query_id := dns.ID
		var KernelPacketRedirectTimeEgress uint64
		redirectTimeMap.LookupAndDelete(&query_id, &KernelPacketRedirectTimeEgress)

		currProcessTime := time.Now().Nanosecond()

		roundProcessTime := float64(currProcessTime-int(KernelPacketRedirectTimeEgress)) / 1000000.0

		if !utils.DEBUG {
			log.Printf("The round trip time for the dns packet %fms", roundProcessTime)
		}
		events.UpdateLatencyMetricEvents(roundProcessTime)
	}
}

// only use for l3 -> ipv4 and l4 -> udp
func (d *DnsPacketGen) EvaluateGeneratePacket(ethLayer, networkLayer, transportLayer, dnsLayer gopacket.Layer,
	l3_bpfMap_checksum uint16, handler *pcap.Handle, isEgress bool, isIpv4, isUdp bool, spec *ebpf.Collection,
	processInfo *ProcessInfo) error {

	st := time.Now().Nanosecond()
	if utils.DEBUG {
		log.Println("[x] Recrafting the entire DNS packet")
	}
	ethernet := ethLayer.(*layers.Ethernet)

	var ipv4 *layers.IPv4
	var ipv6 *layers.IPv6

	if isIpv4 {
		ipv4 = networkLayer.(*layers.IPv4)
		// ipv4.DstIP = net.ParseIP("192.168.64.27").To4()
		ipv4.DstIP = d.IfaceHandler.PhysicalRouterGatewayV4
		ipv4.Checksum = l3_bpfMap_checksum
	} else {
		ipv6 = networkLayer.(*layers.IPv6)
		ipv6.DstIP = net.ParseIP(utils.GLOBAL_ROUTE_IPV6_TRANSFER_LINKS[rand.Intn(len(utils.GLOBAL_ROUTE_IPV6_TRANSFER_LINKS))]).To16()
	}

	var udpPacket *layers.UDP
	var tcpPacket *layers.TCP

	if isUdp {
		udpPacket = transportLayer.(*layers.UDP)
	} else {
		tcpPacket = transportLayer.(*layers.TCP)
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		log.Println("Error parsing the dns header return")
		return fmt.Errorf("error parsing DNS layer")
	}

	if utils.DEBUG {
		fmt.Println("src ip is", ipv4.SrcIP.To4(), "dest ip ", ipv4.DstIP.To4())
		fmt.Println("src ip is", ipv6.SrcIP.To4(), "dest ip ", ipv6.DstIP.To4())
		fmt.Println("src port is", udpPacket.SrcPort, "dest port ", udpPacket.DstPort)
	}

	features, err := ProcessDnsFeatures(dns, isEgress)

	if err != nil {
		log.Println("Error generating the features over the packet", err)
		return err
	}

	isBenign := d.OnnxModel.Evaluate(features, "DNS", isEgress)

	if !isBenign {
		if isEgress {
			log.Println("The Exfiltrated DNS packet was found to be exfiltrated by process in user space with pid ", processInfo.ProcessId)
			if processInfo.ProcessId != 0 && processInfo.ThreadId != 0 {
				// handle the sock layer inc for local cache, only track the egress filter, for xdp over ingress no sock layer needed required process can be sigkilled in egress path
				go IncrementMaliciousProcCountLocalCache(processInfo.ProcessId)
			}
			// for process with ID 0 are not supported since the kernel is old to emit task_comm or task strcut to user space for integration with syscall layer
		}
		log.Println("Malicious DNS Exfiltrated Qeury Found Dropping the packet")
		// add the tld and domain information in packet malicious map for local cache
		if len(features) > 1 {
			for _, feature := range features {
				if isUdp {
					go events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(feature), &d.IfaceHandler.PhysicalNodeBridgeIpv4,
						events.DNS, int(udpPacket.DstPort))
				} else {
					go events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(feature), &d.IfaceHandler.PhysicalNodeBridgeIpv4,
						events.DNS, int(tcpPacket.DstPort))
				}
				go d.StreamClient.MarshallStreamThreadEvent(feature, stream.HostNetworkExfilFeatures{
					ExfilPort:        strconv.Itoa(utils.DNS_EGRESS_PORT),
					Protocol:         string(events.DNS),
					PhysicalNodeIpv4: d.IfaceHandler.PhysicalNodeBridgeIpv4.String(),
					PhysicalNodeIpv6: d.IfaceHandler.PhysicalNodeBridgeIpv6.String(),
				})
			}
		} else if len(features) == 1 {
			if isUdp {
				events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(features[0]), &d.IfaceHandler.PhysicalNodeBridgeIpv4, events.DNS, int(udpPacket.DstPort))
			} else {
				events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(features[0]), &d.IfaceHandler.PhysicalNodeBridgeIpv4, events.DNS, int(tcpPacket.DstPort))
			}
			d.StreamClient.MarshallStreamThreadEvent(features[0], stream.HostNetworkExfilFeatures{
				ExfilPort:        strconv.Itoa(utils.DNS_EGRESS_PORT), // keep this as it until more kernele xfil control is added
				Protocol:         string(events.DNS),
				PhysicalNodeIpv4: d.IfaceHandler.PhysicalNodeBridgeIpv4.String(),
				PhysicalNodeIpv6: d.IfaceHandler.PhysicalNodeBridgeIpv6.String(),
			})
		}
		return nil
	} else {
		if len(features) > 1 {
			for _, feature := range features {
				go events.ExportPromeEbpfExporterEvents[events.RawDnsEvent](events.RawDnsEvent{
					Fqdn:     feature.Fqdn,
					Tld:      feature.Tld,
					IsEgress: isEgress,
					Protocol: events.Protocol(events.DNS),
				})
			}
		} else {
			events.ExportPromeEbpfExporterEvents[events.RawDnsEvent](events.RawDnsEvent{
				Fqdn:     features[0].Fqdn,
				Tld:      features[0].Tld,
				IsEgress: isEgress,
				Protocol: events.Protocol(events.DNS),
			})
		}
	}

	if utils.DEBUG {
		log.Println("Packet Found benign after Deep Lexical Scan Resending the packet")
	}

	dnsPacket := d.GenerateDnsPacket(*dns, nil)

	if isEgress && isBenign {
		d.EvalOverallPacketProcessTime(*dns, spec)
	}

	buffer := gopacket.NewSerializeBuffer()

	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// the kernel redirect has already done DNAT over the packet frame in kernel tc post redirect for next reschedule
	// conntrack entry must be created fro origin packet with the preserved Src address because of no SNAT and interception in Input filter chain in netfilter prerouting phase.

	if isIpv4 && isUdp {
		// ipv4 and udp
		packetL3SrcAddress, _ := netip.ParseAddr(ipv4.SrcIP.String())
		destAddress, _ := netip.ParseAddr(ipv4.DstIP.String())
		d.CleanStaleOlderPacketRescheduleConnEntry(nil, &conntrack.ConntrackCleanEntry{
			SrcAddress: packetL3SrcAddress,
			DestAddres: destAddress,
			SrcPort:    uint16(udpPacket.SrcPort),
			Destport:   uint16(udpPacket.DstPort),
			Protocol:   6,
		})
		udpPacket.SetNetworkLayerForChecksum(ipv4)
		if err := gopacket.SerializeLayers(buffer, opts, ethernet, ipv4, udpPacket, &dnsPacket); err != nil {
			log.Println("Error reconstructing the DNS packet", err)
			return err
		}
	} else if !isIpv4 && isUdp {
		// ipv6 and udp
		packetL3SrcAddress, _ := netip.ParseAddr(ipv6.SrcIP.String())
		destAddress, _ := netip.ParseAddr(ipv6.DstIP.String())
		d.CleanStaleOlderPacketRescheduleConnEntry(nil, &conntrack.ConntrackCleanEntry{
			SrcAddress: packetL3SrcAddress,
			DestAddres: destAddress,
			SrcPort:    uint16(udpPacket.SrcPort),
			Destport:   uint16(udpPacket.DstPort),
			Protocol:   6,
		})
		opts.ComputeChecksums = false
		udpPacket.SetNetworkLayerForChecksum(ipv6)
		if err := gopacket.SerializeLayers(buffer, opts, ethernet, ipv6, udpPacket, &dnsPacket); err != nil {
			log.Println("Error reconstructing the DNS packet", err)
			return err
		}
	} else if isIpv4 && !isUdp {
		// ipv4 and tcp
		packetL3SrcAddress, _ := netip.ParseAddr(ipv4.SrcIP.String())
		destAddress, _ := netip.ParseAddr(ipv4.DstIP.String())
		d.CleanStaleOlderPacketRescheduleConnEntry(nil, &conntrack.ConntrackCleanEntry{
			SrcAddress: packetL3SrcAddress,
			DestAddres: destAddress,
			SrcPort:    uint16(tcpPacket.SrcPort),
			Destport:   uint16(tcpPacket.DstPort),
			Protocol:   6,
		})
		tcpPacket.SetNetworkLayerForChecksum(ipv4)
		fmt.Println("tcp packet", tcpPacket)
		if err := gopacket.SerializeLayers(buffer, opts, ethernet, ipv4, tcpPacket, &dnsPacket); err != nil {
			log.Println("Error reconstructing the DNS packet", err)
			return err
		}
	} else if !isIpv4 && !isUdp {
		// ipv6 and tcp
		packetL3SrcAddress, _ := netip.ParseAddr(ipv6.SrcIP.String())
		destAddress, _ := netip.ParseAddr(ipv6.DstIP.String())
		d.CleanStaleOlderPacketRescheduleConnEntry(nil, &conntrack.ConntrackCleanEntry{
			SrcAddress: packetL3SrcAddress,
			DestAddres: destAddress,
			SrcPort:    uint16(tcpPacket.SrcPort),
			Destport:   uint16(tcpPacket.DstPort),
			Protocol:   6,
		})
		opts.ComputeChecksums = false
		tcpPacket.SetNetworkLayerForChecksum(ipv6)
		if err := gopacket.SerializeLayers(buffer, opts, ethernet, ipv6, tcpPacket, &dnsPacket); err != nil {
			log.Println("Error reconstructing the DNS packet", err)
			return err
		}
	}

	if utils.DEBUG {
		// serialize := time.Now().Nanosecond()
		log.Println("time took to serialize the whole packet", time.Now().Nanosecond()-st)
	}
	outputPacket := buffer.Bytes()
	outputPacketLen := len(outputPacket)

	if d.XdpSocketSendFd == nil {
		// first check and bind the xdp kernel socket to tx queue for the interface
		sockAddr := syscall.SockaddrLinklayer{
			Protocol: syscall.ETH_P_ALL,
			Ifindex:  d.SockSendFdInterface[0].Attrs().Index,
		}

		// need this to be replaced with xdp
		if err := syscall.Sendto(*d.SocketSendFd, outputPacket, 0, &sockAddr); err != nil {
			return err
		}
	} else {
		// inject the packet directly into the tx queue for the xdp bypassing the entire linux kernel network stack
		// eventually free up some of the bpf maps in tc from the kernel space

		fx := d.XdpSocketSendFd.GetDescs(d.XdpSocketSendFd.NumFreeTxSlots())
		for i := range fx {
			fx[i].Len = uint32(outputPacketLen)
		}
		trxCount := d.XdpSocketSendFd.Transmit(fx)
		log.Println("Transmitted framecount is ", trxCount)
	}

	return nil
}
