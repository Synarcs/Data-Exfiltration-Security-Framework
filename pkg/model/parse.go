/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package model

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/conf"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/conntrack"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/progs"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

type DnsPacketGen struct {
	IfaceHandler    *netinet.NetIface // AF_NETLINK
	SocketSendFd    *int              // AF_PACKET
	XdpSocketSendFd *xdp.Socket       // AF_XDP
	OnnxModel       *OnnxModel
	StreamClient    *stream.StreamProducer
}

type DnsPacketGenConfig struct {
	Iface        *netinet.NetIface
	OnnxModel    *OnnxModel
	StreamClient *stream.StreamProducer
}

func NewDnsPacketResendUtils(config *DnsPacketGenConfig) (*DnsPacketGen, error) {
	xdpSocketFd, err := config.Iface.GetRootNamespaceRawSocketFdXDP()
	if err == nil {
		utils.Log("[Using the raw packet with AF_PACKET Fd")

		return &DnsPacketGen{
			IfaceHandler:    config.Iface,
			XdpSocketSendFd: xdpSocketFd,
			SocketSendFd:    nil,
			OnnxModel:       config.OnnxModel,
			StreamClient:    config.StreamClient,
		}, nil
	} else {
		utils.Log("Error Binding the XDP Socket Physical driver lacking support")
		fd, err := config.Iface.GetRootNamespaceRawSocketFd()

		if err != nil {
			return nil, err
		}
		return &DnsPacketGen{
			IfaceHandler:    config.Iface,
			SocketSendFd:    fd,
			XdpSocketSendFd: nil,
			OnnxModel:       config.OnnxModel,
			StreamClient:    config.StreamClient,
		}, nil
	}
}

// convert to an shared distributed cache over the enitr data plane if required
var (
	maliciousExfilProcessCount     map[uint32]int                              = make(map[uint32]int)
	maliciousExfilProcessesRecCt   map[uint32]int                              = make(map[uint32]int)
	maliciousExfilProcessAliveTime map[uint32]events.MaliciousProcessAliveTime = make(map[uint32]events.MaliciousProcessAliveTime)
	maliciousProcCountguard        sync.RWMutex                                = sync.RWMutex{}
)

type CombinedFeatures []DNSFeatures

func IncrementMaliciousProcCountLocalCache(procId uint32) {
	maliciousProcCountguard.Lock()
	defer maliciousProcCountguard.Unlock()
	if ct, fd := maliciousExfilProcessCount[procId]; !fd {
		maliciousExfilProcessCount[procId] = 1
		maliciousExfilProcessAliveTime[procId] = events.MaliciousProcessAliveTime{
			ExfiltrationStartedAt: time.Now().Format(time.RFC850),
			ProcessId:             procId,
			AliveTime:             time.Now().Second(),
		}
		// ensure does there exist conflict for preocess ID which was killed previously
		if val, fd := maliciousExfilProcessesRecCt[procId]; fd {
			maliciousExfilProcessesRecCt[procId] = val + 1
		} else {
			maliciousExfilProcessesRecCt[procId] = 1
		}
	} else {
		if ct > utils.EXFIL_PROCESS_CACHE_CLEAN_THRESHOLD_BENIGN_PORT {
			utils.Logger.Printf("The exfiltration was stopped send sigkill to the process %d is killed", procId)
			if err := utils.KillProc(procId); err != nil {
				utils.Logger.Errorf("Error while sending sigkill to process %d wiht buffer err %+v", procId, err.Error())
			}
			evTime := maliciousExfilProcessAliveTime[procId]
			evTime.AliveTime = time.Now().Second() - int(evTime.AliveTime)
			go events.ExportPromeEbpfExporterEvents[events.MaliciousProcessAliveTime](evTime)
			delete(maliciousExfilProcessAliveTime, procId)
			delete(maliciousExfilProcessCount, procId)
			return
		}
		maliciousExfilProcessCount[procId]++
	}
}

func GetCurrentLoggedExfiltratedProcessids() map[uint32]int {
	return maliciousExfilProcessesRecCt
}

// Re packet send gen ensure removal of stale conntrack entries to reserved cokernel memory and prevent the conntrack table to grow
func (d *DnsPacketGen) CleanStaleOlderPacketRescheduleConnEntry(customNsFdHandle *int, conntrackEntry *conntrack.ConntrackCleanEntry) error {
	if customNsFdHandle != nil {
		connSockHandle, fd := d.IfaceHandler.ConnTrackNsHandles[int(netns.NsHandle(*customNsFdHandle))]
		if !fd {
			return fmt.Errorf("the Conntrack Map not initialized correctly lacking Fd for the conntrack over if_index %d", *customNsFdHandle)
		}
		if utils.DEBUG {
			utils.Log("clean the stale entry for conntrack ", connSockHandle)
		}
		return nil
	}

	connSockHandle, fd := d.IfaceHandler.ConnTrackNsHandles[0]
	if !fd {
		utils.Log("The Required Root namespace not found make sure the Netns map si initiated properly .. ")
		return nil
	}
	if err := connSockHandle.CleanCloneDanglingEntries(conntrackEntry); err != nil {
		if utils.DEBUG {
			// the conntrack internally use the base netfilter layer from kernel if the required conntrack table has no entry and nil value is returned
			utils.Log("Error removing the staled conntrack entry", err.Error())
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

func (d *DnsPacketGen) EvalOverallPacketProcessTime(dns layers.DNS, spec *ebpf.Collection, enforceNetworkPolicyTime bool) {

	redirectTimeMap := spec.Maps[events.EXFILL_SECURITY_EGRESS_REDIRECT_LOOP_TIME]
	if redirectTimeMap != nil {
		query_id := dns.ID
		var KernelPacketRedirectTimeEgress uint64
		redirectTimeMap.LookupAndDelete(&query_id, &KernelPacketRedirectTimeEgress)

		currProcessTime := time.Now().Nanosecond()

		roundProcessTime := float64(currProcessTime-int(KernelPacketRedirectTimeEgress)) / 1_000_000.0

		if utils.DEBUG {
			utils.Logger.Printf("The round trip time for the dns packet %fms", roundProcessTime)
		}
		if !enforceNetworkPolicyTime {
			events.UpdateLatencyMetricEvents(roundProcessTime)
		} else {
			if utils.DEBUG {
				roundProcessTime = roundProcessTime / 1_000 // ust measure in millsecond for tracking response time when first network policy was enforced and userspace dropped packet, when instructed by kernel program for inferencing
				utils.Log(fmt.Sprintf("the first network policy was enforced after time :: %fms", roundProcessTime))
			}
		}
	}
}

/*
Runs inference over DL model and esends if non malicious ove AF_XDP OR AF_PACKET
TODO: fix massive amount of functions args to the function, for custom config structs
*/
func (d *DnsPacketGen) EvaluateGeneratePacket(ctx context.Context,
	ethLayer, networkLayer, transportLayer, dnsLayer gopacket.Layer,
	l3_bpfMap_checksum uint16, handler *pcap.Handle, isEgress bool, isIpv4, isUdp bool, spec *ebpf.Collection,
	processInfo *utils.MaliciousKernelTaskCommExportedProcInfo, isPhysicalNetDevSniff bool,
	egressLink netlink.Link, allowXDP bool,
	customDnat bool,
	customUpstreamDnsresolveIp string) error {

	st := time.Now().Nanosecond()
	if utils.DEBUG {
		utils.Log("[x] Recrafting the entire DNS packet")
	}
	ethernet := ethLayer.(*layers.Ethernet)

	var ipv4 *layers.IPv4
	var ipv6 *layers.IPv6

	if isIpv4 {
		ipv4 = networkLayer.(*layers.IPv4)
		// ipv4.DstIP = net.ParseIP("192.168.64.27").To4()
		if !d.IfaceHandler.DnsResolvers.IsLoopBackEnabled {
			if customDnat {
				ipv4.DstIP = net.ParseIP(customUpstreamDnsresolveIp)
			} else {
				ipv4.DstIP = d.IfaceHandler.PhysicalRouterGatewayV4
			}
		} else {
			ipv4.DstIP = net.ParseIP("127.0.0.53") // stub loopback addr
		}
		ipv4.Checksum = l3_bpfMap_checksum
	} else {
		ipv6 = networkLayer.(*layers.IPv6)
		if !d.IfaceHandler.DnsResolvers.IsLoopBackEnabled {
			ipv6.DstIP = net.ParseIP(utils.GLOBAL_ROUTE_IPV6_TRANSFER_LINKS[rand.Intn(len(utils.GLOBAL_ROUTE_IPV6_TRANSFER_LINKS))]).To16()
		} else {
			ipv6.DstIP = net.ParseIP("::1") // stub loopback addr
		}
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
		utils.Log("Error parsing the dns header return")
		return fmt.Errorf("error parsing DNS layer")
	}

	features, err := ProcessDnsFeatures(dns, isEgress)

	if err != nil {
		utils.Log("Error generating the features over the packet", err)
		return err
	}

	isBenign := d.OnnxModel.Evaluate(features, "DNS", isEgress)

	if !isBenign {
		if isEgress {
			if utils.VerifyKernelSupportTaskComms(processInfo.ProcessId, processInfo.ThreadId) {
				utils.Log("The Exfiltrated DNS packet was found to be exfiltrated by process in user space with pid ", processInfo.ProcessId)
				// used as a metric to interact with kernel syscall layer if supported the implant will be terminated at the endpoing if it exceeds the threshold limit for malicious
				utils.Log("Existing found a  th emalicious transfer for process over stanndard DNS port ", processInfo)
				go IncrementMaliciousProcCountLocalCache(processInfo.ProcessId)
			}
			// for process with ID 0 are not supported since the kernel is old to emit task_comm or task strcut to user space for integration with syscall layer
		}
		utils.Log("Malicious DNS Exfiltrated Query Found Dropping the packet", features)
		// add the tld and domain information in packet malicious map for local cache
		for _, feature := range features {
			if isUdp {
				if utils.VerifyKernelSupportTaskComms(processInfo.ProcessId, processInfo.ThreadId) {
					go events.ExportMaliciousEvents[progs.Protocol](events.DNSFeatures(feature), &d.IfaceHandler.PhysicalNodeBridgeIpv4,
						events.DNS, int(udpPacket.DstPort), processInfo)
				} else {
					go events.ExportMaliciousEvents[progs.Protocol](events.DNSFeatures(feature), &d.IfaceHandler.PhysicalNodeBridgeIpv4,
						events.DNS, int(udpPacket.DstPort), nil)
				}
			} else {
				if utils.VerifyKernelSupportTaskComms(processInfo.ProcessId, processInfo.ThreadId) {
					go events.ExportMaliciousEvents[progs.Protocol](events.DNSFeatures(feature), &d.IfaceHandler.PhysicalNodeBridgeIpv4,
						events.DNS, int(tcpPacket.DstPort), processInfo)
				} else {
					go events.ExportMaliciousEvents[progs.Protocol](events.DNSFeatures(feature), &d.IfaceHandler.PhysicalNodeBridgeIpv4,
						events.DNS, int(udpPacket.DstPort), nil)
				}
			}

			// ensure the agent booted with isolated mode to prevent stream threat events to centralized message broker
			if !conf.GlobalAgentCliConfig.DisableThreadEventStream {
				go d.StreamClient.MarshallStreamThreadEvent(ctx, feature, stream.HostNetworkExfilFeatures{
					ExfilPort:        strconv.Itoa(int(utils.DNS_EGRESS_PORT)),
					Protocol:         string(events.DNS),
					PhysicalNodeIpv4: d.IfaceHandler.PhysicalNodeBridgeIpv4.String(),
					PhysicalNodeIpv6: d.IfaceHandler.PhysicalNodeBridgeIpv6.String(),
				})
			}
			// perform force garbage collection for go runtime to clean userspace memory during processing from kernel packet data in zero-copy mode
			go utils.ForceGc()
			d.EvalOverallPacketProcessTime(*dns, spec, true)
		}
		return nil
	} else {
		if len(features) > 1 {
			for _, feature := range features {
				go events.ExportPromeEbpfExporterEvents[events.RawDnsEvent](events.RawDnsEvent{
					Fqdn:     feature.Fqdn,
					Tld:      feature.Tld,
					IsEgress: isEgress,
					Protocol: progs.Protocol(events.DNS),
				})
			}
		} else {
			events.ExportPromeEbpfExporterEvents[events.RawDnsEvent](events.RawDnsEvent{
				Fqdn:     features[0].Fqdn,
				Tld:      features[0].Tld,
				IsEgress: isEgress,
				Protocol: progs.Protocol(events.DNS),
			})
		}
	}

	if utils.DEBUG {
		utils.Log("Packet Found benign after Deep Lexical Scan Resending the packet")
	}

	dnsPacket := d.GenerateDnsPacket(*dns, nil)

	if isEgress && isBenign {
		d.EvalOverallPacketProcessTime(*dns, spec, false)
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
			utils.Log("Error reconstructing the DNS packet", err)
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
			utils.Log("Error reconstructing the DNS packet", err)
			return err
		}
	}

	if utils.DEBUG {
		utils.Log("time took to serialize the whole packet", time.Now().Nanosecond()-st)
	}
	outputPacket := buffer.Bytes()
	outputPacketLen := len(outputPacket)

	// the tcp passive analysis is only meant to passively analyze tcp traffic and detect any malicious traffic send over egress on physical netdev
	if !isPhysicalNetDevSniff {
		if d.XdpSocketSendFd == nil {
			// first check and bind the xdp kernel socket to tx queue for the interface
			sockAddr := syscall.SockaddrLinklayer{
				Protocol: syscall.ETH_P_ALL,
				Ifindex:  egressLink.Attrs().Index,
			}

			if err := syscall.Sendto(*d.SocketSendFd, outputPacket, 0, &sockAddr); err != nil {
				return err
			}
			return nil
		} else {
			// inject the packet directly into the tx queue for the xdp bypassing the entire linux kernel network stack
			// eventually free up some of the bpf maps in tc from the kernel space
			fx := d.XdpSocketSendFd.GetDescs(d.XdpSocketSendFd.NumFreeTxSlots())
			for i := range fx {
				fx[i].Len = uint32(outputPacketLen)
			}
			trxCount := d.XdpSocketSendFd.Transmit(fx)
			utils.Log("Transmitted framecount is ", trxCount)
		}
	}

	return nil
}
