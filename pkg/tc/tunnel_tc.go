package tc

// DPI over the clone redirect over tc from kernel done via the tc layer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCCloneTunnel struct {
	IfaceHandler             *netinet.NetIface
	GlobalKernelErrorChannel chan bool
	PhysicalTcInterface      *TCHandler
	StreamClient             *stream.StreamProducer
	Onnx                     *model.OnnxModel
}

func GenerateTcTunnelFactory(tc *TCHandler, iface *netinet.NetIface, globalErrorChannel chan bool,
	streamClient *stream.StreamProducer, onnx *model.OnnxModel) *TCCloneTunnel {
	return &TCCloneTunnel{
		IfaceHandler:             iface,
		GlobalKernelErrorChannel: globalErrorChannel,
		PhysicalTcInterface:      tc,
		StreamClient:             streamClient,
		Onnx:                     onnx,
	}
}

func isNetBiosTunnelNSLookUp(dnsPacket *layers.DNS) bool {
	for _, question := range dnsPacket.Questions {
		if question.Type == layers.DNSType(32) { // a NETBIOS record dns quert
			return true
		}
	}
	return false
}

var maliciousExfilProcessCount map[uint32]int = make(map[uint32]int)
var maliciousProcCountguard sync.RWMutex = sync.RWMutex{}

func (tun *TCCloneTunnel) IncrementMaliciousProcCountLocalCacheOverlayPort(mapField *events.DnsMapPayloadNonOverlayPort) {
	maliciousProcCountguard.Lock()
	defer maliciousProcCountguard.Unlock()

	if mapField == nil {
		return
	}
	if ct, fd := maliciousExfilProcessCount[mapField.ProcessId]; !fd {
		maliciousExfilProcessCount[mapField.ProcessId] = 1
	} else {
		if ct > utils.EXFIL_PROCESS_CACHE_CLEAN_THRESHOLD {
			log.Printf("The exfiltration attempt by process %d exceed the limit sending sigkill", mapField.ProcessId)
			cmd := exec.Command("kill", "-9", strconv.Itoa(int(mapField.ProcessId)))
			if err := cmd.Run(); err != nil {
				log.Printf("Error while sending sigkill to process %d", mapField.ProcessId)
			}
			log.Printf("The exfiltration was stopped send sigkill to the process %d is killed", mapField.ProcessId)
			delete(maliciousExfilProcessCount, mapField.ProcessId)
			// use the kernel syscall layer for SGKILL over the process from vmproc if kernel can't emit processId from traffic control layer, else send sigkill immediantley
			return
		}
		maliciousExfilProcessCount[mapField.ProcessId] += 1
	}
}

func (tun *TCCloneTunnel) SniffPacketsForTunnelDPI() {
	runtime.LockOSThread()

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

	go func() {
		for {
			select {
			case msg, ok := <-sniffTunnelErr:
				if !ok {
					return
				}
				log.Println("Received an error while sniffing the packets over the veth bridge in kernel redirected non standard packet clone", msg)
			default:
				time.Sleep(time.Second)
			}
		}
	}()

	var tunnelTrafficEBPFMaps [2]*ebpf.Map = [2]*ebpf.Map{
		tun.PhysicalTcInterface.TcCollection.Maps[events.EXFIL_SECURITY_EGRESS_RECONNISANCE_MAP_SCAN],
		tun.PhysicalTcInterface.TcCollection.Maps[events.EXFIL_SECURITY_EGREES_CLONE_REDIRECT_MAP_NON_STANDARD_PORT],
	}

	for packet := range packetSource.Packets() {
		go tun.ProcessTunnelHandlerPackets(packet, tunnelTrafficEBPFMaps, sniffTunnelErr)
	}
}

func (tc *TCCloneTunnel) PollRingBuffer(ctx context.Context, ebpfEvents *ebpf.Map) {

	runtime.LockOSThread()
	ringBuffer, err := ringbuf.NewReader(ebpfEvents)

	if err != nil {
		panic(err.Error())
	}

	defer ringBuffer.Close()

	for {
		if utils.DEBUG {
			log.Println("polling the ring buffer", "using th map", ebpfEvents)
		}
		record, err := ringBuffer.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("Error reading ring buffer: %s", err)
			return
		}

		var event events.DnsEvent
		if utils.CpuArch() == "arm64" || utils.CpuArch() == "amd64" {
			log.Println("Polling the ring buffer for the arm arch")
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}
		} else {
			log.Println("Polling the ring buffer for the x86 big endian systems")
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}
		}

		// kernel compatible to  extract process from task struct inside kernel traffic direct action qdisc SCHED_CLS in kernel
		if event.ProcessId != 0 && event.ThreadId != 0 {
			log.Println("Potential DNS tunnel from kernel detected, polled from kernel non standard port tunnel transfer", event)
		} else {
			log.Println("Potential DNS tunnel from kernel detected", event)
		}
	}
}

func (tun *TCCloneTunnel) EnsureTransportTunnelPortMapUpdate(tunnelMap *ebpf.Map,
	destPort uint16, fetchEvent *events.ExfilRawPacketMirror,
	erroChannel chan interface{}, isBenign bool) {

	if isBenign {
		fetchEvent.IsPacketRescanedAndMalicious = uint8(0)
		if err := tunnelMap.Put(uint16(destPort), fetchEvent); err != nil {
			log.Println("Error in updating the map for this benign found packet", err)
			/// the kernel will always ensure the key exist in gthe lru map before it even rich the user space for this bridge to sniff upon
			erroChannel <- struct {
				Err string
			}{
				Err: "Error in updating the map for this benign found packet",
			}
		}
	} else {
		fetchEvent.IsPacketRescanedAndMalicious = uint8(1)
		if err := tunnelMap.Put(uint16(destPort), fetchEvent); err != nil {
			log.Println("Error in updating the map for this benign found packet", err)
			erroChannel <- struct {
				Err string
			}{
				Err: "Error in updating the map for this malicious  found packet for kernel to drop pakcet on next packet transfer ",
			}
		}
	}
}

func (tun *TCCloneTunnel) EnsureCleanUpTunnelPortMap(tunnelMap *ebpf.Map, srcPort uint16) (*events.DnsMapPayloadNonOverlayPort, error) {
	var potentialMalicious events.DnsMapPayloadNonOverlayPort
	if err := tunnelMap.LookupAndDelete(srcPort, &potentialMalicious); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, nil
		}
		return nil, err
	}

	return &potentialMalicious, nil
}

func (tun *TCCloneTunnel) ProcessTunnelHandlerPackets(packet gopacket.Packet, ebpfMaps [2]*ebpf.Map, errorChannel chan interface{}) {
	if utils.DEBUG {
		log.Println("called the sniffer for packet")
	}

	// add more eBPF kernel maps if multiple traffic DPI for xfil events is required
	for _, ebpfMap := range ebpfMaps {
		if ebpfMap == nil {
			log.Println("Error the map parsed for tunneled c2c other socket is null")
			errorChannel <- struct {
				Err string
			}{
				Err: "The kernel ebpf map for tun is nil",
			}
			return
		}
	}

	isPackEncapsulated := func(dnsPacket *layers.DNS, transportPayload []byte) bool {
		if dnsPacket == nil {
			return false
		}

		vxlanHeader := layers.VXLAN{}

		if err := vxlanHeader.DecodeFromBytes(transportPayload, gopacket.NilDecodeFeedback); err != nil {
			return false
		}
		// vxland tunnel encap is always over udp vlan id based port whole packet encap

		remoteDestVniTransportID := vxlanHeader.VNI
		remoteDestVxlanPayload := vxlanHeader.Payload

		etherPayload := layers.Ethernet{}

		if err := etherPayload.DecodeFromBytes(remoteDestVxlanPayload, gopacket.NilDecodeFeedback); err != nil {
			return false
		}

		// only parsing ipv4 l3 as encap for vxlan
		ipv4Header := layers.IPv4{}
		if err := ipv4Header.DecodeFromBytes(etherPayload.Payload, gopacket.NilDecodeFeedback); err != nil {
			return false
		}

		udp := layers.UDP{}
		if err := udp.DecodeFromBytes(ipv4Header.Payload, gopacket.NilDecodeFeedback); err != nil {
			tcp := layers.TCP{}
			if err := tcp.DecodeFromBytes(tcp.Payload, gopacket.NilDecodeFeedback); err != nil {
				return false
			}

			dns := layers.DNS{}
			if err := dns.DecodeFromBytes(tcp.Payload, gopacket.NilDecodeFeedback); err != nil {
				return false
			}

			if utils.DEBUG {
				log.Println("found an encapsulated kernel dns packet the service VNI transport ID is ", remoteDestVniTransportID)
			}
			return true
		} else {
			dns := layers.DNS{}
			if err := dns.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err != nil {
				return false
			}

			if utils.DEBUG {
				log.Println("found an encapsulated kernel dns packet the service VNI transport ID is ", remoteDestVniTransportID)
			}
			return true
		}

	}

	// this will always exist since the kenrel will only allow a l4 packet to reach to this bridge in user space via netfilter
	packetTransportLayer := packet.TransportLayer()
	if packetTransportLayer == nil {
		if utils.DEBUG {
			log.Println("the packet does not have a transport layer")
		}
		// runtime chekc although this would never ever happen since the l4 is always checked in kernel
		// not event a dns packet
		return
	}

	udpPack := packet.Layer(layers.LayerTypeUDP)
	tcpPack := packet.Layer(layers.LayerTypeTCP)

	transportPayload := packetTransportLayer.LayerPayload()
	if len(transportPayload) < 12 {
		if utils.DEBUG {
			log.Println("error while parsing the packet from kernel has header lenght to small")
		}
		// the kernel already have marked this as 0 no need to process anything
		// cannot be a dns packet
		return
	}

	dns := &layers.DNS{}

	err := dns.DecodeFromBytes(transportPayload, gopacket.NilDecodeFeedback)
	if err != nil {
		if utils.DEBUG {
			log.Println("error while parsing the packet from kernel")
		}
		return // not a dns packet
	}

	// Check for DNS layer directly
	if utils.DEBUG {
		log.Println("Received a DNS packet for tunnel .....")
	}

	// a tunneled dns packet overlay over the protocol
	// make the  packet pass through remote inferencing via the unix socket to be inferred with remote unix inference
	processMaliciousInferenceNonStandardPort := func(features []model.DNSFeatures, destTransportPort uint16, srcTransportPort uint16,
		event *events.ExfilRawPacketMirror, ev *events.DnsMapPayloadNonOverlayPort) error {

		isAnySectionMal := false
		for _, feature := range features {
			if utils.GetKeyPresentInEgressCache(feature.Tld) {
				isAnySectionMal = true
				break
			}
		}

		if !isAnySectionMal {

			/// used as a processing input for standard tensor vectors for the deep learning model
			featureVectorsFloat := model.GenerateFloatVectors(features, tun.Onnx)
			if tun.Onnx.StaticRuntimeChecks(featureVectorsFloat, true) == model.DEEP_LEXICAL_INFERENCING {
				client, conn, err := model.GetInferenceUnixClient(true)

				if err != nil {
					log.Println("Error Gettting report inference socket for inference")

				}
				defer conn.Close()

				inferRequest := model.InferenceRequest{
					// pass all the 8 features which define the input layer for the inference in the onnx model
					Features: featureVectorsFloat,
				}
				requestPayload, err := json.Marshal(inferRequest)
				if err != nil {
					log.Fatalf("Error while generating the onnx remote inference request payload  %v", err)
					return err
				}

				resp, err := client.Post(fmt.Sprintf("http://%s/onnx/dns", "unix"), "application/json", bytes.NewBuffer(requestPayload))
				if err != nil {
					log.Printf("Error while evaluating the onnx model for the dns features %v", err)
					return err
				}
				defer resp.Body.Close()

				payload, err := io.ReadAll(resp.Body)

				if err != nil {
					log.Printf("Error while evaluating the onnx model for the dns features %v", err)
					return err
				}

				var inferenceResponse model.InferenceResponse
				err = json.Unmarshal(payload, &inferenceResponse)

				if err != nil {
					log.Printf("Error while unmarshalling the onnx inference response %v", err)
					return err
				}

				if !utils.DEBUG {
					log.Println("Received inference from remote unix socket server ", inferenceResponse, inferenceResponse.ThreatType)
				}

				// detected malicious exfiltrated object
				if inferenceResponse.ThreatType {

					if ev != nil && ev.ProcessId != 0 && ev.ThreadId != 0 {
						tun.IncrementMaliciousProcCountLocalCacheOverlayPort(ev)
					}

					for _, feature := range features {
						go events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(feature), &tun.IfaceHandler.PhysicalNodeBridgeIpv4, "DNS", int(destTransportPort)) // (wont overflow (1 << 16))
					}

					go events.ExportPromeEbpfExporterEvents[events.Malicious_Non_Stanard_Transfer](events.Malicious_Non_Stanard_Transfer{
						Src_port:       int(event.SrcPort),
						Dest_port:      int(event.DstPort),
						IsUDPTransport: false,
					})
				}
			}
			return nil
		} else {
			// mark the packet transfered over non standard port to be benigns
			tun.EnsureTransportTunnelPortMapUpdate(ebpfMaps[0], destTransportPort, event, errorChannel, true)
			for _, feature := range features {
				go events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(feature), &tun.IfaceHandler.PhysicalNodeBridgeIpv4, "DNS", int(destTransportPort)) // (wont overflow (1 << 16))
			}

			go events.ExportPromeEbpfExporterEvents[events.Malicious_Non_Stanard_Transfer](events.Malicious_Non_Stanard_Transfer{
				Src_port:       int(event.SrcPort),
				Dest_port:      int(event.DstPort),
				IsUDPTransport: false,
			})

			for _, feature := range features {
				utils.UpdateDomainBlacklistInEgressCache(feature.Tld, feature.Fqdn)
			}

			return nil
		}
	}

	if udpPack != nil {
		destPort := udpPack.(*layers.UDP).DstPort
		var destPortGenType uint16 = uint16(destPort)
		var srcPortGenType uint16 = uint16(udpPack.(*layers.UDP).SrcPort)
		var event events.ExfilRawPacketMirror // a sniff packet struct not event from ring buffer

		if err := ebpfMaps[0].Lookup(&destPortGenType, &event); err != nil {

			if errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Println("The malware c2c agent is retrying to tunnel c2c exfiltrated traffic over ", destPort)
			} else {
				errorChannel <- struct {
					Err string
				}{
					Err: "The kernel has not cloned the packet from tc layer",
				}
			}
			return
		}

		ev, err := tun.EnsureCleanUpTunnelPortMap(ebpfMaps[1], srcPortGenType)

		if err != nil {
			log.Println("Error in deleting the map for this benign found packet", err)
		}

		if isPackEncapsulated(dns, transportPayload) {
			if utils.DEBUG {
				log.Println("A Vxlan kernel encappsulated dns packet is found in vxlan kernel transport header")
			}
			tun.EnsureTransportTunnelPortMapUpdate(ebpfMaps[0], destPortGenType, &event, errorChannel, true) // send true for now need DPI for deep scan over hte packet structure
			return
		}

		event.IsPacketRescanedAndMalicious = uint8(1)
		features, err := model.ProcessDnsFeatures(dns, true)

		if err != nil {
			log.Println("err is ", err)

			errorChannel <- struct {
				Err string
			}{
				Err: "Error while processing the dns packet features extraction for the malicious tunnel dns traffic over random port from kernel",
			}
		}

		tun.EnsureTransportTunnelPortMapUpdate(ebpfMaps[0], destPortGenType, &event, errorChannel, false)

		// check for the netbios local samba lookup for ns resoultion with NB reocrd for queries
		if !isNetBiosTunnelNSLookUp(dns) {
			for _, feature := range features {
				go events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(feature), &tun.IfaceHandler.PhysicalNodeBridgeIpv4, "DNS", int(destPort))

				go tun.StreamClient.MarshallStreamThreadEvent(feature, stream.HostNetworkExfilFeatures{
					ExfilPort:        strconv.Itoa(int(destPort)),
					Protocol:         string(events.DNS),
					PhysicalNodeIpv4: tun.IfaceHandler.PhysicalNodeBridgeIpv4.String(),
					PhysicalNodeIpv6: tun.IfaceHandler.PhysicalNodeBridgeIpv6.String(),
				})
			}
			// the tunnel metric event for other non stanard port monitor from kernel
			go events.ExportPromeEbpfExporterEvents[events.Malicious_Non_Stanard_Transfer](events.Malicious_Non_Stanard_Transfer{
				Src_port:       int(event.SrcPort),
				Dest_port:      int(event.DstPort),
				IsUDPTransport: true,
			})
		}
		// process nothing in userspace
		// just cehck and deep parse the questions of the record for netbios kernel query because of random port process allow for this port in kernel
		// standard go packet does not parse any NB query records

		if err := processMaliciousInferenceNonStandardPort(features, destPortGenType, srcPortGenType, &event, ev); err != nil {
			if utils.DEBUG {
				log.Printf("Error in streaming the threat event for exfiltration attempt happened over non standard port %+v", err)

				errorChannel <- struct {
					Err string
				}{
					Err: fmt.Sprintf("Error in streaming the threat event for exfiltration attempt happened over non standard port Transport TCP:: %+v", err),
				}
			}
		}

	} else {
		destPort := tcpPack.(*layers.TCP).DstPort
		var destPortGenType uint16 = uint16(destPort)
		var srcPortGenType uint16 = uint16(udpPack.(*layers.UDP).SrcPort)
		// kernel will take care to process and set the packet type when kernel redirect iva link clone to the userspace
		var event events.ExfilRawPacketMirror
		log.Println("the dest port for packet transfer is ", uint16(destPort))
		if err := ebpfMaps[0].Lookup(&destPortGenType, &event); err != nil {
			log.Printf("The kernel has not cloned the packet from tc layer")
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				errorChannel <- struct {
					Err string
				}{
					Err: "The kernel has not cloned the packet from tc layer",
				}
			} else {
				log.Println("There is potential traffic retry redirected from kernel for Deep scan ::", destPort)
				// log.Println("The malware c2c agent is retrying to tunnel c2c exfiltrated traffic over ", destPort)
			}
			return
		}

		ev, err := tun.EnsureCleanUpTunnelPortMap(ebpfMaps[1], srcPortGenType)

		if err != nil {
			log.Println("Error in deleting the map for this benign found packet", err)
		}

		if ev != nil && ev.ProcessId != 0 && ev.ThreadId != 0 {
			tun.IncrementMaliciousProcCountLocalCacheOverlayPort(ev)
		}

		features, err := model.ProcessDnsFeatures(dns, true)
		if err != nil {
			errorChannel <- struct {
				Err string
			}{
				Err: "Error while processing the dns packet features extraction for the malicious tunnel dns traffic over random port from kernel",
			}
		}

		if err := processMaliciousInferenceNonStandardPort(features, destPortGenType, srcPortGenType, &event, ev); err != nil {
			if utils.DEBUG {
				log.Printf("Error in streaming the threat event for exfiltration attempt happened over non standard port %+v", err)

				errorChannel <- struct {
					Err string
				}{
					Err: fmt.Sprintf("Error in streaming the threat event for exfiltration attempt happened over non standard port Transport TCP:: %+v", err),
				}
			}
		}
	}
}
