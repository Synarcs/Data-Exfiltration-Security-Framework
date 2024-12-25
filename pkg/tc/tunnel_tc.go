package tc

// DPI over the clone redirect over tc from kernel done via the tc layer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"runtime"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type TCCloneTunnel struct {
	IfaceHandler             *netinet.NetIface
	GlobalKernelErrorChannel chan bool
	PhysicalTcInterface      *TCHandler
	StreamClient             *events.StreamClient
	Onnx                     *model.OnnxModel
}

func GenerateTcTunnelFactory(tc *TCHandler, iface *netinet.NetIface, globalErrorChannel chan bool,
	streamClient *events.StreamClient, onnx *model.OnnxModel) *TCCloneTunnel {
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

	ebpfMap := tun.PhysicalTcInterface.TcCollection.Maps[events.EXFIL_SECURITY_EGRESS_RECONNISANCE_MAP_SCAN]

	for packet := range packetSource.Packets() {
		go tun.ProcessTunnelHandlerPackets(packet, ebpfMap, sniffTunnelErr)
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

func (tun *TCCloneTunnel) ProcessTunnelHandlerPackets(packet gopacket.Packet, ebpfMap *ebpf.Map, errorChannel chan interface{}) {
	if utils.DEBUG {
		log.Println("called the sniffer for packet")
	}

	if ebpfMap == nil {
		log.Println("Error the map parsed for tunneled c2c other socket is null")
		errorChannel <- struct {
			Err string
		}{
			Err: "The kernel ebpf map for tun is nil",
		}
		return
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
	processMaliciousInferenceNonStandardPort := func(features []model.DNSFeatures, destTransportPort uint16,
		event *events.ExfilRawPacketMirror) error {

		isAnySectionMal := false
		for _, feature := range features {
			if utils.GetKeyPresentInCache(feature.Tld) {
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

				if inferenceResponse.ThreatType {
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
			tun.EnsureTransportTunnelPortMapUpdate(ebpfMap, destTransportPort, event, errorChannel, true)
			for _, feature := range features {
				go events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(feature), &tun.IfaceHandler.PhysicalNodeBridgeIpv4, "DNS", int(destTransportPort)) // (wont overflow (1 << 16))
			}

			go events.ExportPromeEbpfExporterEvents[events.Malicious_Non_Stanard_Transfer](events.Malicious_Non_Stanard_Transfer{
				Src_port:       int(event.SrcPort),
				Dest_port:      int(event.DstPort),
				IsUDPTransport: false,
			})

			for _, feature := range features {
				utils.UpdateDomainBlacklistInCache(feature.Tld, feature.Fqdn)
			}

			return nil
		}
	}

	if udpPack != nil {
		destPort := udpPack.(*layers.UDP).DstPort
		var destPortGenType uint16 = uint16(destPort)
		var event events.ExfilRawPacketMirror
		if err := ebpfMap.Lookup(&destPortGenType, &event); err != nil {

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

		if isPackEncapsulated(dns, transportPayload) {
			if utils.DEBUG {
				log.Println("A Vxlan kernel encappsulated dns packet is found in vxlan kernel transport header")
			}
			tun.EnsureTransportTunnelPortMapUpdate(ebpfMap, destPortGenType, &event, errorChannel, true) // send true for now need DPI for deep scan over hte packet structure
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

		tun.EnsureTransportTunnelPortMapUpdate(ebpfMap, destPortGenType, &event, errorChannel, false)

		// check for the neybios local samba lookup for ns resoultion with NB reocrd for queries
		if !isNetBiosTunnelNSLookUp(dns) {
			for _, feature := range features {
				go events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(feature), &tun.IfaceHandler.PhysicalNodeBridgeIpv4, "DNS", int(destPort))
				go tun.StreamClient.MarshallStreamThreadEvent(feature)
			}
			// the tunnel metric event for other non stanard port monitor from kernel
			go events.ExportPromeEbpfExporterEvents[events.Malicious_Non_Stanard_Transfer](events.Malicious_Non_Stanard_Transfer{
				Src_port:       int(event.SrcPort),
				Dest_port:      int(event.DstPort),
				IsUDPTransport: true,
			})
		}
		// process nothing in userspace
		// just cehck and deep parse the questions of the record for netbios kernel query
		// standard go packet does not parse any NB query records

		if err := processMaliciousInferenceNonStandardPort(features, destPortGenType, &event); err != nil {
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
		// kernel will take care to process and set the packet type when kernel redirect iva link clone to the userspace
		var event events.ExfilRawPacketMirror
		log.Println("the dest port for packet transfer is ", uint16(destPort))
		if err := ebpfMap.Lookup(&destPortGenType, &event); err != nil {
			log.Printf("The kernel has not cloned the packet from tc layer")
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				errorChannel <- struct {
					Err string
				}{
					Err: "The kernel has not cloned the packet from tc layer",
				}
			} else {
				log.Println("The malware c2c agent is retrying to tunnel c2c exfiltrated traffic over ", destPort)
			}
			return
		}

		features, err := model.ProcessDnsFeatures(dns, true)
		if err != nil {
			errorChannel <- struct {
				Err string
			}{
				Err: "Error while processing the dns packet features extraction for the malicious tunnel dns traffic over random port from kernel",
			}
		}

		if err := processMaliciousInferenceNonStandardPort(features, destPortGenType, &event); err != nil {
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
