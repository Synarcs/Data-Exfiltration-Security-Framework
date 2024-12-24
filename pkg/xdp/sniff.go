package xdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
)

type IngressSniffHandler struct {
	IfaceHandler *netinet.NetIface
	Ctx          context.Context
	OnnxModel    *model.OnnxModel
	DnsFeatures  *model.DNSFeatures
	DnsPacketGen *model.DnsPacketGen
	StreamClient *events.StreamClient

	GlobalErrorKernelHandlerChannel chan bool // handles all control channel created by main to kill any kernel code if found runtime panics
}

// a builder facotry for the tc load and process all tc egress traffic over the different filter chain which node agent is running
// TODO: Fix all the code redundancies
func GenerateXDPIngressFactory(iface netinet.NetIface,
	onnxModel *model.OnnxModel, streamClient *events.StreamClient, globalErrorKernelHandlerChannel chan bool) IngressSniffHandler {
	return IngressSniffHandler{
		IfaceHandler:                    &iface,
		DnsPacketGen:                    model.GenerateDnsParserModelUtils(&iface, onnxModel, streamClient),
		OnnxModel:                       onnxModel,
		StreamClient:                    streamClient,
		GlobalErrorKernelHandlerChannel: globalErrorKernelHandlerChannel,
	}
}

func (ing *IngressSniffHandler) RemoteIngressInference(features [][]float32,
	rawFeatures []model.DNSFeatures) error {

	if ing.OnnxModel.StaticRuntimeChecks(features, false) == model.DEEP_LEXICAL_INFERENCING {
		// process deep lexical analysis from remote unix transport inference server
		inferRequest := model.InferenceRequest{
			// pass all the 8 features which define the input layer for the inference in the onnx model
			Features: features,
		}
		// layer 7 markup over layer 4 unix transport
		ingressClient, _, err := model.GetInferenceUnixClient(false)

		if err != nil {
			log.Printf("Error while evaluating the onnx model for the dns features %v", err)
			return err
		}

		// need this over multiplex transport layer 7 transport
		requestPayload, err := json.Marshal(inferRequest)
		if err != nil {
			log.Fatalf("Error while generating the onnx remote inference request payload  %v", err)
		}
		resp, err := ingressClient.Post(fmt.Sprintf("http://%s/onnx/dns/ing", "unix"), "application/json", bytes.NewBuffer(requestPayload))
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
		var inferenceResponse model.InferenceResponseIngress
		err = json.Unmarshal(payload, &inferenceResponse)

		if err != nil {
			log.Printf("Error while unmarshalling the onnx inference response %v", err)
			return err
		}

		if utils.DEBUG {
			log.Println("Remote inference over unix ingress socket for transport for node agent ", inferenceResponse)
		}

		for index, resp := range inferenceResponse.ThreatType {
			if resp {
				utils.IngUpdateDomainBlacklistInCache(rawFeatures[index].Tld)
				// putting here 53 the standard DNS port since the socket transport from kernel must be detected before handl itself no need to again check
				// the same port as used for egrres will be used as src port for response from remote c2c malware
				go events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(rawFeatures[index]), &ing.IfaceHandler.PhysicalNodeBridgeIpv4, events.DNS, utils.DNS_EGRESS_PORT)
				go ing.StreamClient.MarshallThreadEvent(rawFeatures[index])
			}
		}
	}
	return nil
}

func (ing *IngressSniffHandler) ProcessEachPacket(packet gopacket.Packet, ifaceHandler *netinet.NetIface, handler *pcap.Handle) error {

	eth := packet.Layer(layers.LayerTypeEthernet)
	var isIpv4 bool
	var isUdp bool
	if eth == nil {
		return fmt.Errorf("no ethernet layer")
	}

	// var ipPacket *layers.IPv4
	// var ipv6Packet *layers.IPv6

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		isIpv4 = false
	} else {
		isIpv4 = true
	}

	if utils.DEBUG {
		log.Println("packet L3 and L4 ", isIpv4, isUdp)
	}

	transportLayer := packet.Layer(layers.LayerTypeUDP)
	var dnsLengthTcp uint16 = 0
	var dnsTcpPayload []byte

	var tcpCheck bool = false
	if transportLayer != nil {
		udpPacket := transportLayer.(*layers.UDP)
		if udpPacket != nil {
			isUdp = true
		} else {
			panic(fmt.Errorf("the packet is malformed"))
		}
	} else {
		transportLayer = packet.Layer(layers.LayerTypeTCP)
		tcpPacket := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)

		if tcpPacket != nil {
			isUdp = false
		} else {
			panic(fmt.Errorf("the packet is malformed"))
		}
		payload := tcpPacket.Payload

		fmt.Println("found tcp packet for domain dest port 53 ", tcpPacket, isUdp, isIpv4, payload)

		if len(payload) < 2 {
			log.Println("errror ", len(payload))
			return fmt.Errorf("TCP payload too short for dns parsing")
		}

		dnsLengthTcp = binary.BigEndian.Uint16(payload[0:2])

		log.Println("The DNs packet parsdd over tcp transport with length ", dnsLengthTcp)
		dnsTcpPayload = payload[2:]
		tcpCheck = true
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)

	if dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)

		processFeaturesInference := func() error {
			features, err := model.ProcessDnsFeatures(dns, false)
			if err != nil {
				log.Println(err)
				return err
			}

			vectors := model.GenerateFloatVectors(features, ing.OnnxModel)
			ing.RemoteIngressInference(vectors, features)
			return nil
		}

		if isIpv4 && isUdp {
			// ipv4 and udp
			if err := processFeaturesInference(); err != nil {
				return err
			}
		}
		if !isIpv4 && isUdp {
			// ipv6 and udp
			if err := processFeaturesInference(); err != nil {
				return err
			}
		}

	} else if tcpCheck {
		dns := &layers.DNS{}

		err := dns.DecodeFromBytes(dnsTcpPayload, gopacket.NilDecodeFeedback)
		if err != nil {
			log.Println("Error decoding the dns packet over the tcp stream", err)
			return err
		}

		var ip_layer3_checksum_kernel_ts events.DPIRedirectionKernelMap // granualar timining control over the redirection from kernel

		if isIpv4 && !isUdp {
			// ipv4 and tcp
			ing.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum,
				handler, false, isIpv4, isUdp, nil)
		}
		if !isIpv4 && !isUdp {
			// ipv6 and tcp
			ing.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum, handler, false, isIpv4,
				isUdp, nil)
		}
	}
	return nil
}

func (ing *IngressSniffHandler) SniffIgressForC2C() error {
	var errorChannel chan error = make(chan error)
	log.Println("Sniffing Ingress traffic for potential malicious remote C2C commands")

	// do deep lexcial analysis of the packet over the ingress for the response action set
	processPcapFilterHandlerIngress := func(linkInterface netlink.Link,
		errorChannel chan<- error, isUdp bool, isStandardPort bool) error {
		cap, err := pcap.OpenLive(linkInterface.Attrs().Name, int32(linkInterface.Attrs().MTU), true, pcap.BlockForever)
		if err != nil {
			fmt.Println("error opening packet capture over hz,te interface from kernel")
			errorChannel <- err
		}
		defer cap.Close()

		if (isUdp || !isUdp) && isStandardPort {
			// runs over br netfilter layer on iptables
			if isUdp {
				log.Println("Generated Ingress Packet Listener to parse DNS packets from kernel over the UDP Layer")
			} else {
				log.Println("Generated Ingress Packet Listener to parse DNS packets from kernel over the TCP Layer")
			}
			if err := cap.SetBPFFilter("udp src port 53 or tcp src port 53"); err != nil {
				log.Fatalf("Error setting BPF filter: %v", err)
			}
		} else if !isUdp && !isStandardPort {
			err := "Not Implemented for non stard port DPI for DNS with no support for ebpf from kernel"
			return fmt.Errorf("err %s", err)
		}

		packets := gopacket.NewPacketSource(cap, cap.LinkType())
		for pack := range packets.Packets() {
			go ing.ProcessEachPacket(pack, ing.IfaceHandler, cap)
		}
		return nil
	}

	for _, link := range ing.IfaceHandler.PhysicalLinks {
		go processPcapFilterHandlerIngress(link, errorChannel, true, true)
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
