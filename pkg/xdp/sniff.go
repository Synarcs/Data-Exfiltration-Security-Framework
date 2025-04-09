package xdp

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream"
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
	StreamClient *stream.StreamProducer

	GlobalErrorKernelHandlerChannel chan error // handles all control channel created by main to kill any kernel code if found runtime panics
}

// a builder facotry for the tc load and process all tc egress traffic over the different filter chain which node agent is running
// TODO: Fix all the code redundancies
func NewIngressSnifferFactory(iface *netinet.NetIface,
	onnxModel *model.OnnxModel, streamClient *stream.StreamProducer, globalErrorKernelHandlerChannel chan error) *IngressSniffHandler {

	// only use  for ingress support for the link (net_device) in kernel
	// Ingress sniff and process neither need AF_XDP not AF_PACKET

	return &IngressSniffHandler{
		IfaceHandler:                    iface,
		OnnxModel:                       onnxModel,
		StreamClient:                    streamClient,
		GlobalErrorKernelHandlerChannel: globalErrorKernelHandlerChannel,
	}
}

func (ing *IngressSniffHandler) RemoteIngressInference(features [][]float32,
	rawFeatures []model.DNSFeatures) error {

	if ing.OnnxModel.StaticRuntimeChecks(features, false) == model.DEEP_LEXICAL_INFERENCING {
		IngressRemoteInferHandler(features, rawFeatures, ing.IfaceHandler, ing.StreamClient)
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
	var dnsTcpPayload []byte

	var tcpCheck bool = false
	if transportLayer != nil {
		udpPacket := transportLayer.(*layers.UDP)
		if udpPacket != nil {
			isUdp = true
		} else {
			panic(fmt.Errorf("the packet is malformed"))
		}
	}

	dnsLayer := packet.Layer(layers.LayerTypeDNS)

	if dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)

		processFeaturesInference := func() error {
			features, err := model.ProcessDnsFeatures(dns, false)
			if err != nil {
				log.Println(err.Error())
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

		// TODO: Support deep parsing for parsing Ingress  TCP traffic
	}
	return nil
}

func (ing *IngressSniffHandler) SniffIgressForC2C(ctx context.Context, sniffUDPPort uint16) error {
	var errorChannel chan error = make(chan error) // dedicated channel to sniff and process ingress sniff errors
	var graceFulCloseSniff chan bool = make(chan bool)
	log.Println("Sniffing Ingress traffic for potential malicious remote C2C commands")

	// do deep lexcial analysis of the packet over the ingress for the response action set
	processPcapFilterHandlerIngress := func(linkInterface netlink.Link,
		errorChannel chan<- error) error {
		cap, err := ing.IfaceHandler.GetPcapHandleoverNetDev(linkInterface)
		if err != nil {
			fmt.Println("error opening packet capture over hz,te interface from kernel")
			errorChannel <- err
		}
		defer cap.Close()

		// runs over br netfilter layer on iptables
		log.Println("Generated Ingress Packet Listener to sniff DNS packets over the UDP and TCP Transport Layer")
		if err := cap.SetBPFFilter(fmt.Sprintf("udp src port %d or tcp src port %d", sniffUDPPort, sniffUDPPort)); err != nil {
			log.Fatalf("Error setting BPF filter: %v", err)
			return err
		}

		packets := gopacket.NewPacketSource(cap, cap.LinkType())
		for {
			select {
			case <-ctx.Done():
				if sniffUDPPort != utils.DNS_EGRESS_PORT {
					log.Println("context cancelled for sniffing over this malicious port ", sniffUDPPort, "since the process was SIGKILL by node agent in user-space")
				}
				graceFulCloseSniff <- true
				return nil
			case pack := <-packets.Packets():
				go ing.ProcessEachPacket(pack, ing.IfaceHandler, cap)
			}
		}
	}

	for _, link := range ing.IfaceHandler.PhysicalLinks {
		go processPcapFilterHandlerIngress(link, errorChannel)
	}

	for {
		select {
		case err, isClosed := <-errorChannel:
			if !isClosed {
				return nil
			}
			close(errorChannel)
			return err
		case _, isClosed := <-graceFulCloseSniff:
			if !isClosed {
				return nil
			}
			close(graceFulCloseSniff)
			return nil
		default:
			time.Sleep(time.Second)
		}
	}
}
