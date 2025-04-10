package tc

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/conf"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/crypto"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/progs"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/tracepoint"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type TCHandler struct {
	Interfaces      *netinet.NetIface
	Prog            *ebpf.Program    // ebpf program for tc with clsact class BPF_PROG_TYPE_CLS_ACT
	TcCollection    *ebpf.Collection // ebpf tc program collection order spec
	DnsPacketGen    *model.DnsPacketGen
	OnnxLoadedModel *model.OnnxModel

	TcTunnelNonStandardPortScan     *TCCloneTunnel // sniffer routine for processing clone redirect traffic to precess exfiltrated traffic over non stanard ports for UDP / TCP transport
	GlobalErrorKernelHandlerChannel chan error     // handles all control channel created by main to kill any kernel code if found runtime panics

	IsEgressXdpSupport   bool
	TcTracepointHandlers *tracepoint.ExfilSecTreacePoint // store all the tracepoint attached and related to tc handlers

	Hash *crypto.Hash // skb agent crypto hash for agent integrity of skb over each redirect

	// the node agent consumer will ensure to send malicious ip address over this channel for node agent to inject them in kernel
	GlobalMalC2L3addressChannelIpv4 chan net.IP
	GlobalMalC2L3addressChannelIpv6 chan net.IP

	config conf.AgentConfig

	CryptoAgentLSMHandler *crypto.CryptoBpfLsm
}

// init AF_PACKET, AF_XDP socket for the kernel
var (
	INIT_KERNEL_SOCKET        = true
	INIT_LIMITS_KERNEL_CONFIG = false
)

var mapsToPinSharedProcKillMap []string

func NewDnsPacketResendUtils(interfaces *netinet.NetIface, onnxModel *model.OnnxModel,
	streamClient *stream.StreamProducer) (*model.DnsPacketGen, error) {
	xdpSocketFd, err := interfaces.GetRootNamespaceRawSocketFdXDP()
	if err == nil {
		utils.Log("[Using the raw packet with AF_PACKET Fd")

		return &model.DnsPacketGen{
			IfaceHandler:        interfaces,
			SockSendFdInterface: interfaces.PhysicalLinks,
			XdpSocketSendFd:     xdpSocketFd,
			SocketSendFd:        nil,
			OnnxModel:           onnxModel,
			StreamClient:        streamClient,
		}, nil
	} else {
		utils.Log("Error Binding the XDP Socket Physical driver lacking support")
		fd, err := interfaces.GetRootNamespaceRawSocketFd()

		if err != nil {
			return nil, err
		}
		return &model.DnsPacketGen{
			IfaceHandler:        interfaces,
			SockSendFdInterface: interfaces.PhysicalLinks,
			SocketSendFd:        fd,
			XdpSocketSendFd:     nil,
			OnnxModel:           onnxModel,
			StreamClient:        streamClient,
		}, nil
	}
}

// a builder facotry for the tc load and process all tc egress traffic over the different filter chain which node agent is running
func NewTcEgressFactory(iface netinet.NetIface, onnxModel *model.OnnxModel,
	streamClient *stream.StreamProducer,
	globalErrorKernelHandlerChannel chan error, agentHash *crypto.Hash, config conf.AgentConfig,
	cryptoAgentLSMHandler *crypto.CryptoBpfLsm) (*TCHandler, error) {
	dnsPacketGen, err := NewDnsPacketResendUtils(&iface, onnxModel, streamClient)

	if err != nil {
		return nil, err
	}

	tcHandler := &TCHandler{
		Interfaces:                      &iface,
		DnsPacketGen:                    dnsPacketGen,
		OnnxLoadedModel:                 onnxModel,
		GlobalErrorKernelHandlerChannel: globalErrorKernelHandlerChannel,
		Hash:                            agentHash,
		config:                          config,
		CryptoAgentLSMHandler:           cryptoAgentLSMHandler,
	}
	if dnsPacketGen.XdpSocketSendFd != nil {
		tcHandler.IsEgressXdpSupport = true
	}

	InitPinMapHandlerNames(config)
	ipv4c2mal, ipv6c2mal := utils.GenerateC2BlacklistAddressChannels()
	tcHandler.GlobalMalC2L3addressChannelIpv4 = ipv4c2mal
	tcHandler.GlobalMalC2L3addressChannelIpv6 = ipv6c2mal
	return tcHandler, nil
}

func InitPinMapHandlerNames(config conf.AgentConfig) {
	mapsToPinSharedProcKillMap = []string{
		events.EXFIL_SECURITY_EGRESS_PROC_MAL,
		events.EXFIL_SECURITY_EGRESS_NSP_MAP,
		events.EXFIL_SOCK_UDP_CONN_MAP,
	}
	if config.GetL3FiltersConfig().EnabledL3v4Filtering {
		mapsToPinSharedProcKillMap = append(mapsToPinSharedProcKillMap, events.EXFIL_SECURITY_EGRESS_L3_IPV4_DYNAMIC_NETPOOL_C2_FILTER)
	}

	if config.GetL3FiltersConfig().EnabledL3v6Filtering {
		mapsToPinSharedProcKillMap = append(mapsToPinSharedProcKillMap, events.EXFIL_SECURITY_EGRESS_L3_IPV6_DYNAMIC_NETPOOL_C2_FILTER)
	}
}

func (tc *TCHandler) PollMaliciousControllerAwareC2Address(errorChannel <-chan error) {
	// ipv4
	go func() {
		for ipv4 := range tc.GlobalMalC2L3addressChannelIpv4 {
			getIpv4BigEndianAddr := utils.GenerateBigEndianIpv4(ipv4.String())
			utils.Log("Injecting the malicious C2 address into the kernel", getIpv4BigEndianAddr)
		}
	}()
	go func() {
		for ipv6 := range tc.GlobalMalC2L3addressChannelIpv6 {
			getIpv6BigEndianAddrOc1, getIpv6BigEndianAddrOc2 := utils.GenerateBigEndianIpv6(ipv6.String())
			utils.Log("Injecting the malicious C2 address into the kernel", getIpv6BigEndianAddrOc1, getIpv6BigEndianAddrOc2)
		}
	}()
}

func (tc *TCHandler) InitDnsRateLimiter(ctx context.Context) error {

	rlimitConfig := tc.config.GetRLimitConfig()

	// the map always be created in kernel if rate limit feature is enabled
	rltmap := tc.TcCollection.Maps[events.EXFIL_SECURITY_TOKEN_BUCKET_DNS_RL]

	if rltmap == nil {
		utils.Log("Runtime Error kernel should have this map defined ")
		return nil
	}

	var tbConfig events.TokenBucketEgressDnsConf = events.TokenBucketEgressDnsConf{
		MaxTokens: uint64(rlimitConfig.Tb.MaxTokens),
	}

	var rlimitCtbKey uint16 = 0
	if err := rltmap.Update(&rlimitCtbKey, &tbConfig, ebpf.UpdateNoExist); err != nil {
		return err
	}

	return nil
}

func (tc *TCHandler) AttachTcHandler(ctx context.Context, prog *ebpf.Program) error {

	for _, link := range tc.Interfaces.PhysicalLinks {
		utils.Log("Attaching TC qdisc to the interface ", link.Attrs().Name)
		_, err := netlink.QdiscList(link)
		if err != nil {
			panic(err.Error())
		}

		qdisc_clsact := &netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(0xffff, 0),
			},
		}
		if err := netlink.QdiscReplace(qdisc_clsact); err != nil {
			panic(err.Error())
		}

		filter := netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           prog.FD(),
			Name:         prog.String(),
			DirectAction: true,
		}

		if err := netlink.FilterReplace(&filter); err != nil {
			panic(err.Error())
		}

		// attach and start bpf timers in kernel as the program is injected in the kernel

		enhancedFeatures := tc.config.GetAddonFeaturesConfig()
		if enhancedFeatures.Dns.EnabledTbRlimit {
			if err := tc.InitDnsRateLimiter(ctx); err != nil {
				utils.Log("Error initializing the dns rate limiter", err.Error())
				tc.GlobalErrorKernelHandlerChannel <- err
			}
		}

	}
	return nil
}

func (tc *TCHandler) PollMonitoringMaps(ctx context.Context, ebpfMap *ebpf.Map, errorEventChannel chan error) error {
	var KernelPacketRedirectCount uint16 = 0

	runtime.LockOSThread()

	defer runtime.UnlockOSThread()
	localCache, err := lru.New[uint32, bool](5)

	if err != nil {
		utils.Log("Error allocating local packet count kernel cache", err)
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			var PacketCountKernel uint32 = 0
			if err := ebpfMap.Lookup(KernelPacketRedirectCount, &PacketCountKernel); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					continue
				} else {
					utils.Log("Error polling metric for redirected kernel count", err)
					errorEventChannel <- err
				}
			}
			_, ok := localCache.Get(PacketCountKernel)
			if ok {
				continue
			}
			info, err := ebpfMap.Info()

			if err != nil {
				utils.Log(fmt.Sprintf("error getting the kernel ebpf map info %+v", err))
				return err
			}

			mapName := strings.Replace((strings.Replace(strings.Replace(ebpfMap.String(), info.Type.String(), "", -1), "(", "", -1)), ")", "", -1)
			mapName = strings.TrimSpace(mapName)
			mapName = strings.Split(mapName, "#")[0]
			if utils.DEBUG {
				utils.Log("The current Redirected count of packets is ", mapName, PacketCountKernel)
			}
			localCache.Add(PacketCountKernel, true)

			switch mapName {
			case events.EXFOLL_SECURITY_KERNEL_REDIRECT_COUNT_MAP:
				if err := events.ExportPromeEbpfExporterEvents[events.PacketDPIRedirectionCountEvent](events.PacketDPIRedirectionCountEvent{
					KernelRedirectPacketCount: PacketCountKernel,
					EvenTime:                  time.Now().Format(time.RFC3339),
				}); err != nil {
					if !utils.DEBUG {
						utils.Log("Error Streaming the prometheus metrics", err)
					}
				}
			case events.EXFILL_SECURITY_EGRESS_REDIRECT_KERNEL_DROP_COUNT_MAP:
				if err := events.ExportPromeEbpfExporterEvents[events.PacketDPIKernelDropCountEvent](events.PacketDPIKernelDropCountEvent{
					KernelDropPacketCount: PacketCountKernel,
					EvenTime:              time.Now().Format(time.RFC3339),
				}); err != nil {
					if !utils.DEBUG {
						utils.Log("Error Streaming the prometheus metrics", err)
					}
				}
			default:
				{
				}
			}

			time.Sleep(time.Second)
		}
	}
}

func (tc *TCHandler) TcHandlerEbfpProg(ctx context.Context, iface *netinet.NetIface, injectChan map[string]chan bool) {
	utils.Log("Attaching a kernel Handler for the TC CLS_Act Qdisc")
	if errors.Is(ctx.Err(), context.Canceled) {
		utils.Log("Tc Egress Handler Qdisc Attach Event cancelled due to root context cancellation ...")
		return
	}

	handler, err := utils.ReadEbpfFromSpec(ctx, utils.TC_EGRESS_ROOT_NETIFACE_INT)

	if err != nil {
		tc.GlobalErrorKernelHandlerChannel <- err
		return
	}

	rawEbpfProgBytes, err := utils.ReadEbpfProgRaw(utils.TC_EGRESS_ROOT_NETIFACE_INT)

	if err != nil {
		tc.GlobalErrorKernelHandlerChannel <- err
		return
	}

	for name, mapSpec := range handler.Maps {
		if strings.Contains(mapsToPinSharedProcKillMap[0], name) {
			mapSpec.Pinning = ebpf.PinByName
		}
	}

	spec, err := ebpf.NewCollectionWithOptions(handler, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: utils.PINPATH,
		},
	})
	if err != nil {
		panic(err)
	}

	defer spec.Close()

	prog := spec.Programs[utils.TC_CONTROL_PROG]
	if prog == nil {
		tc.GlobalErrorKernelHandlerChannel <- fmt.Errorf("No Required TC Hook found for DNS egress %s", utils.TC_CONTROL_PROG)
		return
	}

	info, err := prog.Info()
	if err != nil {
		tc.GlobalErrorKernelHandlerChannel <- err
		return
	}

	if utils.DEBUG {
		if err := tc.CryptoAgentLSMHandler.InjectLSMProgsPostSignatureGenerate(rawEbpfProgBytes, info, nil); err != nil {
			tc.GlobalErrorKernelHandlerChannel <- err
			return
		}
	}

	tc.Prog = prog
	tc.TcCollection = spec

	if err := tc.AttachTcHandler(ctx, prog); err != nil {
		utils.Log("Error attaching the clsact bpf qdisc for netdev")
		tc.GlobalErrorKernelHandlerChannel <- err
		return
	}

	if len(iface.BridgeLinks) != 2 {
		utils.Logger.Fatalf("The Node agent cannot be botted unless all the DPI linux veth bridges are added using netlink before exiting ....")
		// TODO: Add a process global error channel for detach if any of the tc panic
		tc.GlobalErrorKernelHandlerChannel <- fmt.Errorf("The required bridge used for deep security scans not created, please make sure proper veth bridges exist and required linux ns")
		return
	}

	configMap := tc.TcCollection.Maps[events.EXFILL_SECURITY_KERNEL_CONFIG_MAP]

	injectChan[progs.TC_PROG] <- true

	if configMap != nil {
		for index, link := range iface.PhysicalLinks {

			var kernelTCConfig events.ExfilKernelConfig = events.ExfilKernelConfig{
				BridgeIndexId:           uint32(iface.BridgeLinks[0].Attrs().Index),
				NfNdpBridgeIndexId:      uint32(iface.BridgeLinks[1].Attrs().Index),
				RedirectIpv4:            utils.GenerateBigEndianIpv4(utils.GetIpv4AddressUserSpaceDpIString(index + 1)),
				NfNdpBridgeRedirectIpv4: utils.GenerateBigEndianIpv4(utils.BRIDGE_IPAM_MAL_TUNNEL_IPV4_IP),
				KernelTCSKBMark:         tc.Hash.SkbHash,
				IsAgressiveSec:          1, // runs the agent config in aggressive mode to stop even single malicious exfiltration attempt
			}

			if !utils.DEBUG {
				if kernelTCConfig.IsAgressiveSec == 1 {
					utils.Log(fmt.Sprintf("For Netdev :: %s, Exfiltration security runs in aggresive mode to stop even a single exfiltrated or C2 command respond pass via DNS", link.Attrs().Name))
				}
			}

			err := configMap.Put(uint32(link.Attrs().Index), kernelTCConfig)
			if err != nil {
				tc.GlobalErrorKernelHandlerChannel <- err
				return
			}
		}

	}

	// populate the limit map from the kernel
	// makes the kernel packet redirection re-programmable to kernel process the packet redirection based on the limit configured
	// usually kernel process each packet via default bpf_spinlocks to ensure each map is memory safe in kernel heap and consistent
	dnsLimitsMap := tc.TcCollection.Maps[events.EXFILL_SECURITY_KERNEL_DNS_LIMITS_MAP]
	if dnsLimitsMap != nil {
		// grab the fd from the kernel process to load the egress filter map limit

		for index, limit := range events.DNS_LIMITS_CONFIG {
			err := dnsLimitsMap.Put(
				index, limit)
			if err != nil {
				utils.Log("error loading the dns limits in kernel Default in Kernel Loaded BPF object")
			}
		}

		INIT_LIMITS_KERNEL_CONFIG = true
		if utils.DEBUG {
			utils.Log("The Node Agent loaded the dns limits in Kernel successfully")
		}
	}

	errMapPollChannel := make(chan error)
	for _, maps := range spec.Maps {
		// process all the maps which needs to monitoted or polled from kernel for events without explicity events for ring buffer
		if strings.Contains(maps.String(), events.EXFIL_SECURITY_EGRESS_VXLAN_ENCAP_DROP) {
			go tc.PollVxlanRingBuffer(ctx, maps)
		}
		if strings.Contains(maps.String(), events.EXFOLL_SECURITY_KERNEL_REDIRECT_COUNT_MAP) || strings.Contains(maps.String(), events.EXFILL_SECURITY_EGRESS_REDIRECT_KERNEL_DROP_COUNT_MAP) {
			go tc.PollMonitoringMaps(ctx, maps, errMapPollChannel)
		}
	}

	go func() {
		for {
			select {
			case pollError, ok := <-errMapPollChannel:
				if !ok {
					utils.Logger.Fatal("Channel closed for polling kernel events")
				}
				utils.Log("Error polling kernel events", pollError)
				tc.GlobalErrorKernelHandlerChannel <- pollError
				return
			default:
				time.Sleep(time.Second)
			}
		}
	}()

	if INIT_KERNEL_SOCKET {
		if !utils.VerifyKernelEgressTCClsactTaskCommSuppert() {
			utils.Log("Kernel does not support the required egress tc clsact task com for secure malicious port DNS scan will use port  for mal process monitor in kernel")
			return
		}
		tc_tunnel := NewTcTunnelFactory(tc, iface,
			tc.GlobalErrorKernelHandlerChannel, tc.DnsPacketGen.StreamClient, tc.OnnxLoadedModel)
		tc.TcTunnelNonStandardPortScan = tc_tunnel

		// spawn go routine to handle ring buffer polling for nonstandard exfiltrated traffic over the ports
		for _, maps := range spec.Maps {
			if strings.Contains(maps.String(), events.EXFIL_SECURITY_EGREES_REDIRECT_RING_BUFF_NON_STANDARD_PORT) {
				// an ring event buffer
				go tc_tunnel.PollRingBuffer(ctx, maps)
			}
		}

		go tc_tunnel.SniffPacketsForTunnelDPI() // start the packet sniffing for non standard ports bpf_redirect_clone from kernel space

		if utils.VerifyKernelEgressTCClsactTaskCommSuppert() {
			tracepoint_sched := tracepoint.GenerateTracePointHandlers()
			tracepoint_sched.AttachTracePointHandlers(ctx, iface)
		}

		tc.ProcessSniffDPIPacketCapture(ctx, iface, nil)
		INIT_KERNEL_SOCKET = false
	}
}

func (tc *TCHandler) InjectKernelHandlerPacketRedirectLimit(cliProcessedDnsConfig map[uint32]uint32) error {
	dnsLimitsMap := tc.TcCollection.Maps[events.EXFILL_SECURITY_KERNEL_DNS_LIMITS_MAP]
	if dnsLimitsMap != nil {
		// grab the fd from the kernel process to load the egress filter map limit

		for index, limit := range cliProcessedDnsConfig {
			err := dnsLimitsMap.Put(
				index, limit)
			if err != nil {
				utils.Log("error loading the dns limits in kernel Default in Kernel Loaded BPF object")
			}
		}

		if utils.DEBUG {
			utils.Log("The Node Agent loaded the dns limits in Kernel successfully")
		}
	}
	return nil
}

func (tc *TCHandler) ProcessEachPacket(ctx context.Context, packet gopacket.Packet, ifaceHandler *netinet.NetIface,
	handler *pcap.Handle, isPhysicalNetDevSniff bool) error {

	eth := packet.Layer(layers.LayerTypeEthernet)
	var isIpv4 bool
	var isUdp bool
	if eth == nil {
		return nil
	}

	var ipPacket *layers.IPv4
	var ipv6Packet *layers.IPv6

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipv6Packet = (packet.Layer(layers.LayerTypeIPv6)).(*layers.IPv6)
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
		isIpv4 = false
	} else {
		ipPacket = (packet.Layer(layers.LayerTypeIPv4)).(*layers.IPv4)
		isIpv4 = true
		if utils.DEBUG {
			fmt.Println("current packet checksum", ipPacket.Checksum)
		}
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
			utils.Log("the packet is malformed")
			return nil
		}
	} else if isPhysicalNetDevSniff {
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
			utils.Log("errror ", len(payload))
			return fmt.Errorf("TCP payload too short for dns parsing")
		}

		dnsLengthTcp = binary.BigEndian.Uint16(payload[0:2])

		utils.Log("The DNs packet parsdd over tcp transport with length ", dnsLengthTcp)
		dnsTcpPayload = payload[2:]
		tcpCheck = true
	}

	// init conside for pcap over udp dg only for now

	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	dnsMapRedirectMap := tc.TcCollection.Maps[events.EXFILL_SECURITY_EGRESS_REDIRECT_MAP]
	dnsMapRedirectVerify := tc.TcCollection.Maps[events.EXFILL_SECURITY_EGRESS_REDIRECT_TC_VERIFY_MAP]

	if isIpv4 {
		ipv4Address := ipPacket.DstIP.To4().String()
		if !(ipv4Address == utils.GetIpv4AddressUserSpaceDpIString(1) || ipv4Address == utils.GetIpv4AddressUserSpaceDpIString(2)) {
			utils.Log("The Bridge is only meant for DPI pf suspicious or Malicious DNS traffic")
			return fmt.Errorf("packet is not destined for the userspace DPI on the bridge Interface")
		}

		if ipv4Address == utils.GetIpv4AddressUserSpaceDpIString(2) {
			// packet is malicious found from kernel and link redirected and no further DPI should be done on user space
			events.HandleKernelDroppedPacket(
				dnsLayer, isIpv4, isUdp, "DNS",
			)
			return nil
		}

	} else {
		ipv6Address := ipv6Packet.DstIP.To16().String()

		if ipv6Address == utils.MALICIOUS_NETNS_IPV6 {
			events.HandleKernelDroppedPacket(
				dnsLayer, isIpv4, isUdp, "DNS",
			)

			return nil
		}
	}

	isIpv6 := !isIpv4

	processVeifyKernelDnsTS := func(dns_packet_id uint16, ip_layer3_checksum_kernel_ts *events.DPIRedirectionKernelMap) error {

		err := dnsMapRedirectMap.Lookup(&dns_packet_id, ip_layer3_checksum_kernel_ts)
		if err != nil {
			utils.Log("Required redirected packet id is not found in the map", err, dnsMapRedirectMap)
		} else {
			if utils.DEBUG {
				utils.Log("found the required key from BPF Hash fd ", ip_layer3_checksum_kernel_ts.Checksum, time.Unix(0, int64(ip_layer3_checksum_kernel_ts.Kernel_timets)))
			}

			if isIpv6 {
				// support for ipv6
				if ip_layer3_checksum_kernel_ts.Checksum != uint16(utils.DEFAULT_IPV6_CHECKSUM_MAP) {
					return errors.New("Error in Ipv6 header checksum verification ipv6 has no default checksum")
				}
			}

			// for AF_XDP kernel inject in device driver TX queue no need for guard map again and timing attack check as required in AF_PACKET
			if tc.IsEgressXdpSupport {
				if err := dnsMapRedirectMap.Delete(&dns_packet_id); err != nil {
					if !errors.Is(err, ebpf.ErrKeyNotExist) {
						utils.Log("Link has XDP support Error delete the Key ", dns_packet_id)
					}
				}
			} else {
				// will again pass through kernel AF_PACKET via kernel TC
				timeVal := events.DPIRedirectionTimestampVerify{
					Kernel_timets:           ip_layer3_checksum_kernel_ts.Kernel_timets,
					UserSpace_Egress_Loaded: 1,
				}

				if err := dnsMapRedirectVerify.Put(timeVal.Kernel_timets, timeVal.UserSpace_Egress_Loaded); err != nil {
					utils.Log("Error updating the timestamp kernel values for egress traffic")
					return err
				}
			}
		}
		return nil
	}

	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)

		var dns_packet_id uint16 = uint16(dns.ID)
		var ip_layer3_checksum_kernel_ts events.DPIRedirectionKernelMap // granualar timining control over the redirection from kernel

		if !isPhysicalNetDevSniff {
			if err := processVeifyKernelDnsTS(dns_packet_id, &ip_layer3_checksum_kernel_ts); err != nil {
				utils.Log(fmt.Sprintf("Error verify the UDP packet time from kernel %+v", err))
			}
		}

		if isIpv4 && isUdp {
			tc.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum,
				handler, true, isIpv4, isUdp, tc.TcCollection, &utils.MaliciousKernelTaskCommExportedProcInfo{
					ProcessId: ip_layer3_checksum_kernel_ts.ProcId,
					ThreadId:  ip_layer3_checksum_kernel_ts.ThreadId,
				}, isPhysicalNetDevSniff)
			// ipv4 and udp
		}
		if !isIpv4 && isUdp {
			// ipv6 and udp
			tc.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum,
				handler, true, isIpv4, isUdp, tc.TcCollection, &utils.MaliciousKernelTaskCommExportedProcInfo{
					ProcessId: ip_layer3_checksum_kernel_ts.ProcId,
					ThreadId:  ip_layer3_checksum_kernel_ts.ThreadId,
				}, isPhysicalNetDevSniff)
		}
	}

	if tcpCheck && isPhysicalNetDevSniff {
		dns := &layers.DNS{}

		err := dns.DecodeFromBytes(dnsTcpPayload, gopacket.NilDecodeFeedback)
		if err != nil {
			utils.Log("Error decoding the dns packet over the tcp stream", err)
			return err
		}

		var dns_packet_id uint16 = uint16(dns.ID)
		var ip_layer3_checksum_kernel_ts events.DPIRedirectionKernelMap // granualar timining control over the redirection from kernel

		if err := processVeifyKernelDnsTS(dns_packet_id, &ip_layer3_checksum_kernel_ts); err != nil {
			utils.Log(fmt.Sprintf("Error processing the dns packet over tcp stream %+v", err))
		}

		if isIpv4 && !isUdp {
			// ipv4 and tcp
			fmt.Println("called here for redirect over tcp")
			tc.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum,
				handler, true, isIpv4, isUdp, tc.TcCollection, &utils.MaliciousKernelTaskCommExportedProcInfo{
					ProcessId: ip_layer3_checksum_kernel_ts.ProcId,
					ThreadId:  ip_layer3_checksum_kernel_ts.ThreadId,
				}, isPhysicalNetDevSniff) // physical netdev sniff resembles passive and not aggressive analysis and DPI
		}
		if !isIpv4 && !isUdp {
			// ipv6 and tcp
			tc.DnsPacketGen.EvaluateGeneratePacket(eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum,
				handler, true, isIpv4, isUdp, tc.TcCollection, &utils.MaliciousKernelTaskCommExportedProcInfo{
					ProcessId: ip_layer3_checksum_kernel_ts.ProcId,
					ThreadId:  ip_layer3_checksum_kernel_ts.ThreadId,
				}, isPhysicalNetDevSniff) // physical netdev sniff resembles passive and not aggressive analysis and DPI
		}
	}

	return nil
}

func (tc *TCHandler) ProcessPcapFilterHandler(ctx context.Context, linkInterface netlink.Link, ifaceHandler *netinet.NetIface,
	errorChannel chan<- error) error {

	if err := ctx.Err(); err != nil {
		return err
	}

	cap, err := pcap.OpenLive(netinet.NETNS_NETLINK_BRIDGE_DPI, int32(linkInterface.Attrs().MTU), true, pcap.BlockForever)
	if err != nil {
		fmt.Println("error opening packet capture over hz,te interface from kernel")
		errorChannel <- err
	}
	defer cap.Close()

	utils.Log("Generated Egress Packet Listener to parse DNS packets from kernel over the UDP Layer DNS protocol from Node agent owned veth bridge driver")
	if err := cap.SetBPFFilter("udp dst port 53"); err != nil {
		utils.Logger.Fatalf("Error setting BPF filter: %v", err)
	}
	packets := gopacket.NewPacketSource(cap, cap.LinkType())
	for packet := range packets.Packets() {
		go tc.ProcessEachPacket(ctx, packet, ifaceHandler, cap, false) // snice processed over bridge
	}
	return nil
}

func (tc *TCHandler) ProcessPcapFilterHandlerTcpPhysicalNetDev(ctx context.Context, link netlink.Link, errorChannel chan error) {

	utils.Log("Generated Egress Packet Listener to parse DNS packets from kernel over the TCP Layer DNS protocol over ysical netdev")
	// cap, err := pcap.OpenLive(netinet.NETNS_NETLINK_BRIDGE_DPI, int32(linkInterface.Attrs().MTU), true, pcap.BlockForever)

	cap, err := pcap.OpenLive(link.Attrs().Name, int32(link.Attrs().MTU), true, pcap.BlockForever)
	if err != nil {
		fmt.Println("error opening packet capture over hz,te interface from kernel")
		errorChannel <- err
	}
	defer cap.Close()

	if err := cap.SetBPFFilter("udp dst port 53"); err != nil {
		utils.Logger.Fatalf("Error setting BPF filter: %v", err)
	}

	for pack := range gopacket.NewPacketSource(cap, cap.LinkType()).Packets() {
		go tc.ProcessEachPacket(ctx, pack, nil, cap, true)
	}
}

func (tc *TCHandler) ProcessSniffDPIPacketCapture(ctx context.Context, ifaceHandler *netinet.NetIface, prog *ebpf.Program) error {
	utils.Log("Loading the Egress Packet Capture over Custom Linux iface in network namespace")

	errorChannel := make(chan error, len(ifaceHandler.PhysicalLinks))
	tcpSniffErroChannel := make(chan error, len(ifaceHandler.PhysicalLinks))

	if len(ifaceHandler.PhysicalLinks) > 1 && tc.config.GetAgentConfig().EnhancedFeatures.Dns.EnabledPassiveEnhancedTCPDPI {
		utils.Log("Processing of multiple Physical links")

		for iface := 0; iface < len(ifaceHandler.PhysicalLinks); iface++ {
			go tc.ProcessPcapFilterHandlerTcpPhysicalNetDev(ctx, ifaceHandler.PhysicalLinks[iface], tcpSniffErroChannel)
		}
	}

	tc.ProcessPcapFilterHandler(ctx, ifaceHandler.PhysicalLinks[0], ifaceHandler, errorChannel)

	go func() {
		for {
			select {
			case paylaod, ok := <-errorChannel:
				{
					if !ok {
						return
					}
					fmt.Println(paylaod.Error())
				}
			default:
				time.Sleep(time.Second * 1)
			}
		}
	}()
	return nil
}

func (tc *TCHandler) DetachTCLinkedTracepointHookHandlers() error {
	if tc.TcTracepointHandlers == nil {
		return nil
	}

	return tc.TcTracepointHandlers.RemoveTracepoints()
}

func (tc *TCHandler) DetachHandler(ctx *context.Context) error {
	// used for removal of tc qdisc and all nested filters to parent qdisc class/ classless filter form all the host interfacee
	for _, link := range tc.Interfaces.PhysicalLinks {
		err := netlink.QdiscDel(&netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
			},
		})
		if err != nil {
			utils.Log("No Matching clsact desc found to delete")
			return err
		}
	}
	if utils.VerifyKernelEgressTCClsactTaskCommSuppert() {
		if err := tc.DetachTCLinkedTracepointHookHandlers(); err != nil {
			return err
		}
	}
	for _, pinMaps := range mapsToPinSharedProcKillMap {
		if tc.TcCollection != nil {
			if _, fd := tc.TcCollection.Maps[pinMaps]; fd {
				if tc.TcCollection.Maps[pinMaps].IsPinned() {
					if err := tc.TcCollection.Maps[pinMaps].Unpin(); err != nil {
						return err
					}
					tc.TcCollection.Maps[pinMaps].Close()
				}
			}
		}
	}
	return nil
}
