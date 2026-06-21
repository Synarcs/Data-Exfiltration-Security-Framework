/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package tc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"syscall"
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
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils/agenterr"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type (
	TCHandler struct {
		Interfaces      *netinet.NetIface
		Prog            *ebpf.Program    // ebpf program for tc with clsact class BPF_PROG_TYPE_CLS_ACT
		TcCollection    *ebpf.Collection // ebpf tc program collection order spec
		DnsPacketGen    *model.DnsPacketGen
		OnnxLoadedModel *model.OnnxModel

		TcTunnelNonStandardPortScan     *TCCloneTunnel              // sniffer routine for processing clone redirect traffic to precess exfiltrated traffic over non stanard ports for UDP / TCP transport
		GlobalErrorKernelHandlerChannel chan<- *agenterr.AgentError // handles all control channel created by main to kill any kernel code if found runtime panics

		IsEgressXdpSupport   bool
		TcTracepointHandlers *tracepoint.ExfilSecTreacePoint // store all the tracepoint attached and related to tc handlers

		Hash *crypto.Hash // skb agent crypto hash for agent integrity of skb over each redirect

		// the node agent consumer will ensure to send malicious ip address over this channel for node agent to inject them in kernel
		GlobalMalC2L3addressChannelIpv4 chan net.IP
		GlobalMalC2L3addressChannelIpv6 chan net.IP

		TaskCommTCEgressKernelSupport bool
		config                        conf.AgentConfig

		CryptoAgentLSMHandler *crypto.CryptoBpfLsm

		HasDiffPriorityQdiscFilter bool // default CNI is running qdisc filter for k8s node to ndoe communication, must disable XDP for egress send and rely on AF_PACKET for TC and eBPF filter to run
		TCXEgressLinks             []link.Link
	}

	// provide all input required to inject kernel tc qdisc eBPF programs in kernel
	KernelTcInjectConfig struct {
		Iface                           *netinet.NetIface
		OnnxModel                       *model.OnnxModel
		StreamClient                    *stream.StreamProducer
		GlobalErrorKernelHandlerChannel chan<- *agenterr.AgentError
		AgentHash                       *crypto.Hash
		AgentConfig                     conf.AgentConfig
		CryptoAgentLSMHandler           *crypto.CryptoBpfLsm
	}
)

// atomic insert to initi DPI in kernel
var (
	atomic_random_port_tunnel_overlay_agent_analysis sync.Once
	atomic_standard_port_passive_egress_dpi          sync.Once
	atomic_process_scheduler_tracepoints             sync.Once
	atomic_physical_netdev_ingress_sniff             sync.Once
)

var mapsToPinSharedProcKillMap []string

var (
	errAttachedQdiscHigherPrio = errors.New("error: the eBPF Exfil security framework cannot be attached with existing qdisc attached and having a TC egress filter with lowest priority, configure the filter to run with highest priority closest to default qdisc")
)

var KerneleBPFMapMonitorPollChannel map[string]chan string = make(map[string]chan string)

// a builder facotry for the tc load and process all tc egress traffic over the different filter chain which node agent is running
func NewTcEgressFactory(config *KernelTcInjectConfig) (*TCHandler, error) {
	// uses the kernel AF_PACKET or AF_XDP sockets to get fd / tx umem rings for af_xdp inside kernel
	dnsPacketGen, err := model.NewDnsPacketResendUtils(&model.DnsPacketGenConfig{
		Iface:        config.Iface,
		OnnxModel:    config.OnnxModel,
		StreamClient: config.StreamClient,
	})

	if err != nil {
		return nil, err
	}

	tcHandler := &TCHandler{
		Interfaces:                      config.Iface,
		DnsPacketGen:                    dnsPacketGen,
		OnnxLoadedModel:                 config.OnnxModel,
		GlobalErrorKernelHandlerChannel: config.GlobalErrorKernelHandlerChannel,
		Hash:                            config.AgentHash,
		config:                          config.AgentConfig,
		CryptoAgentLSMHandler:           config.CryptoAgentLSMHandler,
		TaskCommTCEgressKernelSupport:   utils.VerifyKernelEgressTCClsactTaskCommSuppert(),
	}
	if dnsPacketGen.XdpSocketSendFd != nil {
		tcHandler.IsEgressXdpSupport = true
	}

	InitPinMapHandlerNames(config.AgentConfig)
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
		events.EXFIL_TC_BRIDGE_CONFIG_MAP,
		events.EXFILL_SECURITY_KERNEL_CONFIG_MAP,
		events.EXFIL_SECURITY_ERROR_PIPE_AGENT,
	}

	if config.GetL3FiltersConfig().EnabledL3v4Filtering {
		mapsToPinSharedProcKillMap = append(mapsToPinSharedProcKillMap, events.EXFIL_SECURITY_EGRESS_L3_IPV4_DYNAMIC_NETPOOL_C2_FILTER)
	}

	if config.GetL3FiltersConfig().EnabledL3v6Filtering {
		mapsToPinSharedProcKillMap = append(mapsToPinSharedProcKillMap, events.EXFIL_SECURITY_EGRESS_L3_IPV6_DYNAMIC_NETPOOL_C2_FILTER)
	}
}

func PacketTcKernelDPICountMaps() []string {
	// the agent holds a global control channel for polling drop kernel malicious events to emitted to the kafka controller with respective channel for each map polling from kernel, compared plain timer based busy polling
	// add the maps for deep kernel monitoring as required
	return []string{
		events.EXFILL_SECURITY_KERNEL_REDIRECT_COUNT_MAP,
		events.EXFILL_SECURITY_EGRESS_REDIRECT_KERNEL_DROP_COUNT_MAP,
	}
}

// poll the malicious event  prevented  all inside kernel without endpoint agent intervention
func (tc *TCHandler) PollMaliciousControllerAwareC2Address(ctx context.Context, errorChannel <-chan error) {
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

// exfil rate limiter over egress TC on clsact qdisc
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

// Attach the kernel TC eBPF program over egress physical link
func (tc *TCHandler) AttachTCXHandler(ctx context.Context, prog *ebpf.Program) error {
	for _, netlink := range tc.Interfaces.PhysicalLinks {
		// the DNS security programs must have highest priority to be executed first over cls_bpf egress filters list  attached to netdev
		ln, err := link.AttachTCX(link.TCXOptions{
			Interface: netlink.Attrs().Index,
			Program:   prog,
			Attach:    ebpf.AttachTCXEgress,
			Anchor:    link.Head(),
		})
		if err != nil {
			goto clean
		}
		tc.TCXEgressLinks = append(tc.TCXEgressLinks, ln)
	}
	return nil
clean:
	for _, ln := range tc.TCXEgressLinks {
		if err := ln.Close(); err != nil {
			utils.Log(err.Error())
			continue
		}
	}
	return nil
}

// Used for monitoring system kernel performance time with all kernel injected eBPF programs
func (tc *TCHandler) PollKernelDPIPerformanceTimeBuffer(ctx context.Context) error {
	if !utils.ENABLE_KERNEL_DPI_IMPACT_MEASURE_TIME {
		return nil
	}
	dpiKernelTimeMap := tc.TcCollection.Maps[events.EXFIL_SECURITY_EGRESSS_DPI_TIME]
	if dpiKernelTimeMap == nil {
		return fmt.Errorf("please ensure in kernel eBPF program DPI benchmark is enabled")
	}
	buffer, err := ringbuf.NewReader(dpiKernelTimeMap)
	if err != nil {
		return err
	}

	for {
		record, err := buffer.Read()
		if err != nil {
			return err
		}

		var payload events.DPIPerformanceTime
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &payload); err != nil {
			utils.Logger.Error("Error reading the ring buffer")
			return err
		}

	}
}

// Relies on legacy TC via cls_bpf priority over legacy TC subsystem for bpf filter attachment
func (tc *TCHandler) AttachTCHandler(ctx context.Context, prog *ebpf.Program) error {
	if utils.VerifyTcxSupportEgressLink() {
		// TODO: Implement injection support over TCX vs prio based legacy TC cls_bpf filters
		return tc.AttachTCXHandler(ctx, prog)
	}

	utils.Log("the loopback egress links are ", tc.Interfaces.GetTCEgressAttachLinks())
	for _, link := range tc.Interfaces.GetTCEgressAttachLinks() {
		utils.Log("Attaching TC qdisc to the interface ", link.Attrs().Name)

		/*
		   For CNI processing and adding filter they should have have highe priority post the DNS security egress security qdisc for pod  to pod communication  across nodes
		*/
		qdiscs, err := netlink.QdiscList(link)
		if err != nil {
			return err
		}

		hasClsactQdisc := false
		var existingQdiscFilter *netlink.Clsact
		for _, qdisc := range qdiscs {
			if cls, ok := qdisc.(*netlink.Clsact); ok && cls.Parent == netlink.HANDLE_CLSACT {
				hasClsactQdisc = true
				existingQdiscFilter = cls
			}
		}

		if hasClsactQdisc {
			// increase the priory for the filter to be at leaf,
			filters, err := netlink.FilterList(link, existingQdiscFilter.Parent)
			if err != nil {
				goto ATTACH_SECURITY_FILTER
			}
			var currPrio uint16 = (1 << 16) - 1
			var currHandle uint32
			for _, filter := range filters {
				if fl, ok := filter.(*netlink.BpfFilter); ok {
					if fl.Priority < currPrio {
						currPrio = fl.Priority
						currHandle = fl.Handle
						break
					}
				}
			}
			if currPrio == 1 && currHandle != netlink.MakeHandle(0xffff, 0) {
				// ensure the filter is removed and reattached with higher priority to ensure
				utils.Log(errAttachedQdiscHigherPrio.Error())
				return fmt.Errorf("the eBPF DNS exfiltration framework must have lower prio pre execution of any CNI attached tc hooks")
			} else if currPrio == 1 && currHandle == netlink.MakeHandle(0xffff, 0) {
				goto ATTACH_SECURITY_FILTER
			}
			tc.HasDiffPriorityQdiscFilter = true
		}

	ATTACH_SECURITY_FILTER:
		qdisc_clsact := &netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(0xffff, 0),
			},
		}
		if err := netlink.QdiscReplace(qdisc_clsact); err != nil {
			return err
		}

		if !hasClsactQdisc {
			utils.Log("Attaching CLSACT qdisc over link ", link.Attrs().Name, "in egress direction with parent", netlink.HANDLE_MIN_EGRESS)
		}
		filter := netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
				Protocol:  unix.ETH_P_ALL,
				Priority:  utils.TC_CLSACT_PARENT_QDISC_PRIO,
			},
			Fd:           prog.FD(),
			Name:         prog.String(),
			DirectAction: true,
		}

		if err := netlink.FilterReplace(&filter); err != nil {
			return err
		}

		// attach and start bpf timers in kernel as the program is injected in the kernel

		enhancedFeatures := tc.config.GetAddonFeaturesConfig()
		if enhancedFeatures.Dns.EnabledTbRlimit {
			if err := tc.InitDnsRateLimiter(ctx); err != nil {
				utils.Log("Error initializing the dns rate limiter", err.Error())
				return err
			}
		}

	}
	return nil
}

/*
Read through the monitoring eBPF kernel maps tracking malicious activity in kernel
Emit threat events and other prometheus metrics accordingly
*/
func (tc *TCHandler) ReadMonitoringMaps(ctx context.Context, errorEventChannel chan error) {
	var KernelPacketRedirectCount uint16 = 0

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	geteBPFMapFromCollection := func(mpName string) (*ebpf.Map, error) {
		if mp, fd := tc.TcCollection.Maps[mpName]; !fd {
			return nil, fmt.Errorf("the required map not found %s", mpName)
		} else {
			return mp, nil
		}
	}

	pollMapKernelCountMetrics := func(mapName string) {
		for range KerneleBPFMapMonitorPollChannel[mapName] {
			var CurrentPacketCountKernel uint32 = 0
			if mp, err := geteBPFMapFromCollection(mapName); err != nil {
				errorEventChannel <- err
			} else {
				if err := mp.Lookup(KernelPacketRedirectCount, &CurrentPacketCountKernel); err != nil {
					if !errors.Is(err, ebpf.ErrKeyNotExist) {
						utils.Log("Error polling metric for redirected kernel count", err)
						errorEventChannel <- err
					}
				}
			}
			switch mapName {
			case events.EXFILL_SECURITY_KERNEL_REDIRECT_COUNT_MAP:
				if err := events.ExportPromeEbpfExporterEvents[events.PacketDPIRedirectionCountEvent](events.PacketDPIRedirectionCountEvent{
					KernelRedirectPacketCount: CurrentPacketCountKernel,
					EvenTime:                  time.Now().Format(time.RFC3339),
				}); err != nil {
					if !utils.DEBUG {
						utils.Log("Error Streaming the prometheus metrics", err)
					}
				}
			case events.EXFILL_SECURITY_EGRESS_REDIRECT_KERNEL_DROP_COUNT_MAP:
				if err := events.ExportPromeEbpfExporterEvents[events.PacketDPIKernelDropCountEvent](events.PacketDPIKernelDropCountEvent{
					KernelDropPacketCount: CurrentPacketCountKernel,
					EvenTime:              time.Now().Format(time.RFC3339),
				}); err != nil {
					if !utils.DEBUG {
						utils.Log("Error Streaming the prometheus metrics", err)
					}
				}
			}
		}
	}

	for _, mapName := range PacketTcKernelDPICountMaps() {
		go pollMapKernelCountMetrics(mapName)
	}

	// block the poller until the core agent thread dont cancel polling from kernel and all kernel programs are ejected
	<-ctx.Done()
}

func (tc *TCHandler) ExportKernelPacketProcessCountEvents() {

	// only poll for the ring buffers and kernel maps over non-encap traffic from kernel, once gopacket receive packet from the tap rx queue netdev
	for _, mp := range PacketTcKernelDPICountMaps() {
		if fd := tc.TcCollection.Maps[mp]; fd != nil {
			KerneleBPFMapMonitorPollChannel[mp] <- time.Now().String()
		}
	}
}

func (tc *TCHandler) TcHandlerEbfpProg(ctx context.Context, iface *netinet.NetIface, injectChan map[string]chan bool) {
	utils.Log("Attaching a kernel Handler for the TC CLS_Act Qdisc")

	handler, err := utils.ReadEbpfFromSpec(ctx, utils.TC_EGRESS_ROOT_NETIFACE_INT)

	if err != nil {
		tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(err, "TC_WIRE", fmt.Sprintf("Error injecting egress eBPF TC program %s", utils.TC_EGRESS_ROOT_NETIFACE_INT))
		return
	}

	rawEbpfProgBytes, err := utils.ReadEbpfProgRaw(utils.TC_EGRESS_ROOT_NETIFACE_INT)

	if err != nil {
		tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(err, "TC_WIRE", fmt.Sprintf("Error reading the egress eBPF TC program raw %s", utils.TC_EGRESS_ROOT_NETIFACE_INT))
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
		tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(err, "TC_WIRE", fmt.Sprintf("Error Loading the eBPF program, map pinned path %s", utils.PINPATH))
		return
	}

	prog := spec.Programs[utils.TC_CONTROL_PROG]
	if prog == nil {
		tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(err, "TC_WIRE", fmt.Sprintf("no Required TC Hook found for DNS egress %s", utils.TC_CONTROL_PROG))
		return
	}

	info, err := prog.Info()
	if err != nil {
		tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(err, "TC_WIRE", fmt.Sprintf("error getting eBPF program Info: %s", utils.TC_CONTROL_PROG))
		return
	}

	if utils.DEBUG {
		if err := tc.CryptoAgentLSMHandler.InjectLSMProgsPostSignatureGenerate(rawEbpfProgBytes, info, nil); err != nil {
			tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(err, "TC_WIRE_EBPF_CRYPTO_SIG", fmt.Sprintf("error generating crypto signature from the raw eBPF program %s", utils.TC_EGRESS_ROOT_NETIFACE_INT))
			return
		}
	}

	tc.Prog = prog
	tc.TcCollection = spec

	if err := tc.AttachTCHandler(ctx, prog); err != nil {
		utils.Log("Error attaching the clsact bpf qdisc for netdev")
		tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(err, "TC_WIRE", fmt.Sprintf("Error attaching egress TC program %s", utils.TC_EGRESS_ROOT_NETIFACE_INT))
		return
	}

	if len(iface.BridgeLinks) < 2 {

		utils.Logger.Fatalf("The Node agent cannot be booted unless all the DPI linux veth bridges are added using netlink before exiting ....")
		// TODO: Add a process global error channel for detach if any of the tc panic
		tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(
			nil, "TC_WIRE", fmt.Sprintf("The required bridge used for deep security scans not created, please make sure proper veth bridges exist and required linux ns"),
		)
		return
	}

	// check all the egress bridge links are on the node
	agentDPIbridgeLinks := 0
	for _, lnk := range iface.BridgeLinks {
		if lnk.Attrs().Name == netinet.NETNS_NETLINK_BRIDGE_DPI || lnk.Attrs().Name == netinet.NETNS_TUNNEL_TRAFFIC_NETLINK_BRIDGE_DPI {
			agentDPIbridgeLinks++
		}
	}
	if agentDPIbridgeLinks != 2 {
		tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(
			nil, "TC_WIRE", fmt.Sprintf("the required bridge used for deep security scans not created, please make sure proper veth bridges exist and required linux ns"),
		)
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
			}

			if tc.config.GetAgentAggressiveDpiMode() {
				kernelTCConfig.IsAgressiveSec = 1 // agressive DPI
			} else {
				kernelTCConfig.IsAgressiveSec = 0 // passive DPI
			}

			if !utils.DEBUG {
				if kernelTCConfig.IsAgressiveSec == 1 {
					utils.Log(fmt.Sprintf("For Netdev :: %s, Exfiltration security runs in aggresive mode to stop even a single exfiltrated or C2 command respond pass via DNS", link.Attrs().Name))
				}
			}

			err := configMap.Put(uint32(link.Attrs().Index), kernelTCConfig)
			if err != nil {
				tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(err, "TC_WIRE", fmt.Sprintf("Error inject egress DPI config into eBPF mapss"))
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
				utils.Log("error loading the dns limits in kernel from userspace agent, kernel default limits apply for feature ", limit)
			}
		}

		if utils.DEBUG {
			utils.Log("The Node Agent loaded the dns limits in Kernel successfully")
		}
	}

	errMapPollChannel := make(chan error)

	if fd := tc.TcCollection.Maps[events.EXFIL_SECURITY_EGRESS_VXLAN_ENCAP_DROP]; fd != nil {
		go tc.PollVxlanRingBuffer(ctx, tc.TcCollection.Maps[events.EXFIL_SECURITY_EGRESS_VXLAN_ENCAP_DROP])
	}

	// init the kernel polling channels to poll packet metrics
	for _, mp := range PacketTcKernelDPICountMaps() {
		KerneleBPFMapMonitorPollChannel[mp] = make(chan string)
	}

	go tc.ReadMonitoringMaps(ctx, errMapPollChannel)
	if utils.ENABLE_KERNEL_DPI_IMPACT_MEASURE_TIME {
		go tc.PollKernelDPIPerformanceTimeBuffer(ctx)
	}

	go func() {
		for {
			select {
			case pollError, ok := <-errMapPollChannel:
				if !ok {
					utils.Logger.Fatal("Channel closed for polling kernel events")
				}
				utils.Log("Error polling kernel events", pollError)
				tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(err, "TC_WIRE_RINGBUFF", fmt.Sprintf("Error polling metric for egress TC program"))
				return
			default:
				time.Sleep(time.Second)
			}
		}
	}()

	// atomic ref  holder to denote userspace loaded the kernel tc program post monitor of tunnel traffic maps, considering both tunnel and standard DNS port exfiltration preventeed by single TC prog in kernel
	atomic_random_port_tunnel_overlay_agent_analysis.Do(func() {
		tc_tunnel := tc.InitTCTunnelExfilPrevention(ctx, !tc.config.GetAgentConfig().Agent.AgentModeAggressive)
		tc.TcTunnelNonStandardPortScan = tc_tunnel
		tc.StartTunnelExfilPacketDPIoverBrNetdev(ctx)
	})

}

/*
Start preventing DNS exfiltration over random UDP port with kernel TC aggresively scanning SKB L7 payload for potential SKB packets with DNS exfiltrated data
*/
func (tc *TCHandler) InitTCTunnelExfilPrevention(ctx context.Context, isPassiveStandardDNSPortUDPTransfer bool) *TCCloneTunnel {
	return NewTcTunnelFactory(
		&TCCloneTunnelConfig{
			PhysicalTcInterfaceeBPFProgCollection: tc.TcCollection,
			Iface:                                 tc.Interfaces,
			GlobalErrorChannel:                    tc.GlobalErrorKernelHandlerChannel,
			StreamClient:                          tc.DnsPacketGen.StreamClient,
			Onnx:                                  tc.OnnxLoadedModel,
			isPassiveStandardDNSPortUDPTransfer:   isPassiveStandardDNSPortUDPTransfer,
			InferenceServerSock:                   tc.OnnxLoadedModel.InferenceServerSock,
		})
}

// Start polling on the ring buffers in kernel for tunnel overlay exfiltration attempts
// meant for ingress traffic to analyze ingress C2 response patterns
func (tc *TCHandler) StartTunnelExfilPacketDPIoverBrNetdev(ctx context.Context) {
	// spawn go routine to handle ring buffer polling for nonstandard / standard port for passive DPI exfiltrated traffic over the ports
	// let this be global map err poller from kernel for mallicious port obfuscation tunnel events as well as kernel DPI runtime errors otherwise exported via kernel pipe
	for _, maps := range tc.TcCollection.Maps {
		if strings.Contains(maps.String(), events.EXFIL_SECURITY_EGREES_REDIRECT_RING_BUFF_NON_STANDARD_PORT) || strings.Contains(maps.String(), events.EXFIL_SECURITY_ERROR_PIPE_AGENT) {
			go tc.TcTunnelNonStandardPortScan.PollRingBuffer(ctx, maps)
		}
	}

	go tc.TcTunnelNonStandardPortScan.SniffPacketsForTunnelDPI(ctx) // start the packet sniffing for non standard ports bpf_redirect_clone from kernel space

	atomic_process_scheduler_tracepoints.Do(func() {
		if utils.VerifyKernelEgressTCClsactTaskCommSuppert() {
			tracepoint_sched := tracepoint.GenerateTracePointHandlers()
			tracepoint_sched.AttachTracePointHandlers(ctx, tc.Interfaces)
		}
	})

	atomic_physical_netdev_ingress_sniff.Do(func() {
		tc.ProcessSniffDPIIngressDNSCapture(ctx, tc.Interfaces, nil)
	})
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

/*
Node agent helper to process as a passive DPI, kernel wont live redirect whole skb, rather clone redirect via tap netdev tx handlers, for the rx handler to read it over the virtual netdev for DPI over master bridge
*/
func (tc *TCHandler) ProcessEachPacketPassiveDpi(ctx context.Context) {
	if utils.DEBUG {
		utils.Log("the agent in running in passive mode andall the kernel program are operational in passive process threat hunt strategy for C2 implants")
	}
}

/*
Aggressive DPI for processing L3 UDP packet over DNS live redirected from kernel
*/
func (tc *TCHandler) KernelPacketTSVerifcation(ctx context.Context, dns_packet_id uint16, isIpv6 bool,
	ip_layer3_checksum_kernel_ts *events.DPIRedirectionKernelMap, dnsMapRedirectMap *ebpf.Map, dnsMapRedirectVerify *ebpf.Map) error {

	err := dnsMapRedirectMap.Lookup(&dns_packet_id, ip_layer3_checksum_kernel_ts)
	if err != nil {
		utils.Log("Required redirected packet id is not found in the map or unkown error", err, dnsMapRedirectMap)
	} else {
		if utils.DEBUG {
			utils.Log("found the required key from BPF Hash fd ", ip_layer3_checksum_kernel_ts.Checksum, time.Unix(0, int64(ip_layer3_checksum_kernel_ts.KernelTimets)))
		}

		if isIpv6 {
			// support for ipv6
			if ip_layer3_checksum_kernel_ts.Checksum != uint16(utils.DEFAULT_IPV6_CHECKSUM_MAP) {
				return errors.New("error in Ipv6 header checksum verification ipv6 has no default checksum")
			}
		}

		// for AF_XDP kernel inject in device driver TX queue no need for guard map again and timing attack check as required in AF_PACKET
		if tc.IsEgressXdpSupport {
			if err := dnsMapRedirectMap.Delete(&dns_packet_id); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					utils.Log("Link has XDP support Error delete the Key ", dns_packet_id)
				}
				return err
			}
		} else {
			// will again pass through kernel AF_PACKET via kernel TC
			timeVal := events.DPIRedirectionTimestampVerify{
				Kernel_timets:           ip_layer3_checksum_kernel_ts.KernelTimets,
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

func (tc *TCHandler) ProcessEachPacket(ctx context.Context, packet gopacket.Packet,
	handler *pcap.Handle, isPhysicalNetDevSniff bool, physicalSniffNetdev *netlink.Link) {

	eth := packet.Layer(layers.LayerTypeEthernet)
	var isIpv4 bool
	var isUdp bool
	if eth == nil {
		return
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
			utils.Log("the UDP Packet is malformed")
			return
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
			utils.Log("TCP payload too short for dns parsing", len(payload))
			return
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
			return
		}

		if ipv4Address == utils.GetIpv4AddressUserSpaceDpIString(2) {
			// packet is malicious found from kernel and link redirected and no further DPI should be done on user space
			go model.HandleKernelDroppedPacket[progs.Protocol](
				ctx,
				dnsLayer, isIpv4, isUdp, events.DNS, tc.Interfaces,
			)
		}

	} else {
		ipv6Address := ipv6Packet.DstIP.To16().String()

		if ipv6Address == utils.MALICIOUS_NETNS_IPV6 {
			go model.HandleKernelDroppedPacket[progs.Protocol](
				ctx,
				dnsLayer, isIpv4, isUdp, events.DNS, tc.Interfaces,
			)
		}
	}

	isIpv6 := !isIpv4

	if !tc.config.GetAgentConfig().Agent.AgentModeAggressive {
		tc.ProcessEachPacketPassiveDpi(ctx)
		return
	}
	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)

		var dns_packet_id uint16 = uint16(dns.ID)
		var ip_layer3_checksum_kernel_ts events.DPIRedirectionKernelMap // granualar timining control over the redirection from kernel

		if !isPhysicalNetDevSniff {
			if err := tc.KernelPacketTSVerifcation(ctx, dns_packet_id, isIpv6, &ip_layer3_checksum_kernel_ts, dnsMapRedirectMap, dnsMapRedirectVerify); err != nil {
				utils.Log(fmt.Sprintf("Error verify the UDP packet time from kernel %+v", err))
			}
		}

		var egressLink netlink.Link
		if len(tc.Interfaces.PhysicalLinks) > 1 {
			// TODO: fix the broken ifindex emit from kernel for each packet extracked from (__sk_buff) running on attached tc filter at egress point
			link, err := tc.Interfaces.GetEgressLinkFromIfIndex(ip_layer3_checksum_kernel_ts.SkbIndex)
			if err != nil {
				tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(
					err, "TC_WIRE_PCAP", fmt.Sprintf("Error getting the pcap sniffer on interface %s ", (*physicalSniffNetdev).Attrs().Name),
				)
				return
			}
			egressLink = *link
		} else {
			egressLink = tc.Interfaces.PhysicalLinks[0]
		}

		if isIpv4 && isUdp {
			var agentDNSDefaultGwDnat bool = false
			isSameResolver, destIp := tc.Interfaces.UpstreamLinkoverAgentResolverIpv4(ip_layer3_checksum_kernel_ts.L3Address)
			if !isSameResolver {
				var currupstreamL3Ip = utils.BigEndianToIPv4(ip_layer3_checksum_kernel_ts.L3Address)
				if utils.DEBUG {
					utils.Log("the current upstream converted l3 address unmatched from kernel to agent dest resolver ::: ", currupstreamL3Ip)
				}
				agentDNSDefaultGwDnat = true
			}

			// TODO: fix code redudnacies into a common utils
			tc.DnsPacketGen.EvaluateGeneratePacket(ctx, eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum,
				handler, true, isIpv4, isUdp, tc.TcCollection, &utils.MaliciousKernelTaskCommExportedProcInfo{
					ProcessId: ip_layer3_checksum_kernel_ts.ProcId,
					ThreadId:  ip_layer3_checksum_kernel_ts.ThreadId,
				}, isPhysicalNetDevSniff, egressLink,
				tc.HasDiffPriorityQdiscFilter,
				// dnat custom upstream resolver config
				agentDNSDefaultGwDnat,
				destIp,
			)
			// ipv4 and udp
		}
		if !isIpv4 && isUdp {
			// ipv6 and udp
			tc.DnsPacketGen.EvaluateGeneratePacket(ctx, eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum,
				handler, true, isIpv4, isUdp, tc.TcCollection, &utils.MaliciousKernelTaskCommExportedProcInfo{
					ProcessId: ip_layer3_checksum_kernel_ts.ProcId,
					ThreadId:  ip_layer3_checksum_kernel_ts.ThreadId,
				}, isPhysicalNetDevSniff, egressLink,
				tc.HasDiffPriorityQdiscFilter,
				false, "")
		}
	}

	if tcpCheck && isPhysicalNetDevSniff {
		dns := &layers.DNS{}

		err := dns.DecodeFromBytes(dnsTcpPayload, gopacket.NilDecodeFeedback)
		if err != nil {
			utils.Log("Error decoding the dns packet over the tcp stream", err)
			return
		}

		var dns_packet_id uint16 = uint16(dns.ID)
		var ip_layer3_checksum_kernel_ts events.DPIRedirectionKernelMap // granualar timining control over the redirection from kernel

		if err := tc.KernelPacketTSVerifcation(ctx, dns_packet_id, isIpv6, &ip_layer3_checksum_kernel_ts,
			dnsMapRedirectMap, dnsMapRedirectVerify); err != nil {
			utils.Log(fmt.Sprintf("Error processing the dns packet over tcp stream %+v", err))
		}

		egressLink, err := tc.Interfaces.GetEgressLinkFromIfIndex(uint32((*physicalSniffNetdev).Attrs().Index))
		if err != nil {
			utils.Logger.Error(err.Error())
			tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(
				err, "TC_WIRE_PCAP", fmt.Sprintf("Error getting the pcap sniffer on interface %s ", (*physicalSniffNetdev).Attrs().Name),
			)
			return
		}

		if isIpv4 && !isUdp {
			// ipv4 and tcp
			tc.DnsPacketGen.EvaluateGeneratePacket(ctx, eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum,
				handler, true, isIpv4, isUdp, tc.TcCollection, &utils.MaliciousKernelTaskCommExportedProcInfo{
					ProcessId: ip_layer3_checksum_kernel_ts.ProcId,
					ThreadId:  ip_layer3_checksum_kernel_ts.ThreadId,
				}, isPhysicalNetDevSniff, *egressLink,
				tc.HasDiffPriorityQdiscFilter, false, "") // physical netdev sniff resembles passive and not aggressive analysis and DPI
		}
		if !isIpv4 && !isUdp {
			// ipv6 and tcp
			tc.DnsPacketGen.EvaluateGeneratePacket(ctx, eth, ipLayer, transportLayer, dnsLayer, ip_layer3_checksum_kernel_ts.Checksum,
				handler, true, isIpv4, isUdp, tc.TcCollection, &utils.MaliciousKernelTaskCommExportedProcInfo{
					ProcessId: ip_layer3_checksum_kernel_ts.ProcId,
					ThreadId:  ip_layer3_checksum_kernel_ts.ThreadId,
				}, isPhysicalNetDevSniff, *egressLink, tc.HasDiffPriorityQdiscFilter, false, "") // physical netdev sniff resembles passive and not aggressive analysis and DPI
		}
	}
}

// Does sniff over the host netdev to analyze C2 DNS response pattern
func (tc *TCHandler) ProcessPcapFilterHandler(ctx context.Context, linkInterface netlink.Link, ifaceHandler *netinet.NetIface,
	errorChannel chan<- error) {

	if err := ctx.Err(); err != nil {
		errorChannel <- err
		return
	}

	// cap, err := pcap.OpenLive(netinet.NETNS_NETLINK_BRIDGE_DPI, int32(linkInterface.Attrs().MTU), true, pcap.BlockForever)
	cap, err := tc.Interfaces.GetPcapHandleoverNetDevByName(netinet.NETNS_NETLINK_BRIDGE_DPI, int32(linkInterface.Attrs().MTU))

	if err != nil {
		fmt.Println("error opening packet capture over hz,te interface from kernel")
		errorChannel <- err
	}
	defer cap.Close()

	utils.Log("Generated Egress Packet Listener to parse DNS packets from kernel over the UDP Layer DNS protocol from Node agent owned veth bridge driver")
	if err := cap.SetDirection(pcap.DirectionIn); err != nil {
		utils.Logger.Fatalf("Error setting BPF direction filter for netdev: %v", err)
		errorChannel <- err
		return
	}

	if err := cap.SetBPFFilter("udp dst port 53"); err != nil {
		utils.Logger.Fatalf("Error setting BPF filter: %v", err)
		errorChannel <- err
		return
	}

	packets := gopacket.NewPacketSource(cap, cap.LinkType())
	for packet := range packets.Packets() {
		go tc.ExportKernelPacketProcessCountEvents()          // let the agent start polling for monitor the kernel exported packet count metrcis
		go tc.ProcessEachPacket(ctx, packet, cap, false, nil) // start deep packet userspace analysis over the packet
	}
}

func (tc *TCHandler) ProcessPcapFilterHandlerTcpPhysicalNetDev(ctx context.Context, link netlink.Link, errorChannel chan error) {

	utils.Log("Generated Egress Packet Listener to parse DNS packets from kernel over the TCP Layer DNS protocol over ysical netdev")
	// cap, err := pcap.OpenLive(netinet.NETNS_NETLINK_BRIDGE_DPI, int32(linkInterface.Attrs().MTU), true, pcap.BlockForever)

	cap, err := tc.Interfaces.GetPcapHandleoverNetDevByName(link.Attrs().Name, int32(link.Attrs().MTU))

	if err != nil {
		fmt.Println("error opening packet capture over hz,te interface from kernel")
		errorChannel <- err
	}
	defer cap.Close()

	if err := cap.SetDirection(pcap.DirectionIn); err != nil {
		utils.Logger.Fatalf("Error setting BPF direction filter for netdev: %v", err)
		errorChannel <- err
		return
	}

	if err := cap.SetBPFFilter("tcp dst port 53"); err != nil {
		utils.Logger.Fatalf("Error setting BPF filter: %v", err)
		errorChannel <- err
	}

	for pack := range gopacket.NewPacketSource(cap, cap.LinkType()).Packets() {
		go tc.ProcessEachPacket(ctx, pack, cap, true, &link)
	}
}

// does a UDP sniff on the host netdev, as well to analyze C2 response pattern for response
func (tc *TCHandler) ProcessSniffDPIIngressDNSCapture(ctx context.Context, ifaceHandler *netinet.NetIface, prog *ebpf.Program) error {
	utils.Log("Loading the Egress Packet Capture over Custom Linux iface in network namespace")

	errorChannel := make(chan error, len(ifaceHandler.PhysicalLinks))
	tcpSniffErroChannel := make(chan error, len(ifaceHandler.PhysicalLinks))

	if len(ifaceHandler.PhysicalLinks) > 1 && tc.config.GetAgentConfig().EnhancedFeatures.Dns.EnabledPassiveEgressEnhancedTCPDPI {
		utils.Log("Processing of multiple Physical links")

		for iface := 0; iface < len(ifaceHandler.PhysicalLinks); iface++ {
			go tc.ProcessPcapFilterHandlerTcpPhysicalNetDev(ctx, ifaceHandler.PhysicalLinks[iface], tcpSniffErroChannel)
		}
	}

	tc.ProcessPcapFilterHandler(ctx, ifaceHandler.PhysicalLinks[0], ifaceHandler, errorChannel)

	return nil
}

func (tc *TCHandler) DetachTCLinkedTracepointHookHandlers() error {
	if tc.TcTracepointHandlers == nil {
		return nil
	}

	return tc.TcTracepointHandlers.RemoveTracepoints()
}

/*
Close the open socket fd,  over kernel AF_PACKET raw / AF_XDP socket for egress tx queues
*/
func (tc *TCHandler) CloseSocketFd() {
	if tc.DnsPacketGen.XdpSocketSendFd != nil {
		utils.Log("Closing the AF_XDP Socket  for egress rescanned packed resend")
		if err := tc.DnsPacketGen.XdpSocketSendFd.Close(); err != nil {
			tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(
				err, "TC_WIRE_SOCK_CLOSE", fmt.Sprintf("Error closing the AF_XDP socket on physical wire "),
			)
		}
		return
	}

	if tc.DnsPacketGen.SocketSendFd != nil {
		utils.Log("Closing the AF_PACKET Socket for egress rescanned packed resend")
		if err := syscall.Close(*tc.DnsPacketGen.SocketSendFd); err != nil {
			tc.GlobalErrorKernelHandlerChannel <- agenterr.EmitNewError(
				err, "TC_WIRE_SOCK_CLOSE", fmt.Sprintf("Error closing the AF_PACKET socket on physical wire "),
			)
		}
	}
}

func (tc *TCHandler) DetachHandler(ctx *context.Context) error {
	// used for removal of tc qdisc and all nested filters to parent qdisc class/ classless filter form all the host interfacee
	defer tc.CloseSocketFd()

	if utils.VerifyTcxSupportEgressLink() {
		for _, link := range tc.TCXEgressLinks {
			if err := link.Close(); err != nil {
				return err
			}
		}
		return nil
	}

	if !tc.HasDiffPriorityQdiscFilter {
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
	} else {
		// remove filters with matching handle  only
		for _, link := range tc.Interfaces.PhysicalLinks {
			netlink.FilterDel(&netlink.BpfFilter{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: link.Attrs().Index,
					Parent:    netlink.HANDLE_MIN_EGRESS,
					Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
					Protocol:  unix.ETH_P_ALL,
					Priority:  utils.TC_CLSACT_PARENT_QDISC_PRIO,
				},
				Fd:           tc.Prog.FD(),
				Name:         tc.Prog.String(),
				DirectAction: true,
			})
		}
	}
	if utils.VerifyKernelEgressTCClsactTaskCommSuppert() {
		if err := tc.DetachTCLinkedTracepointHookHandlers(); err != nil {
			return err
		}
	}

	if err := utils.UnPinPinnedMaps(tc.TcCollection, mapsToPinSharedProcKillMap); err != nil {
		return err
	}

	defer tc.TcCollection.Close()

	return nil
}
