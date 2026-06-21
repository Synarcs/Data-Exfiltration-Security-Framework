/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package tc

// DPI over the clone redirect over tc from kernel done via the tc layer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/conf"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/progs"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/rpc/inference"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils/agenterr"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// the tc clone is a child handler which same eBPF tc kernel program enforce dns exfil security with only different of preventing exfiltration over random ports
type (
	TCCloneTunnel struct {
		IfaceHandler                          *netinet.NetIface
		GlobalKernelErrorChannel              chan<- *agenterr.AgentError
		PhysicalTcInterfaceeBPFProgCollection *ebpf.Collection
		StreamClient                          *stream.StreamProducer
		Onnx                                  *model.OnnxModel

		TaskCommTCEgressKernelSupport bool
		IngressTunnelSniffer          *xdp.IngressSniffHandler

		AgentOperationPassiveMode bool                               // passive DPI stop breaches over both random and default UDP port over DNS
		InferenceServerSock       *inference.DNSOnnxInferenceService // grpc socket l7 client connected to onnx inference server over UDS
	}

	TCCloneTunnelConfig struct {
		PhysicalTcInterfaceeBPFProgCollection *ebpf.Collection
		Iface                                 *netinet.NetIface
		GlobalErrorChannel                    chan<- *agenterr.AgentError
		StreamClient                          *stream.StreamProducer
		Onnx                                  *model.OnnxModel
		isPassiveStandardDNSPortUDPTransfer   bool
		InferenceServerSock                   *inference.DNSOnnxInferenceService
	}
)

// this is meant for stopping exfiltration over random ports
// the root kernel single tc handler is advacned to stop exfiltration over both standard and random UDP ports
func NewTcTunnelFactory(config *TCCloneTunnelConfig) *TCCloneTunnel {
	// sniff for random port traffic when detected to be malicious until other wise suspended and terminated

	tccloneTunnel := &TCCloneTunnel{
		IfaceHandler:                          config.Iface,
		GlobalKernelErrorChannel:              config.GlobalErrorChannel,
		PhysicalTcInterfaceeBPFProgCollection: config.PhysicalTcInterfaceeBPFProgCollection,
		StreamClient:                          config.StreamClient,
		Onnx:                                  config.Onnx,
		TaskCommTCEgressKernelSupport:         utils.VerifyKernelEgressTCClsactTaskCommSuppert(),
		AgentOperationPassiveMode:             config.isPassiveStandardDNSPortUDPTransfer,
		InferenceServerSock:                   config.InferenceServerSock,
	}

	if IsTunnelSniffForLargeMaliciousThresholdRequired() {
		tccloneTunnel.IngressTunnelSniffer = xdp.NewIngressSniffer(&xdp.IngressSnifferConfig{
			Iface:                           config.Iface,
			OnnxModel:                       config.Onnx,
			StreamClient:                    config.StreamClient,
			GlobalErrorKernelHandlerChannel: config.GlobalErrorChannel,
		})
	}
	return tccloneTunnel
}

func IsTunnelSniffForLargeMaliciousThresholdRequired() bool {
	return utils.EXFIL_PROCESS_CACHE_CLEAN_THRESHOLD > utils.EXFIL_PROCESS_CACHE_CLEAN_MALICIOUS_PORT_INGRESS_SNIF_THRESHOLD
}

var (
	// dont use spin lock user space write a map from userspace, and kernel always read it, and never write,
	kernelMaliciousTransferPortDelete  sync.Mutex = sync.Mutex{}
	kernelUpdateMaliciousReferenceLock sync.Mutex = sync.Mutex{}

	// map 3  (proc --> isMal (bool))
	updateMapMaliciousProcIdLock sync.Mutex = sync.Mutex{}
	cleanMapMaliciousProcIdLock  sync.Mutex = sync.Mutex{}
	maliciousProcCountguardLock  sync.Mutex = sync.Mutex{}
)

var (
	maliciousExfilProcessCount map[uint32]int = make(map[uint32]int)
	// convert to an shared distributed cache over the enitr data plane if required
	maliciousExfilProcessesRecCt map[uint32]int = make(map[uint32]int) // the lifecycle is only until the agent is alive for in-mory log count, for detailed metrics, prometheus is exporting detailed kernel metrics of malicious detected count

	maliciousExfilProcessAliveTime map[uint32]events.MaliciousProcessAliveTime = make(map[uint32]events.MaliciousProcessAliveTime)

	maliciousExfilPortIngressSniffCtxMap map[uint16]*maliciousExfilPortIngressSniffCtx = make(map[uint16]*maliciousExfilPortIngressSniffCtx) // sniff ctx port --> cancel ctx for cancel sniffing over port
)

func (tun *TCCloneTunnel) EnsureCleanUpTunnelPortMap(tunnelMap *ebpf.Map, srcPort uint16) (*events.DnsMapPayloadNonOverlayPort, error) {

	// ensure even though parallel sniff across go routines happen the kernel map update over this port transfer is synchronized
	kernelMaliciousTransferPortDelete.Lock()
	defer kernelMaliciousTransferPortDelete.Unlock()

	var potentialMaliciousTaskComm events.DnsMapPayloadNonOverlayPort
	if err := tunnelMap.LookupAndDelete(srcPort, &potentialMaliciousTaskComm); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, nil
		}
		return nil, err
	}

	return &potentialMaliciousTaskComm, nil
}

func (tun *TCCloneTunnel) UpdateMaliciousTransferProcessMapKernelDropClean(procId uint32, dport uint16) {
	// will be called since the process was SIGKILL from node agent in user space or via kernel syscall layer all entries for this must be cleaned
	cleanMapMaliciousProcIdLock.Lock()
	defer cleanMapMaliciousProcIdLock.Unlock()

	// aligned with memory pages
	var nsp_map_dport events.ExfilNSPDportPayload = events.ExfilNSPDportPayload{
		Processid: procId,
		Dport:     dport,
	}

	malProcMap := tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGRESS_PROC_MAL]
	if malProcMap == nil {
		return
	}

	deepScanCloneProcPortMap := tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGRESS_NSP_MAP]
	if deepScanCloneProcPortMap != nil {
		return
	}

	// remove the proc info from the thrid map for kernel re init pack flow
	if err := malProcMap.Delete(&procId); err != nil {
		utils.Log(err.Error()) // no need to process this as this may never happen since user space has guard rails for mutex in uapi
	}

	// remove from map 2 deepScanCloneProcPortMap (a process port and process id) can never collide over each clock cycle from CPU
	if err := deepScanCloneProcPortMap.Delete(&nsp_map_dport); err != nil {
		if utils.DEBUG {
			utils.Log(err.Error()) // EONET does not care for removel
		}
	}
}

// a placeholder for agent to help track via mpa the ingress sniff go routines booted to hunt all the potential malicious exfiltration attempts over random UDP ports
type maliciousExfilPortIngressSniffCtx struct {
	ctx         context.Context
	cancelSniff context.CancelFunc
}

var exfilSizePriorSigKill int = 0

func (tun *TCCloneTunnel) IncrementMaliciousProcCountLocalCacheOverlayPort(mapField *events.DnsMapPayloadNonOverlayPort, maliciousDestPort uint16) {
	maliciousProcCountguardLock.Lock()
	defer maliciousProcCountguardLock.Unlock()

	// the sniff context uses same mutex for node agent to track detected malicous process and associated port
	if IsTunnelSniffForLargeMaliciousThresholdRequired() {
		if _, fd := maliciousExfilPortIngressSniffCtxMap[maliciousDestPort]; !fd {
			ctx, cancel := context.WithCancel(context.Background())
			maliciousExfilPortIngressSniffCtxMap[maliciousDestPort] = &maliciousExfilPortIngressSniffCtx{
				ctx:         ctx,
				cancelSniff: cancel,
			}
			// make sure the whole context info struct is not passed for context missues ensure only the raw context for sniff session over this specifc port is passed
			// the sniff session for this port internally uses pcap over AF_PACKET as link layer for live packet sniffing
			go tun.IngressTunnelSniffer.SniffIgressForC2C(ctx, maliciousDestPort)
		}
	}

	if ct, fd := maliciousExfilProcessCount[mapField.ProcessId]; !fd {
		maliciousExfilProcessCount[mapField.ProcessId] = 1
		maliciousExfilProcessAliveTime[mapField.ProcessId] = events.MaliciousProcessAliveTime{
			ExfiltrationStartedAt: time.Now().Format(time.RFC850),
			ProcessId:             mapField.ProcessId,
			AliveTime:             time.Now().Second(),
		}

		// ensure does there exist conflict for preocess ID which was killed previously
		if val, fd := maliciousExfilProcessesRecCt[mapField.ProcessId]; fd {
			maliciousExfilProcessesRecCt[mapField.ProcessId] = val + 1
		} else {
			maliciousExfilProcessesRecCt[mapField.ProcessId] = 1
		}
	} else {
		if utils.DEBUG {
			utils.Log("Inc malicious count curr is ", maliciousExfilProcessCount[mapField.ProcessId])
		}
		if ct > utils.EXFIL_PROCESS_CACHE_CLEAN_THRESHOLD {
			// use the kernel syscall layer for SGKILL over the process from vmproc if kernel can't emit processId from traffic control layer, else send sigkill immediantley
			if utils.DEBUG {
				utils.Log("Amount of data exfiltrated prior removal and send a sigkill to the process", exfilSizePriorSigKill)
			}
			exfilSizePriorSigKill = 0
			if err := utils.KillProc(mapField.ProcessId); err != nil {
				utils.Logger.Printf("Error while sending sigkill to process %d wiht buffer err %+v", mapField.ProcessId, err.Error())
			}
			utils.Logger.Printf("The exfiltration was stopped send sigkill to the process %d was killed successfully", mapField.ProcessId)
			evTime := maliciousExfilProcessAliveTime[mapField.ProcessId]
			evTime.AliveTime = time.Now().Second() - int(evTime.AliveTime)

			go events.ExportPromeEbpfExporterEvents[events.MaliciousProcessAliveTime](evTime)

			delete(maliciousExfilProcessAliveTime, mapField.ProcessId)
			delete(maliciousExfilProcessCount, mapField.ProcessId)

			// stop sniffing PCAP over this port since the node SIGKILL the process
			// since the process is exfiltrating be parallel proc fd or the port would always be there in map to kill the process unless kernel traps the process to reach threshold configured in userspace
			if IsTunnelSniffForLargeMaliciousThresholdRequired() {
				if sniffCtx, fd := maliciousExfilPortIngressSniffCtxMap[maliciousDestPort]; fd {
					sniffCtx.cancelSniff()
				}
			}
			return
		}
		maliciousExfilProcessCount[mapField.ProcessId]++
	}

}

func GetCurrentLoggedExfiltratedProcessids() map[uint32]int {
	return maliciousExfilProcessesRecCt
}

func (tun *TCCloneTunnel) UpdateExportMetricsCountForDnsExfilRandomPort(isCloneRedirectedAndMalicious bool) error {
	kernelUpdateMaliciousReferenceLock.Lock()
	defer kernelUpdateMaliciousReferenceLock.Unlock()

	var redirCountKey uint16 = 0
	if !isCloneRedirectedAndMalicious {
		cloneredirectMap := tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGRESS_CLONE_REDIRECT_COUNT_MAP]
		if cloneredirectMap != nil {
			var currCt uint32 = 0
			if err := cloneredirectMap.Lookup(&redirCountKey, &currCt); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					utils.Logger.Printf("Error while reading the clone redirect count from the map %+v for suspicious packet redirect", err)
				}
				return err
			}
			events.ExportPromeEbpfExporterEvents[events.PacketDPICloneRedirectionCountEvent](events.PacketDPICloneRedirectionCountEvent{
				KernelCloneRedirectPacketCount: currCt,
				EvenTime:                       time.Now().GoString(),
			})
		}
	} else {
		cloneredirectDropMap := tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGRESS_CLONE_REDIRECT_DROP_KERNEL_COUNT_MAP]
		if cloneredirectDropMap != nil {
			var currCt uint32 = 0
			if err := cloneredirectDropMap.Lookup(&redirCountKey, &currCt); err != nil {
				if !errors.Is(err, ebpf.ErrKeyNotExist) {
					utils.Logger.Printf("Error while reading the clone redirect count from the map %+v", err)
				}
				return err
			}
			events.ExportPromeEbpfExporterEvents[events.PacketDPICloneRedirectionDropCountEvent](events.PacketDPICloneRedirectionDropCountEvent{
				KernelCloneRedirectPacketDropCount: currCt,
				EvenTime:                           time.Now().GoString(),
			})
		}
	}
	return nil
}

func (tun *TCCloneTunnel) SniffPacketsForTunnelDPI(ctx context.Context) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var handler *pcap.Handle
	var pcapErr error

	handler, pcapErr = tun.IfaceHandler.GetPcapHandleoverNetDevByName(netinet.NETNS_TUNNEL_TRAFFIC_NETLINK_BRIDGE_DPI, netinet.NETNS_BRIDGE_DEV_MTU)
	if pcapErr != nil {
		utils.Logger.Printf("Error while sniffing packets on the interface %s", netinet.NETNS_TUNNEL_TRAFFIC_NETLINK_BRIDGE_DPI)
		tun.GlobalKernelErrorChannel <- agenterr.EmitNewError(
			pcapErr, "TUNNEL_TC_PCAP", "Error getting the AF_PACKET pcap handler on netdev "+netinet.NETNS_TUNNEL_TRAFFIC_NETLINK_BRIDGE_DPI,
		)
		return
	}

	if err := handler.SetDirection(pcap.DirectionIn); err != nil {
		utils.Logger.Errorf("Error setting up the bpf filter :: %v", err)
		tun.GlobalKernelErrorChannel <- agenterr.EmitNewError(
			err, "TUNNEL_TC_PCAP", "Error setting PCAP direction for traffic ... ",
		)
		return
	}
	defer handler.Close()

	if err := handler.SetBPFFilter("udp or tcp"); err != nil {
		utils.Logger.Error("Error while setting the bpf filter")
		tun.GlobalKernelErrorChannel <- agenterr.EmitNewError(
			err, "TUNNEL_TC_PCAP", "Error setting the BPF filter on  netdev "+netinet.NETNS_NETLINK_BRIDGE_DPI,
		)
		return
	}

	sniffTunnelErr := make(chan interface{})

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-sniffTunnelErr:
				if !ok {
					return
				}
				utils.Log("Received an error while sniffing the packets over the veth bridge in kernel redirected non standard packet clone", msg)
			default:
				time.Sleep(time.Second)
			}
		}
	}()

	var tunnelTrafficEBPFMaps []*ebpf.Map = []*ebpf.Map{
		tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGRESS_CLONE_REDIRECT_COUNT_MAP],
		tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGRESS_CLONE_REDIRECT_DROP_KERNEL_COUNT_MAP],
	}

	tunnelTrafficEBPFMaps = append(tunnelTrafficEBPFMaps, tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGRESS_PROC_MAL])
	tunnelTrafficEBPFMaps = append(tunnelTrafficEBPFMaps, tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGRESS_NSP_MAP])
	tunnelTrafficEBPFMaps = append(tunnelTrafficEBPFMaps, tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGREES_CLONE_REDIRECT_MAP_NON_STANDARD_PORT])

	// add more eBPF kernel maps if multiple traffic DPI for xfil events is required
	for _, ebpfMap := range tunnelTrafficEBPFMaps {
		if ebpfMap == nil {
			utils.Log("Error the map parsed for tunneled c2c other socket is null")
			sniffTunnelErr <- struct {
				Err string
			}{
				Err: "The kernel ebpf map for tun is nil",
			}
			return
		}
	}

	// zero copy buffer to read buffer packets from the kernel rx handlers for performance over DPI
	for {
		data, _, err := handler.ZeroCopyReadPacketData()
		if err != nil {
			return
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		go tun.ProcessTunnelHandlerPackets(ctx, packet, sniffTunnelErr)
	}
}

func (tc *TCCloneTunnel) PollRingBuffer(ctx context.Context, ebpfEvents *ebpf.Map) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ringBuffer, err := ringbuf.NewReader(ebpfEvents)

	if err != nil {
		return err
	}

	defer ringBuffer.Close()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			record, err := ringBuffer.Read()
			if utils.DEBUG {
				utils.Log("polling the ring buffer", "using th map", ebpfEvents)
			}
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return err
				}
				utils.Logger.Printf("Error reading ring buffer: %s", err)
				return err
			}
			if utils.DEBUG {
				utils.Logger.Printf("Polling the ring buffer for the %s arch", utils.CpuArch())
			}

			if strings.Contains(ebpfEvents.String(), events.EXFIL_SECURITY_EGREES_REDIRECT_RING_BUFF_NON_STANDARD_PORT) {
				var event events.DnsEvent
				err = binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &event)
				if err != nil {
					utils.Logger.Fatalf("Failed to parse event: %v", err)
					return err
				}

				// kernel compatible to  extract process from task struct inside kernel traffic direct action qdisc SCHED_CLS in kernel
				if event.ProcessId != 0 && event.ThreadId != 0 {
					events.PrettyPrintMaliciousDNSEvent(&event)
				} else {
					utils.Log("Potential DNS tunnel from kernel detected", event)
				}
			}
			if strings.Contains(ebpfEvents.String(), events.EXFIL_SECURITY_ERROR_PIPE_AGENT) {
				// TODO: perform deep er ELK export for log or loki for deeper in kernel monitoring over massive scaled data planes at endpoints.
				var event events.KernelGlobalDPError
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &event); err != nil {
					utils.Logger.Errorf("Error polling kernel DPI error %+v", err)
					return err
				}

				utils.Log(event)
			}
		}
	}
}

/*
Update a process as malicious , and should be sigkilled or dropped prior threshold kernel kprobe else sigkill from userspace
*/
func (tun *TCCloneTunnel) EnsureTransportTunnelPortMapUpdateKernelProc(procComm *events.DnsMapPayloadNonOverlayPort,
	errorChannel chan interface{}) error {
	updateMapMaliciousProcIdLock.Lock()
	defer updateMapMaliciousProcIdLock.Unlock()

	// no need of mutex use atomic update to map values to control concurrent go routines
	if _, fd := tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGRESS_PROC_MAL]; fd {
		exfil_mal_proc_map := tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGRESS_PROC_MAL]
		var curr_detected_proc_mal_count events.DnsMapPayloadNonOverlayPortValue
		curr_detected_proc_mal_count.MalDetectedCount++
		if err := exfil_mal_proc_map.Lookup(&procComm.ProcessId, &curr_detected_proc_mal_count); err != nil {
			exfil_mal_proc_map.Update(&procComm.ProcessId, &curr_detected_proc_mal_count, ebpf.UpdateAny)
			// user space is only updating guarded with user synchronize lock or mutex ensure the updates are always synchronized for any map updates in kernel
		}
	}
	return nil
}

func (tun *TCCloneTunnel) ProcessMaliciousInferenceNonStandardPortfeatures(ctx context.Context, features []model.DNSFeatures, destTransportPort uint16, srcTransportPort uint16,
	event *events.ExfilRawPacketMirror, ev *events.DnsMapPayloadNonOverlayPort,
	errorChannel chan interface{}, layer gopacket.Layer) error {

	dnsExfilPayloadSize := utils.GetPacketPayloadSize(layer, "DNS")

	isAnySectionDomMalInCache := false
	for _, feature := range features {
		if utils.GetKeyPresentInEgressCache(feature.Tld) {
			isAnySectionDomMalInCache = true
			break
		}
	}

	if isAnySectionDomMalInCache {
		// check if something is there in ingress cache as malicious
		for _, feature := range features {
			if utils.IngGetKeyPresentInCache(feature.Tld) {
				isAnySectionDomMalInCache = true
				break
			}
		}
	}

	if !isAnySectionDomMalInCache {

		/// used as a processing input for standard tensor vectors for the deep learning model
		featureVectorsFloat := model.GenerateFloatVectors(features, tun.Onnx)
		if tun.Onnx.StaticRuntimeChecks(featureVectorsFloat, true) == model.DEEP_LEXICAL_INFERENCING {

			if tun.InferenceServerSock == nil {
				utils.Log("the Inference socket is not set ... ", tun.InferenceServerSock)
				return nil // dont block or erro for passive DPI if inference socket is not mounted
			}
			inferenceResponse, err := tun.InferenceServerSock.EgressInference(ctx, featureVectorsFloat)
			if err != nil {
				utils.Logger.Error(err.Error())
				return err
			}

			// detected malicious exfiltrated object
			if inferenceResponse.ThreatType {
				exfilSizePriorSigKill += dnsExfilPayloadSize

				if utils.DEBUG {
					// TODO: Enhance metrics to export the amount of payload being exfiltrated
					utils.Log("Exfiltrated DNS payload size is ", dnsExfilPayloadSize)
				}

				for _, feature := range features {
					if utils.VerifyKernelSupportTaskComms(ev.ProcessId, ev.ThreadId) {
						go events.ExportMaliciousEvents[progs.Protocol](events.DNSFeatures(feature), &tun.IfaceHandler.PhysicalNodeBridgeIpv4, "DNS",
							int(destTransportPort), &utils.MaliciousKernelTaskCommExportedProcInfo{
								ProcessId: ev.ProcessId,
								ThreadId:  ev.ThreadId,
							})
					} else {
						go events.ExportMaliciousEvents[progs.Protocol](events.DNSFeatures(feature), &tun.IfaceHandler.PhysicalNodeBridgeIpv4, "DNS",
							int(destTransportPort), nil)
					}

					if !conf.GlobalAgentCliConfig.DisableThreadEventStream {
						go tun.StreamClient.MarshallStreamThreadEvent(ctx, feature, stream.HostNetworkExfilFeatures{
							ExfilPort:        strconv.Itoa(int(destTransportPort)),
							Protocol:         string(events.DNS),
							PhysicalNodeIpv4: tun.IfaceHandler.PhysicalNodeBridgeIpv4.String(),
							PhysicalNodeIpv6: tun.IfaceHandler.PhysicalNodeBridgeIpv6.String(),
						})
					}
				}

				// update as the clone redirect as this is found malicious a potential DNS tunnel in kernel
				go tun.UpdateExportMetricsCountForDnsExfilRandomPort(true)

				// add the sld in cache in user space to stop reference over again to the ONNX inference server
				for _, feature := range features {
					utils.UpdateDomainNestedEgressCache(feature.Tld, feature.Fqdn, true)
				}

				utils.Log("Updating the process as it was detected carrying out breach ", ev)
				tun.EnsureTransportTunnelPortMapUpdateKernelProc(ev, errorChannel)

				go events.ExportPromeEbpfExporterEvents[events.Malicious_Non_Stanard_Transfer](events.Malicious_Non_Stanard_Transfer{
					Src_port:       int(event.SrcPort),
					Dest_port:      int(event.DstPort),
					IsUDPTransport: false,
				})

				if ev != nil {
					// only support sigkill if the kernel can emit process id from tc
					if utils.VerifyKernelSupportTaskComms(ev.ProcessId, ev.ThreadId) {
						tun.IncrementMaliciousProcCountLocalCacheOverlayPort(ev, destTransportPort)
					}
				}
				go utils.ForceGc()
			}
		}
	} else {
		// some section are already scanned and found to be malicious from different process or same process from user-space over the SLD domain exfiltrating date
		exfilSizePriorSigKill += dnsExfilPayloadSize
		utils.Log("SLD domain scanned to malicious not re scanning with remote unix inference server", features)
		if utils.DEBUG {
			// TODO: Enhance metrics to export the amount of payload being exfiltrated
			utils.Log("Exfiltrated DNS payload size is ", dnsExfilPayloadSize)
		}
		for _, feature := range features {
			if utils.VerifyKernelSupportTaskComms(ev.ProcessId, ev.ThreadId) {
				go events.ExportMaliciousEvents[progs.Protocol](events.DNSFeatures(feature), &tun.IfaceHandler.PhysicalNodeBridgeIpv4,
					"DNS", int(destTransportPort), &utils.MaliciousKernelTaskCommExportedProcInfo{
						ProcessId: ev.ProcessId,
						ThreadId:  ev.ThreadId,
					}) // (wont overflow (1 << 16))
			} else {
				go events.ExportMaliciousEvents[progs.Protocol](events.DNSFeatures(feature), &tun.IfaceHandler.PhysicalNodeBridgeIpv4,
					"DNS", int(destTransportPort), nil) //
			}

			if !conf.GlobalAgentCliConfig.DisableThreadEventStream {
				// even though found continous stream the events for any detected malicious events in the data plane for incident response and tracking every packet level  malicious activity
				go tun.StreamClient.MarshallStreamThreadEvent(ctx, feature, stream.HostNetworkExfilFeatures{
					ExfilPort:        strconv.Itoa(int(destTransportPort)),
					Protocol:         string(events.DNS),
					PhysicalNodeIpv4: tun.IfaceHandler.PhysicalNodeBridgeIpv4.String(),
					PhysicalNodeIpv6: tun.IfaceHandler.PhysicalNodeBridgeIpv6.String(),
				})
			}
		}

		go events.ExportPromeEbpfExporterEvents[events.Malicious_Non_Stanard_Transfer](events.Malicious_Non_Stanard_Transfer{
			Src_port:       int(event.SrcPort),
			Dest_port:      int(event.DstPort),
			IsUDPTransport: false,
		})

		for _, feature := range features {
			utils.UpdateDomainNestedEgressCache(feature.Tld, feature.Fqdn, true)
		}

		utils.Log("Updating the process as it was detected carrying out breach ", ev)
		tun.EnsureTransportTunnelPortMapUpdateKernelProc(ev, errorChannel)

		if ev != nil {
			if utils.VerifyKernelSupportTaskComms(ev.ProcessId, ev.ThreadId) {
				tun.IncrementMaliciousProcCountLocalCacheOverlayPort(ev, destTransportPort)
			}
			// older kernel version use kernel proc fs mount to ge process Information
		}
	}
	go utils.ForceGc()
	return nil
}

func (tun *TCCloneTunnel) ProcessTunnelHandlerPackets(ctx context.Context, packet gopacket.Packet,
	errorChannel chan interface{}) {

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
				utils.Log("found an encapsulated kernel dns packet the service VNI transport ID is ", remoteDestVniTransportID)
			}
			return true
		} else {
			dns := layers.DNS{}
			if err := dns.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err != nil {
				return false
			}

			if utils.DEBUG {
				utils.Log("found an encapsulated kernel dns packet the service VNI transport ID is ", remoteDestVniTransportID)
			}
			return true
		}

	}

	extractDnsLayer := func(dns *layers.DNS, transportPayload []byte) error {
		if err := dns.DecodeFromBytes(transportPayload, gopacket.NilDecodeFeedback); err != nil {
			return err
		}
		return nil
	}

	// this will always exist since the kenrel will only allow a l4 packet to reach to this bridge in user space via netfilter
	packetTransportLayer := packet.TransportLayer()
	if packetTransportLayer == nil {
		if utils.DEBUG {
			utils.Log("the packet does not have a transport layer")
		}
		// runtime chekc although this would never ever happen since the l4 is always checked in kernel
		// not event a dns packet
		return
	}

	udpPack := packet.Layer(layers.LayerTypeUDP)
	tcpPack := packet.Layer(layers.LayerTypeTCP)

	isUDP := udpPack != nil
	isTCP := tcpPack != nil
	// the map will be synchronized in user space to update map in for redire count with proper locks in kernel and appropriate spin locks
	go tun.UpdateExportMetricsCountForDnsExfilRandomPort(false)
	transportPayload := packetTransportLayer.LayerPayload()
	if len(transportPayload) < 12 {
		if utils.DEBUG {
			utils.Log("error while parsing the packet from kernel has header lenght to small")
		}
		// the kernel already have marked this as 0 no need to process anything
		// cannot be a dns packet
		return
	}

	dns := &layers.DNS{}

	// a tunneled dns packet overlay over the protocol
	// make the  packet pass through remote inferencing via the unix socket to be inferred with remote unix inference
	if isUDP {
		destPort := udpPack.(*layers.UDP).DstPort

		var destPortGenTypeValue uint16 = uint16(destPort)
		var srcPortGenTypeValue uint16 = uint16(udpPack.(*layers.UDP).SrcPort)

		var maliciousTunnelDNSEvent events.ExfilRawPacketMirror // a sniff packet struct not event from ring buffer

		// read and clean the srcport --> (procId, threadId)
		ev, err := tun.EnsureCleanUpTunnelPortMap(tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGREES_CLONE_REDIRECT_MAP_NON_STANDARD_PORT],
			srcPortGenTypeValue)

		if err != nil {
			// would nout occur if the C2 implant is continue to exhibit malicious activity at the endpoint
			utils.Log("Error in deleting the map for this kernel clone redirected suspicious  packet", err)
			return
		}

		if utils.VerifyNonDnsTransportPorts(destPortGenTypeValue) {
			if err := extractDnsLayer(dns, transportPayload); err != nil {
				utils.Log("error while parsing the packet from kernel")
				return
			}
		}

		if utils.VerifyNonDnsTransportPorts(destPortGenTypeValue) {
			// check for vxlan encap over the udp frame
			if isPackEncapsulated(dns, transportPayload) {
				if utils.DEBUG {
					utils.Log("A Vxlan kernel encappsulated dns packet is found in vxlan kernel transport header")
				}
				tun.EnsureTransportTunnelPortMapUpdateKernelProc(ev, errorChannel)
				return
			}
		}

		if !utils.VerifyNonDnsTransportPorts(destPortGenTypeValue) {
			utils.Log("the mode the current agent is ", tun.AgentOperationPassiveMode, " port ... ", destPortGenTypeValue)
		}

		if !utils.VerifyNonDnsTransportPorts(destPortGenTypeValue) && tun.AgentOperationPassiveMode && utils.DEBUG {
			utils.Log("the EDR agent running is passive mode, received clone packed for inference on the same nsp bridge iface ...")
		}

		features, err := model.ProcessDnsFeatures(dns, true)

		if err != nil {
			errorChannel <- struct {
				Err string
			}{
				Err: "Error while processing the dns packet features extraction for the malicious tunnel dns traffic over random port from kernel",
			}
		}

		// process nothing in userspace
		// just check and deep parse the questions of the record for netbios kernel query because of random port process allow for this port in kernel
		// standard go packet does not parse any NB query records
		if err := tun.ProcessMaliciousInferenceNonStandardPortfeatures(ctx, features, destPortGenTypeValue,
			srcPortGenTypeValue, &maliciousTunnelDNSEvent, ev, errorChannel, dns); err != nil {
			if utils.DEBUG {
				utils.Logger.Printf("Error in streaming the threat event for exfiltration attempt happened over non standard port %+v", err)
			}
			errorChannel <- struct {
				Err string
			}{
				Err: fmt.Sprintf("Error in streaming the threat event for exfiltration attempt happened over non standard port Transport TCP:: %+v", err),
			}
		}

	} else if isTCP {
		destPort := tcpPack.(*layers.TCP).DstPort
		var destPortGenType uint16 = uint16(destPort)
		var srcPortGenType uint16 = uint16(udpPack.(*layers.UDP).SrcPort)
		// kernel will take care to process and set the packet type when kernel redirect iva link clone to the userspace
		var event events.ExfilRawPacketMirror
		utils.Log("the dest port for packet transfer is ", uint16(destPort))

		ev, err := tun.EnsureCleanUpTunnelPortMap(tun.PhysicalTcInterfaceeBPFProgCollection.Maps[events.EXFIL_SECURITY_EGREES_CLONE_REDIRECT_MAP_NON_STANDARD_PORT], srcPortGenType)

		if err != nil {
			utils.Log("Error in deleting the map for this benign found packet", err)
		}

		if utils.VerifyNonDnsTransportPorts(destPortGenType) {
			if err := extractDnsLayer(dns, transportPayload); err != nil {
				utils.Log("error while parsing the packet from kernel")
				return
			}
		}

		// verify kernel support task comm to access kernel task struct over kernel TC layer
		if tun.TaskCommTCEgressKernelSupport {
			tun.IncrementMaliciousProcCountLocalCacheOverlayPort(ev, destPortGenType)
		}

		features, err := model.ProcessDnsFeatures(dns, true)
		if err != nil {
			errorChannel <- struct {
				Err string
			}{
				Err: "Error while processing the dns packet features extraction for the malicious tunnel dns traffic over random port from kernel",
			}
		}

		if err := tun.ProcessMaliciousInferenceNonStandardPortfeatures(ctx, features, destPortGenType,
			srcPortGenType, &event, ev, errorChannel, dns); err != nil {
			if utils.DEBUG {
				utils.Logger.Printf("Error in streaming the threat event for exfiltration attempt happened over non standard port %+v", err)

				errorChannel <- struct {
					Err string
				}{
					Err: fmt.Sprintf("Error in streaming the threat event for exfiltration attempt happened over non standard port Transport TCP:: %+v", err),
				}
			}
		}
	}
}
