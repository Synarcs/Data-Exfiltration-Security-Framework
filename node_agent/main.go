/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/bridgetc"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/cli"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/conf"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/containers"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/containers/sock"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/crypto"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/envoy"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/kprobe"
	onnx "github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	progs "github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/progs"
	controllerrpc "github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/rpc"
	tcl "github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/tc"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/tracepoint/uapimac"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils/profile"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/xdp"
)

type KernelCleanHooks struct {
	tc        *tcl.TCHandler
	nft       *bridgetc.BridgeTCFilters
	kprobe    *kprobe.NetKProbes
	sockProgs *sock.SockKernelProgs
	iface     *netinet.NetIface
	cliSock   *cli.NodeDaemonCli
}

// return a channel map for other events hook the node agent must inject post successfull injection of the required prog of interest
func initKernelProgInjectComptionEvent() map[string]chan bool {
	return map[string]chan bool{
		progs.TC_PROG:        make(chan bool),
		progs.NETFILTER_PROG: make(chan bool),
		progs.SOCK_PROG:      make(chan bool),
		progs.KPROBE:         make(chan bool),
		progs.TRACEPOINT:     make(chan bool),
		progs.XDP:            make(chan bool),
		progs.LSM_BPF_HOOKS:  make(chan bool),
	}
}

func kernelHooksCleanUp(ctx context.Context, config *conf.NodeAgentCliOptions,
	cleanHooks *KernelCleanHooks, ignoreErr bool) error {
	if err := cleanHooks.tc.DetachHandler(&ctx); err != nil && !ignoreErr {
		return err
	} // kernel TC layer

	if err := cleanHooks.nft.DetachKernelBridgeTCFilters(&ctx); err != nil && !ignoreErr {
		return err
	} // kernel Netfilter layer

	cleanHooks.tc.IsLinkPppLinkAttached(&ctx)

	if err := cleanHooks.kprobe.DetachKprobeHandlers(); err != nil && !ignoreErr {
		return err
	} // kernel kprobe layer

	for _, openConnSocks := range cleanHooks.iface.ConnTrackNsHandles {
		if err := openConnSocks.CloseConntrackNetlinkSock(); err != nil && !ignoreErr {
			return err
		}
	} // not kernel eBPF hook but internally relies over kernel conntrack layer for cleaning nf_netlink socket

	if config.CliFlag {
		utils.Log("Cleaning the mounted unix socket")
		cleanHooks.cliSock.CloseChan <- true
	}

	if !utils.VerifyKernelEgressTCClsactTaskCommSuppert() {
		// clean the kernel sock op for attached filter over init kernel sock prog
		if err := cleanHooks.sockProgs.DetachKernelSockProg(ctx); err != nil && !ignoreErr {
			return err
		} // kernel socks cgroup layer
	}

	return nil
}

/*
The signed kernel keys which the node agent generate in data plane is always secured via the crypto keys ephemeral to the life time of agent
*/
func CleanCryptoDirs() error {
	if err := crypto.CleanOlderCrypoDir(); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return err
	}
	return nil
}

/*
Init all the kernel crypto dir ephemeral to hold keyrings and signatures to secure bpf programs injections
*/
func InitKernelCryptoHooks() (*crypto.NodeAgentCryptoConfig, error) {

	if err := crypto.CleanOlderCrypoDir(); err != nil {
		utils.Log("Error cleaning the older crypto dir, the node agent for LSM in kernel must boot with new ephemeral keys")
		return nil, err
	}

	if agentCryptoConfig, err := crypto.GenerateBPFCert(); err != nil {
		return nil, err
	} else {
		utils.Log("Configuring the kernel keyring for the node agent")

		if err := crypto.AddKernelKeyRing(agentCryptoConfig); err != nil {
			return nil, err
		}
		return agentCryptoConfig, nil
	}
}

func initSeccompDynamicSeccomFilters() error {

	// TODO: dynamic userspace enforced process aware security with dynamic security fitler values
	_, err := uapimac.NewFilter(uint32(os.Getpid()))
	if err != nil {
		return err
	}
	return nil
}

func populateInjectedKeyringMetaInfo() (*crypto.KernelCryptoKeyRingIds, error) {
	sessionIdInjectedRing, err := crypto.GetKeyRingSessionId()
	if err != nil {
		utils.Log("Error getting the kernel keyring session id", err.Error())
		return nil, err
	}

	if utils.DEBUG {
		utils.Log("The keyring session found and is ", sessionIdInjectedRing)
	}

	ebpfKeyringId, err := crypto.GetEbpFProgSignKeyringId()
	if err != nil {
		return nil, err
	}

	if utils.DEBUG {
		utils.Log("The keyring session found for ebpf is ", ebpfKeyringId)
	}

	rootKeyringId, err := crypto.GetRootKeyRingId()
	if err != nil {
		return nil, err
	}

	if utils.DEBUG {
		utils.Log("The keyring session found for root is ", rootKeyringId)
	}

	return &crypto.KernelCryptoKeyRingIds{
		SessionId:         uint32(sessionIdInjectedRing),
		EbpfSignKeyringId: uint32(ebpfKeyringId),
		RootKeyringId:     uint32(rootKeyringId),
	}, nil
}

// only configure varibales or thresholds of the agent and not the core kernel injection  program security
func configureGlobalAgentConfigOpts(nodeAgentCliOptions *conf.NodeAgentCliOptions) {
	if nodeAgentCliOptions.BPFProgPath != "" {
		if err := utils.ConfigureCustomEBPFProgOutputPath(nodeAgentCliOptions.BPFProgPath); err != nil {
			panic(err.Error())
		}
	}

	if nodeAgentCliOptions.SigKillBenignPortThreshold != utils.DEFAULT_SIGKILL_MALICIOUS_EXFIL_THRESHOLD {
		utils.EXFIL_PROCESS_CACHE_CLEAN_THRESHOLD_BENIGN_PORT = nodeAgentCliOptions.SigKillBenignPortThreshold
	}

	if nodeAgentCliOptions.SigKillTunnelPortThreshold != utils.DEFAULT_SIGKILL_MALICIOUS_EXFIL_THRESHOLD {
		utils.EXFIL_PROCESS_CACHE_CLEAN_THRESHOLD = nodeAgentCliOptions.SigKillTunnelPortThreshold
	}

	if nodeAgentCliOptions.ControllerRPCPort != controllerrpc.CONTROLLER_RPC_PORT {
		controllerrpc.CONTROLLER_RPC_PORT = nodeAgentCliOptions.ControllerRPCPort
	}
}

func InitControllerRpcClient(ctx context.Context) (*controllerrpc.AgentControllerRpcServices, error) {
	rpcClient := controllerrpc.NewAgentControllerRpcServices()
	if err := rpcClient.NodeAgentControllerEnforceSecRpc(ctx); err != nil {
		return nil, err
	}
	return rpcClient, nil
}

func main() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx := context.Background()
	ctx, agentCancelFunc := context.WithCancel(ctx)
	utils.NewLogger(ctx)

	var nodeAgentCliOptions conf.NodeAgentCliOptions
	utils.Log("The Node Agent Booted up with thte process Id", os.Getpid())
	flag.StringVar(&nodeAgentCliOptions.BPFProgPath, "bpf_prog_path", "", "the path containing all the eBPF compiled programs")
	flag.StringVar(&nodeAgentCliOptions.AgentConfigPath, "agent_config_path", "", "custom path absolute path for booting up the agent | must be yaml as per Agent required format")
	flag.BoolVar(&nodeAgentCliOptions.Debug, "debug", false, "Run the Node Agent in debug mode (default: false)")
	flag.BoolVar(&nodeAgentCliOptions.CliFlag, "cli", false, "Runs the Node Agent control Daemon socket over a unix socket as cli reference (default: false)")
	flag.BoolVar(&nodeAgentCliOptions.Profile, "profile", false, "Runs pprof profile server for flamegraph based node agent profiling live once injected all progs in kernel (default: false)")
	flag.BoolVar(&nodeAgentCliOptions.DisableThreadEventStream, "disable_thread_stream", false, "Assumes the endpoint security agent is isolated and does not streams threat events to centralized message broker")

	// k8s integration as planned for supporting sidecar traffic mutation guards to thwart exfiltration over all pods virtual net_device in kernel attached to either the host cni vxlan / bgp net_device or internal node to node communication on same pod
	flag.BoolVar(&nodeAgentCliOptions.Sdr, "sdr", false, "Run the eBPF Node Agent as a containerd using CAP_NET_ADMIN as a sidecar for traffic exfiltration security in Kubernetes")

	// integrates with existing CNI's based on the availaible netfilter in user space via envoy for cilium (l7 filters) or iptables, ipvs (l3, l4) filters
	flag.BoolVar(&nodeAgentCliOptions.Cni, "cni", false, "Instructs current configured CNI")
	flag.IntVar(&nodeAgentCliOptions.K8sControllerWebhookPort, "mutatePort", 3000, "The port the eBPF Node agent mutation web hook runs ")

	// kernel syscall layer interaction , needs kernel to support ring buffer emission for
	flag.IntVar(&nodeAgentCliOptions.SigKillBenignPortThreshold, "sigkill_benign", utils.DEFAULT_SIGKILL_MALICIOUS_EXFIL_THRESHOLD, "Defines the threshold for the number of times exfiltration through a process to be prevented by eBPF node agent for benign DNS port tunnelling, post being sigkilled")
	flag.IntVar(&nodeAgentCliOptions.SigKillTunnelPortThreshold, "sigkill_tunnel", utils.DEFAULT_SIGKILL_MALICIOUS_EXFIL_THRESHOLD, "Defines the threshold for the number of times exfiltration through a process to be prevented by eBPF node agent for malicious port tunnelling, post being sigkilled")

	// crypto lsm kernel integrate with pki for custom bootstreap ec CA or global cloud PKI config
	flag.BoolVar(&nodeAgentCliOptions.ControllerEnabledZtEnfoce, "controller_cz", false, "Enables the controller enabled LSM and cloud gobal CA for eBPF prog load integrity verification")
	flag.IntVar(&nodeAgentCliOptions.ControllerRPCPort, "controller_rpc_port", 3200, "Port used for rpc between data plane and controller")

	flag.BoolVar(&nodeAgentCliOptions.ContainerRuntime, "crt", false, "Run the eBPF Node Agent as a container relying on bridge networking overlay from OCI pl;ugin mounted on host to stop exfiltration on host")

	flag.Usage = func() {
		utils.Log("Usage: node_agent [options]")
		flag.PrintDefaults()
	}
	flag.Parse()

	configureGlobalAgentConfigOpts(&nodeAgentCliOptions)
	conf.ConfigureGlobalAgentCLiConfig(&nodeAgentCliOptions)
	globalEBPFProgInjectChan := initKernelProgInjectComptionEvent()

	// configure the global logger

	agentCryptoConfig, err := InitKernelCryptoHooks()
	if err != nil {
		utils.Log("the Node agent cannot boot without crypto validation ", err.Error())
		panic(err.Error())
	}

	_, err = populateInjectedKeyringMetaInfo()
	if err != nil {
		utils.Log("Error populating the keyring meta info", err.Error())
		panic(err.Error())
	}

	var cryptoLsmProgHandler *crypto.CryptoBpfLsm

	if !nodeAgentCliOptions.ControllerEnabledZtEnfoce {
		cryptoLsmProgHandler = crypto.New(
			crypto.NewCryptoBpfLsmWithLocalCAConfig(ctx, agentCryptoConfig),
		)
	} else {
		rpcClient, err := InitControllerRpcClient(ctx)
		if err != nil {
			panic(err.Error())
		}
		cryptoLsmProgHandler = crypto.New(
			crypto.NewCryptoBpfLsmWithLocalControllerRpcConfig(ctx, nodeAgentCliOptions.ControllerEnabledZtEnfoce, rpcClient),
		)
	}

	// // inject the crypto lsm program in kernel for all ebpf prog verification
	// if err := cryptoLsmProgHandler.InjectLsmProg(ctx); err != nil {
	// 	utils.Log("Error injecting the crypto lsm prog in kernel", err.Error())
	// 	panic(err.Error())
	// }

	envoy.InitTCPWasmFilter()

	// rf Netlink packet parsing for the node agent
	iface := netinet.NewNetIface()
	iface.ReadInterfaces(nodeAgentCliOptions.ContainerRuntime || nodeAgentCliOptions.Sdr)
	iface.ReadRoutes()
	iface.ConfigureAgentDnsServerConfig(nil)
	iface.InitconnTrackSockHandles()

	// before node agent inject kernel programs for security add inotify watchers for sysetmd resolved
	go iface.UpdateResolvedConfigForAgent(ctx)

	// init the hash for skb and entire node agent, the hash should be always unique per agent boot and injecttion in kernel
	hash := &crypto.Hash{}
	hash.GetRandomBootSkbMark()

	// io Disk Cache Inodes for Node agent
	if err := utils.InitCache(); err != nil {
		panic(err.Error())
	}

	topDomains, err := utils.ReadTldDomainsData()

	// running over the sidecar mode the eBPF root egress runs over kernel socket layer as against tc for egress DPI
	if nodeAgentCliOptions.Sdr && nodeAgentCliOptions.Cni {
		/*
			The sdr mode is used specifically for kubernetes following sidecar, well aligned with l7 service mesh sidecar envoy proxies
			This inject a sidecar via the k8s mutation webhook to load in kernel which runs in NET_ADMIN cap, and runs DNS exfiltration security, with eBPF kernel code sock ops egress security for DPI and packet filtering over the pod internal virtual phsycial link attach to the host vhost (for example cilium vxlan over cilium_host)
		*/
		panic(fmt.Errorf("cannot inject sidecar guards on the pod physical link with enabled CNI filter , please select either CNI or Sdr mode"))
	}

	if nodeAgentCliOptions.Sdr || nodeAgentCliOptions.Cni {
		utils.Log("The eBPF Node Agent for DNS security booted as a sidecar for Kubernetes POD for exfiltration security")
		mutationHookService := containers.NewMutationWebHook(nodeAgentCliOptions.K8sControllerWebhookPort, ":")
		mutationHookService.InitMutationServer()
		// configure the k8s Admission mutation webhook to inject k8s eBPF DNS as a sidecar for all pods labelled as security required for eBPF node agent
		return
	}

	globalErrorKernelHandlerChannel := utils.InitGlobalErrorControlChannel()
	var agentConfigLoader conf.AgentConfig = &conf.Config{}
	if nodeAgentCliOptions.AgentConfigPath != "" {
		if err := agentConfigLoader.ReadNodeAgentConfig(nodeAgentCliOptions.AgentConfigPath); err != nil {
			panic(err.Error())
		}
	} else {
		if err := agentConfigLoader.ReadNodeAgentConfig(""); err != nil {
			panic(err.Error())
		}
	}
	globalConfig := agentConfigLoader.GetAgentConfig()

	if utils.DEBUG {
		utils.Log("The Node Agent booted with global config", agentConfigLoader.GetAgentConfig())
	}

	cliSock := cli.NewRemoteCliSocketServer()
	if nodeAgentCliOptions.CliFlag {
		utils.Log(fmt.Sprintf("The ebpf node agent booted with unix stream socket as cli daemon control for root admins  %s", cli.LocalCliUnixSockPath))
		go cliSock.NewNodeAgentUnixCLISocket()
	}

	if nodeAgentCliOptions.Debug {
		utils.DEBUG = nodeAgentCliOptions.CliFlag
	}

	tst := make(chan os.Signal, 1)
	var term chan os.Signal = make(chan os.Signal, 1)

	if err != nil {
		utils.Log("error loading the top domains", err)
		panic(err.Error())
	}

	// holds kafka brokers and other kafka cluster related config
	globalKakfBrokerConfig := stream.InitBrokerConfig(globalConfig, &nodeAgentCliOptions)
	// eBPF node-agent kafka stream producer for dns threat events streaming
	streamProducer := &stream.StreamProducer{
		KafkaBrokerConfig: globalKakfBrokerConfig,
	}

	streamConsumer := &stream.StreamConsumer{
		KafkaBrokerConfig: globalKakfBrokerConfig,
		TopDomainsCache:   topDomains,
	}

	if err := streamProducer.NewStreamKafkaProducer(ctx); err != nil {
		utils.Log("The Remote Kafka stream broker not found for threat stream analytics continue...", err)
	}

	if err := streamConsumer.NewStreamKafkaConsumer(ctx); err != nil {
		utils.Log("Error starting node agent data plane kafka consumer ", err.Error())
	}

	// load the model from onnx lib
	model, err := onnx.NewRemoteInferenceSocket(topDomains)
	if err != nil {
		utils.Log("The Required dumped stored model cannot be loaded , Node agent current process panic", os.Getpid())
		panic(err.Error())
	}

	// kernel traffic control clsact prior qdisc or prior egress ifinde called via netlink
	// keep the iface for now only restrictive over the DNS egress layer
	tc, err := tcl.NewTcEgressFactory(&tcl.KernelTcInjectConfig{
		Iface:                           iface,
		OnnxModel:                       model,
		StreamClient:                    streamProducer,
		GlobalErrorKernelHandlerChannel: globalErrorKernelHandlerChannel,
		AgentConfig:                     agentConfigLoader,
		AgentHash:                       hash,
		CryptoAgentLSMHandler:           cryptoLsmProgHandler,
	})

	if err != nil {
		utils.Log(err.Error())
		panic(err.Error())
	}

	if globalConfig.EnhancedFeatures.Dns.EnableNxFloodPrevention {
		xdpHandler := xdp.NewXdpHandler(iface)
		if err := xdpHandler.LinkXdp(); err != nil {
			utils.Logger.Printf("Error Attach the XDP to physical link %+v", err)
		}
	}

	if globalConfig.EnhancedFeatures.Dns.EnableIngressSniff {
		// ingress pcap based packet sniff layer for deep packet monitoring over the ingress traffic, rely on pcap and AF_PACKET for CAP_RAW to sniff packets and not real XDP kernel rate limiter
		ingress := xdp.NewIngressSniffer(&xdp.IngressSnifferConfig{
			Iface:                           iface,
			OnnxModel:                       model,
			StreamClient:                    streamProducer,
			GlobalErrorKernelHandlerChannel: globalErrorKernelHandlerChannel,
		})
		go ingress.SniffIgressForC2C(ctx, utils.DNS_EGRESS_PORT)
	}

	// all factory maps for the loaded kprobes by the ebpf Node Agent
	kprobe := kprobe.NewKprobeEventFactory()

	// host network traffic control for egress traffic to load the ebpf in kernel
	go tc.TcHandlerEbfpProg(ctx, iface, globalEBPFProgInjectChan)

	// kernel tc process post routing hooks for attach over tc clsact bridge filters for the DPI in kernel
	netfilter := &bridgetc.BridgeTCFilters{
		Interfaces: iface,
		Hash:       hash,
	}
	go netfilter.AttachTcHandlerIngressBridge(ctx, false)

	// process pre default boot interfaces of type tunnels loaded pre in kernel
	go tcl.VerifyTunnelNetDevicesOnBoot(ctx, tc, iface)

	// add the kernel sock map
	tunnelSocketEventHandler := make(chan events.KernelNetlinkSocket)
	go kprobe.ProcessTunnelEvent(ctx, iface, tunnelSocketEventHandler, tc)
	go kprobe.AttachNetlinkSockHandler(iface, tunnelSocketEventHandler)

	go events.StartPrometheusMetricExporterServer(agentConfigLoader.GetAgentConfig())

	// start the profile server for flamegraph and cpu profiling for the node agent
	profilerContext, cancelctx := context.WithCancel(ctx)
	if nodeAgentCliOptions.Profile {
		go profile.InitProfileServer(profilerContext)
	}

	var sockProgs *sock.SockKernelProgs = new(sock.SockKernelProgs)
	if !utils.VerifyKernelEgressTCClsactTaskCommSuppert() {
		// ensure the kernel sock map is added for overlay proc task comm support in kernel tc layer
		// sock ops support all kernel socket layer progs (cgroups, sock_ops,skb_filters) etc
		if err := sockProgs.InjectKernelSockOps(ctx, utils.SOCK_SKB_OP_CODE_EBPF); err != nil {
			utils.Log("running on Older Kernel version to support Task comm over kernel error inject over sock ops prog ", err.Error())
			globalErrorKernelHandlerChannel <- err
		}
	}

	detachKernelHooksOpts := &KernelCleanHooks{
		tc:        tc,
		nft:       netfilter,
		kprobe:    kprobe,
		sockProgs: sockProgs,
		iface:     iface,
		cliSock:   cliSock,
	}

	// global error channel for the kernel hooks
	go func() {
		for err := range globalErrorKernelHandlerChannel {
			utils.Logger.Error("Error receieved in node agent global error chan ", err.Error())
			if err := kernelHooksCleanUp(ctx, &nodeAgentCliOptions, detachKernelHooksOpts, false); err != nil {
				utils.Logger.Printf("Error receieved in node agent global error chan closing ... %+v", err)
			}
		}
	}()

	go func(tc *tcl.TCHandler) {
		// load the node agent consumer from kafka topics which controller instructs all the data plane nodes for efiltration updates with node l3 information where exfiltration was stopeed and killed
		utils.Log("Loading the consumer for consuming thrat events update from control plane")
		for range globalEBPFProgInjectChan[progs.TC_PROG] {
			streamConsumer.ConfigureeBPFEgressHandlerForDynamicL3Blacklist(ctx, tc.TcCollection, tc.Prog, iface)
			if err := streamConsumer.ConsumeStreamAnalyzedThreatEvent(ctx); err != nil {
				streamConsumer.CloseConsumer()
			}
		}
	}(tc)

	signal.Notify(tst, syscall.SIGABRT, syscall.SIGINT, syscall.SIGTERM)

	go func(term chan os.Signal, tst chan os.Signal) {
		sig := <-tst
		term <- sig
	}(term, tst)

	// TODO move this to uring or epoll fd listners for the remote inference server to emity socket close signal event consumed via unix trafer port
	go func() {
		cleanMountedKernelHooks := func() {
			if err := kernelHooksCleanUp(ctx, &nodeAgentCliOptions, detachKernelHooksOpts, false); err != nil {
				utils.Log(fmt.Sprintf("Error cleaning the injected kernel hooks %+v", err))
			}
			os.Exit(int(syscall.SIGTERM))
		}

		fsSockMntRemoveWatchChan := make(chan bool)
		go onnx.OnnxModelFsUnixMountWatcher(ctx, fsSockMntRemoveWatchChan)

		for range fsSockMntRemoveWatchChan {
			utils.Log("The onnx model mount is required received Fs mont cl")
			cleanMountedKernelHooks()
		}
	}()

	// export the cpu metrics for the node agent once booted to prometheus
	go events.ExportCpuProcessMetrics(ctx)

	sigType := <-term
	switch sigType {
	case syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM:
		utils.Log("Received signal", sigType, "Terminating all the kernel routines ebpf programs")
	}
	utils.Log("Stopping the root node agent ebpf programs atatched in Kernel", os.Getpid())
	agentCancelFunc() // used only for ring buffers to stop polling ting buff from kernel
	if err := kernelHooksCleanUp(ctx, &nodeAgentCliOptions, detachKernelHooksOpts, false); err != nil {
		utils.Logger.Printf("Error cleaning the injected kernel hooks %+v", err)
	}

	if err := cryptoLsmProgHandler.RemoveCryptoLSMProgs(); err != nil {
		utils.Logger.Printf("Error removing the crypto lsm prog sig verifier progs %+v", err)
	}

	if err := crypto.CleanupKernelKeyRing(); err != nil {
		utils.Log("Error cleaning up the kernel keyring for custom signed keys", err.Error())
	}

	if crypto.DUMP_CA_LSM {
		CleanCryptoDirs()
	}

	streamProducer.CloseProducer()
	streamConsumer.CloseConsumer()

	// cancel ctx for the profiler running
	if nodeAgentCliOptions.Profile {
		cancelctx()
	}

	utils.Log("Node agent gracefully shutdown successfully with root process id", os.Getpid())
	os.Exit(int(syscall.SIGTERM)) // a graceful shutdown evict all the kernel hooks
}
