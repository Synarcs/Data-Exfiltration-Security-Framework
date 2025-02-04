package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/cli"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/kprobe"
	onnx "github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netfilter"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/rpc"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/sidecar"
	tcl "github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/tc"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/xdp"
	"gopkg.in/yaml.v2"
)

func initGlobalErrorControlChannel() chan bool {
	return make(chan bool)
}

type EbpfNodeAgentOptions struct {
	CliFlag          bool
	Debug            bool
	StreamClient     bool
	Sdr              bool
	MutatePort       int
	ContainerRuntime bool
	// used for sigkill with threshold limit for maslicious exfil detection
	SigKill int
}

func ReadGlobalNodeAgentConfig() (*utils.NodeAgentConfig, error) {
	if _, err := os.Stat(utils.NODE_CONFIG_FILE); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Println("Error cannot boot node daemon of ebpf with the base config file required {metrics, streamserver, dnsserver}")
			return nil, err
		}
		log.Printf("Erorr the config file exists but cannot be read %+v", err)
		return nil, err
	}

	var config *utils.NodeAgentConfig = &utils.NodeAgentConfig{}

	ff, _ := os.ReadFile(utils.NODE_CONFIG_FILE)

	if err := yaml.Unmarshal(ff, &config); err != nil {
		log.Printf("Error unmarshalling the config file %+v", err)
	}

	return config, nil
}

func main() {
	runtime.LockOSThread()
	var nodeAgentOptions EbpfNodeAgentOptions
	log.Println("The Node Agent Booted up with thte process Id", os.Getpid())
	flag.BoolVar(&nodeAgentOptions.Debug, "debug", false, "Run the Node Agent in debug mode")
	flag.BoolVar(&nodeAgentOptions.StreamClient, "streamClient", false, "Load the GRPC stream server over the node agent for threat streaming")
	flag.BoolVar(&nodeAgentOptions.CliFlag, "cli", false, "Runs the Node Agent control Daemon socket over a unix socket as cli reference")
	flag.BoolVar(&nodeAgentOptions.Sdr, "sdr", false, "Run the eBPF Node Agent as a containerd using CAP_NET_ADMIN as a sidecar for traffic exfiltration security in Kubernetes")
	flag.IntVar(&nodeAgentOptions.MutatePort, "mutatePort", 3000, "The port the eBPF Node agent mutation web hook runs ")
	flag.IntVar(&nodeAgentOptions.SigKill, "sigkill", 5, "Define the threshold for a process to be detected, post being sigkilled")
	flag.BoolVar(&nodeAgentOptions.ContainerRuntime, "crt", false, "Run the eBPF Node Agent as a container relying on bridge networking overlay from OCI pl;ugin mounted on host to stop exfiltration on host")

	flag.Usage = func() {
		fmt.Println("Usage: node_agent [options]")
		flag.PrintDefaults()
	}
	flag.Parse()

	ctx := context.Background()

	// rf Netlink packet parsing for the node agent
	iface := netinet.NetIface{}
	iface.ReadInterfaces(nodeAgentOptions.ContainerRuntime || nodeAgentOptions.Sdr)
	iface.ReadRoutes()
	iface.GetRootGateway()
	iface.InitconnTrackSockHandles()

	// io Disk Cache Inodes for Node agent
	utils.InitCache()
	topDomains, err := utils.ReadTldDomainsData()

	// running over the sidecar mode the eBPF root egress runs over kernel socket layer as against tc for egress DPI
	if nodeAgentOptions.Sdr {
		/*
			The sdr mode is used specifically for kubernetes following sidecar, well aligned with l7 service mesh sidecar envoy proxies
			This inject a sidecar via the k8s mutation webhook to load in kernel which runs in NET_ADMIN cap, and runs DNS exfiltration security, with eBPF kernel code sock ops egress security for DPI and packet filtering
		*/
		log.Println("The eBPF Node Agent for DNS security booted as a sidecar for Kubernetes POD for exfiltration security")
		mutationHookService := sidecar.NewMutationWebHook(nodeAgentOptions.MutatePort, ":")
		mutationHookService.InitMutationServer()
		return
	}

	globalErrorKernelHandlerChannel := initGlobalErrorControlChannel()

	globalConfig, err := ReadGlobalNodeAgentConfig()
	if err != nil {
		panic(err.Error())
	}

	log.Println("The Node Agent booted with global config", globalConfig)

	cliSock := cli.GenerateRemoteCliSocketServer()
	if nodeAgentOptions.CliFlag {
		log.Printf("The ebpf node agent booted with unix stream socket as cli daemon control for root admins  %s", cli.LocalCliUnixSockPath)
		go cliSock.ConfigureUnixSocket(globalErrorKernelHandlerChannel)
	}

	if nodeAgentOptions.Debug {
		utils.DEBUG = nodeAgentOptions.CliFlag
	}

	if nodeAgentOptions.StreamClient {
		config := make(chan interface{})
		rpcServer := rpc.NodeAgentService{
			ConfigChannel: config,
		}

		if !utils.DEBUG {
			// ideally the node agent works for handling receiveing streaming server side events from remote control plane endpoints
			go rpcServer.Server()
		}
	}

	tst := make(chan os.Signal, 1)
	var term chan os.Signal = make(chan os.Signal, 1)

	if err != nil {
		log.Println("error loading the top domains", err)
		panic(err.Error())
	}

	// holds kafka brokers and other kafka cluster related config
	globalKakfBrokerConfig := stream.InitBrokerConfig(globalConfig)
	// eBPF node-agent kafka stream producer for dns threat events streaming
	streamProducer := &stream.StreamProducer{
		KafkaBrokerConfig: globalKakfBrokerConfig,
	}

	streamConsumer := &stream.StreamConsumer{
		KafkaBrokerConfig: globalKakfBrokerConfig,
	}

	if err := streamProducer.GenerateStreamKafkaProducer(ctx); err != nil {
		log.Println("The Remote Kafka stream broker not found for threat stream analytics continue...", err)
	}

	if err := streamConsumer.GenerateStreamKafkaConsumer(ctx); err != nil {
		log.Println("The Remote Kafka stream broker not found for threat stream analytics continue...", err)
	}

	// load the model from onnx lib
	// TODO: fix this remove garbage unwanted memory load for the model
	model, err := onnx.ConnectRemoteInferenceSocket(topDomains)
	if err != nil {
		log.Println("The Required dumped stored model cannot be loaded , Node agent current process panic", os.Getpid())
		panic(err.Error())
	}

	// kernel traffic control clsact prior qdisc or prior egress ifinde called via netlink
	// keep the iface for now only restrictive over the DNS egress layer
	tc := tcl.GenerateTcEgressFactory(iface, model, streamProducer, globalErrorKernelHandlerChannel)

	// ingress xdp based packet sniff layer for deep packet monitoring over the ingress traffic
	ingress := xdp.GenerateXDPIngressFactory(iface, model, streamProducer, globalErrorKernelHandlerChannel)

	// all factory maps for the loaded kprobes by the ebpf Node Agent
	kprobe := kprobe.GenerateKprobeEventFactory()

	// host network traffic control for egress traffic to load the ebpf in kernel
	go tc.TcHandlerEbfpProg(ctx, &iface)

	// kernel netfilter process post routing hooks
	netfilter := netfilter.NetFilter{
		Interfaces: &iface,
	}
	go netfilter.AttachTcHandlerIngressBridge(ctx, false)

	// process pre default boot interfaces of type tunnels loaded pre in kernel
	go tcl.VerifyTunnelNetDevicesOnBoot(ctx, &tc, &iface)

	// add the kernel sock map
	tunnelSocketEventHandler := make(chan events.KernelNetlinkSocket)
	go kprobe.ProcessTunnelEvent(ctx, &iface, tunnelSocketEventHandler, &tc)
	go kprobe.AttachNetlinkSockHandler(&iface, tunnelSocketEventHandler)

	go events.StartPrometheusMetricExporterServer(globalConfig)

	go ingress.SniffIgressForC2C()

	if utils.DEBUG {
		for _, val := range iface.Links {
			fmt.Println(val.Attrs().Index, val.Attrs().Name)
		}
	}

	signal.Notify(tst, syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM)

	go func(term chan os.Signal, tst chan os.Signal) {
		sig := <-tst
		term <- sig
	}(term, tst)

	kernelHooksCleanUp := func() {
		tc.DetachHandler(&ctx)
		netfilter.DetachKernelBridgeNetfilterHook(&ctx) // will be loaded and found at runtime since the node agent owns this netface within kernel
		tc.IsLinkPppLinkAttached(&ctx)

		kprobe.DetachSockHandler()

		for _, openConnSocks := range iface.ConnTrackNsHandles {
			openConnSocks.CloseConntrackNetlinkSock()
		}

		if nodeAgentOptions.CliFlag {
			cliSock.CleanRemoteSock()
		}
	}

	// handle process log to log for now the processes which are detected malicious to send sigkill and kill them from kernel exec hooks
	go func() {
		cleanTicker := time.NewTicker(utils.EXFIL_PROCESS_CACHE_CLEAN_INTERVAL)
		for {
			select {
			case <-cleanTicker.C:
				onnx.LogMaliciousProcCountLocalCache()
			default:
				time.Sleep(time.Second)
			}
		}
	}()

	// global error channel for the kernel hooks
	go func() {
		for {
			select {
			case <-globalErrorKernelHandlerChannel:
				kernelHooksCleanUp()
			default:
				time.Sleep(time.Second)
			}
		}
	}()

	// TODO move this to uring or epoll fd listners for the remote inference server to emity socket close signal event consumed via unix trafer port
	go func() {
		ticker := time.NewTicker(time.Second)
		evalOnnxInferenceUnixSockMount := func() {
			_, egressErr := os.Stat(utils.ONNX_INFERENCE_UNIX_SOCKET_EGRESS)
			_, ingressErr := os.Stat(utils.ONNX_INFERENCE_UNIX_SOCKET_INGRESS)
			if egressErr != nil || ingressErr != nil {
				if errors.Is(egressErr, os.ErrNotExist) {
					log.Println("The Unix Local Unix Inference Socket is not available", egressErr.Error())
					log.Println("Gracefully shutting the Node agent and remove all kernel hooks")
				} else if errors.Is(ingressErr, os.ErrNotExist) {
					log.Println("The Unix Local Unix Inference Socket is not available", ingressErr.Error())
					log.Println("Gracefully shutting the Node agent and remove all kernel hooks")
				} else {
					log.Println("The Remote Unix Socket FD is not healthy", err.Error())
				}
				kernelHooksCleanUp()
				os.Exit(1)
			}
		}
		for {
			select {
			case <-ticker.C:
				evalOnnxInferenceUnixSockMount()
			default:
				time.Sleep(time.Second)
			}
		}
	}()

	sigType, done := <-term
	if done {
		switch sigType {
		case syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM:
			log.Println("Received signal", sigType, "Terminating all the kernel routines ebpf programs")
		}
		log.Println("Killing the root node agent ebpf programs atatched in Kernel", os.Getpid())
		kernelHooksCleanUp()
		streamProducer.CloseProducer()
		streamConsumer.CloseConsumer()
		os.Exit(int(syscall.SIGKILL)) // a graceful shutdown evict all the kernel hooks
	}

}
