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
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/kprobe"
	onnx "github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netfilter"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/rpc"
	tcl "github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/tc"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/xdp"
	"gopkg.in/yaml.v2"
)

func initGlobalErrorControlChannel() chan bool {
	return make(chan bool)
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
	var cliFlag bool
	var debug bool
	var streamClient bool
	log.Println("The Node Agent Booted up with thte process Id", os.Getpid())
	flag.BoolVar(&debug, "debug", false, "Run the Node Agent in debug mode")
	flag.BoolVar(&streamClient, "streamClient", false, "Load the GRPC stream server over the node agent for threat streaming")
	flag.BoolVar(&cliFlag, "cli", false, "Runs the Node Agent control Daemon socket over a unix socket as cli reference")

	flag.Usage = func() {
		fmt.Println("Usage: node_agent [options]")
		flag.PrintDefaults()
	}

	flag.Parse()

	globalErrorKernelHandlerChannel := initGlobalErrorControlChannel()

	globalConfig, err := ReadGlobalNodeAgentConfig()
	if err != nil {
		panic(err.Error())
	}

	log.Println("The Node Agent booted with global config", globalConfig)

	cliSock := cli.GenerateRemoteCliSocketServer()
	if cliFlag {
		log.Printf("The ebpf node agent booted with unix stream socket as cli daemon control for root admins  %s", cli.LocalCliUnixSockPath)
		go cliSock.ConfigureUnixSocket(globalErrorKernelHandlerChannel)
	}

	if debug {
		utils.DEBUG = debug
	}

	if streamClient {
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

	ctx := context.Background()

	// rf Netlink packet parsing for the node agent
	iface := netinet.NetIface{}
	iface.ReadInterfaces()
	iface.ReadRoutes()
	iface.GetRootGateway()

	// io Disk Cache Inodes for Node agent
	utils.InitCache()
	topDomains, err := utils.VerifyTopDomainsData()

	if err != nil {
		log.Println("error loading the top domains", err)
		panic(err.Error())
	}

	streamProducer := &events.StreamClient{
		GlobalConfig: globalConfig,
	}

	if err := streamProducer.GenerateStreamKafkaProducer(&ctx); err != nil {
		log.Println("The Remote Kafka stream broken not found for threat stream analytics continue...", err)
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
	go tc.TcHandlerEbfpProg(&ctx, &iface)

	// kernel netfilter process post routing hooks
	netfilter := netfilter.NetFilter{
		Interfaces: &iface,
	}
	go netfilter.AttachTcHandlerIngressBridge(&ctx, false)

	// process pre default boot interfaces of type tunnels loaded pre in kernel
	go tcl.VerifyTunnelNetDevicesOnBoot(&ctx, &tc, &iface)

	// add the kernel sock map
	tunnelSocketEventHandler := make(chan events.KernelNetlinkSocket)
	go kprobe.ProcessTunnelEvent(&ctx, &iface, tunnelSocketEventHandler, &tc)
	go kprobe.AttachNetlinkSockHandler(&iface, tunnelSocketEventHandler)

	go events.StartPrometheusMetricExporterServer()

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

		if cliFlag {
			cliSock.CleanRemoteSock()
		}
	}

	go func() {
		for {
			goRoutinesCount := runtime.NumGoroutine()
			if utils.DEBUG {
				log.Println("Number of goroutines running", goRoutinesCount)
			}
			time.Sleep(time.Second)
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

	go func() {
		for {
			_, err := os.Stat(utils.ONNX_INFERENCE_UNIX_SOCKET_EGRESS)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					log.Println("The Unix Local Unix Inference Socket is not available", err.Error())
					log.Println("Gracefully shutting the Node agent and remove all kernel hooks")
				} else {
					log.Println("The Remote Unix Socket FD is not healthy", err.Error())
				}
				kernelHooksCleanUp()
				os.Exit(1)
			}
			time.Sleep(time.Second)
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
		streamProducer.CloseStreamClient()
		os.Exit(int(syscall.SIGKILL)) // a graceful shutdown evict all the kernel hooks
	}

}
