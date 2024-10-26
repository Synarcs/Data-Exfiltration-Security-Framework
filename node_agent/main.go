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

	onnx "github.com/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Data-Exfiltration-Security-Framework/pkg/rpc"
	tc "github.com/Data-Exfiltration-Security-Framework/pkg/tc"
	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/Data-Exfiltration-Security-Framework/pkg/xdp"
)

func main() {
	log.Println("The Node Agent Booted up with thte process Id", os.Getpid())
	flag.Bool("debug", false, "Run the Node Agent in debug mode")

	flag.Usage = func() {
		fmt.Println("Usage: node_agent [options]")
		flag.PrintDefaults()
	}

	flag.Parse()

	tst := make(chan os.Signal, 1)
	var term chan os.Signal = make(chan os.Signal, 1)

	iface := netinet.NetIface{}
	iface.ReadInterfaces()
	iface.ReadRoutes()
	iface.GetRootGateway()

	utils.InitCache()

	// load the model from onnx lib
	// TODO: fix this remove garbage unwanted memory load for the model
	model, err := onnx.ConnectRemoteInferenceSocket(".")
	if err != nil {
		log.Println("The Required dumped stored model cannot be loaded , Node agent current process panic", os.Getpid())
		panic(err.Error())
	}

	ctx := context.Background()

	// kernel traffic control clsact prior qdisc or prior egress ifinde called via netlink
	// keep the iface for now only restrictive over the DNS egress layer
	tc := tc.GenerateTcEgressFactory(iface, model)

	config := make(chan interface{})
	rpcServer := rpc.NodeAgentService{
		ConfigChannel: config,
	}

	var ingress xdp.IngressSniffHandler = xdp.GenerateTcIngressFactory(iface, model)

	go tc.TcHandlerEbfpProg(&ctx, &iface)

	if !utils.DEBUG {
		// ideally the node agent works for handling receiveing streaming server side events from remote control plane endpoints
		go rpcServer.Server()
	}
	go ingress.SniffEgressForC2C()

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

	go func() {
		for {
			goRoutinesCount := runtime.NumGoroutine()
			if utils.DEBUG {
				log.Println("Number of goroutines running", goRoutinesCount)
			}
			time.Sleep(time.Second)
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
				tc.DetachHandler(&ctx)
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
		tc.DetachHandler(&ctx)
		os.Exit(int(syscall.SIGKILL)) // a graceful shutdown evict all the kernel hooks
	}
}
