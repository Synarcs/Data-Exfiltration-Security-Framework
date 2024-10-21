package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Data-Exfiltration-Security-Framework/pkg/rpc"
	tc "github.com/Data-Exfiltration-Security-Framework/pkg/tc"
	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/Data-Exfiltration-Security-Framework/pkg/xdp"
)

func main() {
	log.Println("The Node Agent Booted up with thte process Id", os.Getpid())

	tst := make(chan os.Signal, 1)
	var term chan os.Signal = make(chan os.Signal, 1)

	iface := netinet.NetIface{}
	iface.ReadInterfaces()
	iface.ReadRoutes()
	iface.GetRootGateway()

	utils.InitCache()

	unixFd, err := model.ListenInferenceUnixClient()
	if err != nil {
		log.Println("Error opening unix socket for the inference server")
		panic(err.Error())
	}

	// load the model from onnx lib
	model, err := model.LoadOnnxModelToMemory(".", unixFd)
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
	go rpcServer.Server()
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
