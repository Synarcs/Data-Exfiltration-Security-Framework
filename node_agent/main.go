package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Data-Exfiltration-Security-Framework/pkg/rpc"
	tc "github.com/Data-Exfiltration-Security-Framework/pkg/tc"
	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
)

func cpuArch() string {
	return runtime.GOARCH
}

func main() {
	log.Println("[x] The Node Agent Booted up with thte process Id", os.Getpid())

	tst := make(chan os.Signal, 1)
	var term chan os.Signal = make(chan os.Signal, 1)

	iface := netinet.NetIface{}
	iface.ReadInterfaces()

	ctx := context.Background()

	var config chan interface{} = make(chan interface{})

	// // kernel traffic control clsact prior qdisc or prior egress ifinde called via netlink
	tc := tc.TCHandler{
		Interfaces:    iface.PhysicalLinks,
		DnsPacketGen:  tc.GenerateDnsParserModelUtils(&iface),
		ConfigChannel: config,
	}

	rpcServer := rpc.NodeAgentService{
		ConfigChannel: config,
	}

	go tc.TcHandlerEbfpProg(&ctx, &iface)
	go rpcServer.Server()

	if utils.DEBUG {
		for _, val := range iface.Links {
			fmt.Println(val.Attrs().Index, val.Attrs().Name)
		}
	}
	// // kernel xdp ingress for ifindex over xdp inside kernel
	// xdp := xdp.XdpHandler{
	// 	NetIfIndex: iface.Links[0].Attrs().Index,
	// }
	// if err := xdp.LinkXdp(func(interfaceId *int) error { return nil })(1 << 10); err != nil {
	// 	panic(err.Error())
	// }

	signal.Notify(tst, syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM)

	go func(term chan os.Signal, tst chan os.Signal) {
		sig := <-tst
		term <- sig
	}(term, tst)

	sigType, done := <-term
	if done {
		switch sigType {
		case syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM:
			fmt.Println("Received signal", sigType, "Terminating all the kernel routines ebpf programs")
		}
		fmt.Println("Killing the root node agent ebpf programs atatched in Kernel")
		tc.DetachHandler(&ctx)
		os.Exit(int(syscall.SIGKILL)) // a graceful shutdown evict all the kernel hooks
	}
}
