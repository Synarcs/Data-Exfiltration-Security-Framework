package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Data-Exfiltration-Security-Framework/pkg/netinet"
	tc "github.com/Data-Exfiltration-Security-Framework/pkg/tc"
	xdp "github.com/Data-Exfiltration-Security-Framework/pkg/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	TC_CONTROL_PROG = "classify"
)

func tcHandler(ctx *context.Context, iface *netinet.NetIface, tc *tc.TCHandler) {

	handler, err := tc.ReadEbpfFromSpec(ctx)

	if err != nil {
		panic(err.Error())
	}

	spec, err := ebpf.NewCollection(handler)
	if err != nil {
		panic(err.Error())
	}

	defer spec.Close()

	if len(spec.Programs) > 1 {
		fmt.Println("Multiple programs found in the root collection")
	}
	if len(spec.Programs) == 0 {
		fmt.Println("The Ebpf Bytecode is corrupt or malformed")
	}

	prog := spec.Programs[TC_CONTROL_PROG]

	if prog == nil {
		panic(fmt.Errorf("No Required TC Hook found for DNS egress"))
	}

	if err := tc.AttachTcHandler(ctx, prog); err != nil {
		fmt.Println("Error attaching the clsact bpf qdisc for netdev")
		panic(err.Error())
	}

	ringBuffer, err := ringbuf.NewReader(spec.Maps["dns_ring_events"])

	if err != nil {
		panic(err.Error())
	}

	defer ringBuffer.Close()

	fmt.Println(spec.Maps, spec.Programs, " prog info ", prog.FD(), prog.String())

	go func() {
		for {
			fmt.Println("polling the ring buffer")
			data, err := ringBuffer.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				panic(err.Error())
			}
			fmt.Println("Data from ring buffer is ", data, string(data.RawSample))
		}
	}()
	if prog == nil {
		panic(fmt.Errorf("No Cliassify TC Egress collection found").Error())
	}

	// tcHandler.AttachTcHandler(&ctx, prog)
}

func main() {
	var tst chan os.Signal = make(chan os.Signal)

	// multi go route to handle for each tc chain handler
	// if err := xdp.LinkXdp(func(interfaceId *int) error { return nil }); err != nil {
	// }

	iface := netinet.NetIface{}
	iface.ReadInterfaces()
	ctx := context.Background()
	tc := tc.TCHandler{}

	tcHandler(&ctx, &iface, &tc)
	if err := xdp.LinkXdp(func(interfaceId *int) error { return nil })(1 << 10); err != nil {
		panic(err.Error())
	}

	signal.Notify(tst, syscall.SIGKILL, syscall.SIGINT)

	_, ok := <-tst

	if ok {
		fmt.Println("Root Process Sig Interrup terminating all the routines")
		tc.DetachHandler(&ctx)
		os.Exit(1)
	}
}
