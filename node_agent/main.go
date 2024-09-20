package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Data-Exfiltration-Security-Framework/pkg/netinet"
	tc "github.com/Data-Exfiltration-Security-Framework/pkg/tc"
	xdp "github.com/Data-Exfiltration-Security-Framework/pkg/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	TC_CONTROL_PROG = "classify" // CLSACT
)

func parseIp(saddr uint32) string {
	var s1 uint8 = (uint8)(saddr>>24) & 0xFF
	var s2 uint8 = (uint8)(saddr>>16) & 0xFF
	var s3 uint8 = (uint8)(saddr>>8) & 0xFF
	var s4 uint8 = (uint8)(saddr & 0xFF)
	return fmt.Sprintf("%d.%d.%d.%d", uint8(s1), uint8(s2), uint8(s3), uint8(s4))
}

func tcHandler(ctx *context.Context, iface *netinet.NetIface, tc *tc.TCHandler) {
	log.Println("Attaching a kernel Handler for the TC CLS_Act Qdisc")
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
			fmt.Println("polling the ring buffer", "using th map", spec.Maps["dns_ring_events"])
			record, err := ringBuffer.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				panic(err.Error())
			}
			var event events.DnsEvent
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}

			// No further conversion is needed; values are already in host byte order
			fmt.Printf("PID: %d, SrcIP: %s, DstIP: %s, SrcPort: %d, DstPort: %d\n",
				event.PID, parseIp(event.SrcIP), parseIp(event.DstIP), event.SrcPort, event.DstPort)
			fmt.Printf("Payload Size: %d, UDP Frame Size: %d\n", event.PayloadSize, event.UdpFrameSize)
		}
	}()
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
	tc := tc.TCHandler{
		Interfaces: iface.Links,
	}

	tcHandler(&ctx, &iface, &tc)
	if err := xdp.LinkXdp(func(interfaceId *int) error { return nil })(1 << 10); err != nil {
		panic(err.Error())
	}

	time.Sleep(time.Hour)
	signal.Notify(tst, syscall.SIGKILL, syscall.SIGINT)

	_, ok := <-tst

	if ok {
		fmt.Println("Root Process Sig Interrup terminating all the routines")
		tc.DetachHandler(&ctx)
		os.Exit(1)
	}
}
