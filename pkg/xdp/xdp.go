package xdp

import (
	"context"
	"log"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
)

const (
	TC_INGRESS_ROOT_NETIFACE_INT = "xdp.o"
)

type XdpHandler struct {
	Interfaces []netlink.Link // phsycal interfaces which kernel supports
}

func (xdp *XdpHandler) LinkXdp(xdpHandle func(interfaceId *int) error) error {
	handler, err := ebpf.LoadCollectionSpec(TC_INGRESS_ROOT_NETIFACE_INT)

	if err != nil {
		log.Fatal("error loading the xdp program over interface")
		return err
	}

	spec, err := ebpf.NewCollection(handler)
	if err != nil {
		log.Fatal("error loading the xdp program over interface")
		return err
	}

	if len(spec.Programs) > 1 {
		log.Println("Multiple programs found in the root collection")
	}
	if len(spec.Programs) == 0 {
		log.Println("The Ebpf Bytecode is corrupt or malformed")
	}

	defer spec.Close()
	prog := spec.Programs[utils.XDP_CONTROL_PROG]
	defer prog.Close()

	for _, links := range xdp.Interfaces {
		go func() {
			l, err := link.AttachXDP(link.XDPOptions{
				Program:   prog,
				Interface: links.Attrs().Index,
			})
			if err != nil {
				log.Println("Error attaching the XDP program to the interface")
				panic(err.Error())
			}

			defer l.Close()
		}()
	}
	return nil
}

func (xdp *XdpHandler) XdpHandler(ctx *context.Context, iface *netinet.NetIface) error {
	return nil
}
