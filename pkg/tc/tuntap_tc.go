package tc

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

func (tc *TCHandler) AttachTcProgramTunTap(ctx *context.Context, interfaceName string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err.Error())
	}
	handler, err := tc.ReadEbpfFromSpec(ctx, TC_EGRESS_TUNNEL_NETIFACE_INT) // the tuntap handler interface

	if err != nil {
		return err
	}

	spec, err := ebpf.NewCollection(handler)

	if err != nil {
		return err
	}
	defer spec.Close()

	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return err
	}

	err = netlink.QdiscAdd(&netlink.Clsact{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
		},
	})
	if err != nil {
		return err
	}

	log.Println("the ebpf tc clsact direct action attached in kernel for egress hook over the tunnel interface")
	return nil
}

func (tc *TCHandler) DetachHandlerTunTap(ctx *context.Context) error {

	for _, link := range tc.Interfaces.Links {
		flags := link.Attrs().Flags
		if strings.Contains(flags.String(), "pointtopoint") {
			// attach the ppp socket tc hooks inside kernel

			err := netlink.QdiscDel(&netlink.Clsact{
				QdiscAttrs: netlink.QdiscAttrs{
					LinkIndex: link.Attrs().Index,
					Parent:    netlink.HANDLE_CLSACT,
					Handle:    netlink.MakeHandle(utils.TC_CLSACT_PARENT_QDISC_HANDLE, 0),
				},
			})
			if err != nil {
				fmt.Println("No Matching clsact desc found to delete")
			}
			log.Println("Successfully Removed the Traffic control from the interface ", link.Attrs().Name)
		}
	}

	return nil
}
