package tc

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

func VerifyTunnelNetDevicesOnBoot(ctx *context.Context, tc *TCHandler, iface *netinet.NetIface) error {

	tunnelNetDev := iface.FindTunnelLinksOnBootUp()
	if len(tunnelNetDev) > 1 {
		for _, tunn := range tunnelNetDev {
			go tc.AttachTcProgramTunTap(ctx, tunn.Attrs().Name)
		}
	} else if len(tunnelNetDev) == 1 {
		tc.AttachTcProgramTunTap(ctx, tunnelNetDev[0].Attrs().Name)
	}
	return nil
}

func (tc *TCHandler) AttachTcProgramTunTap(ctx *context.Context, interfaceName string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err.Error())
	}
	handler, err := ReadEbpfFromSpec(ctx, TC_EGRESS_TUNNEL_NETIFACE_INT) // the tuntap handler interface

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

func (tc *TCHandler) IsLinkPppLinkAttached(ctx *context.Context) {
	for _, link := range tc.Interfaces.Links {
		if strings.Contains(link.Attrs().Flags.String(), "pointtopoint") {
			// deteach the present added kernel tuntap interface
			if err := tc.DetachHandlerTunTap(ctx, link); err != nil {
				log.Printf("Error detaching the Netlink Attached Socket event %+v", err)
			}
		}
	}
}

func (tc *TCHandler) DetachHandlerTunTap(ctx *context.Context, link netlink.Link) error {
	log.Println("Detaching the Attached PPP links found and their dynamically loaded eBPF program in kernel for DPI")
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

	return nil
}
