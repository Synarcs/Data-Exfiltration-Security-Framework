package tc

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type TCHandler struct {
	Interfaces []netlink.Link
}

const (
	TC_INGRESS_MONITOR_MAP = "bpf_sx"
)

func (tc *TCHandler) ReadEbpfFromSpec(ctx *context.Context) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec("icmp.o")
	if err != nil {
		return nil, err
	}
	return spec, nil
}

func (tc *TCHandler) CreateDPIInterfaceTc(ctx *context.Context) error {
	log.Println("Creating the TC ingress monitor for the DPI")

	fd, err := netlink.LinkByName(TC_INGRESS_MONITOR_MAP)
	if err == nil {
		fmt.Println("Link already exists with name ", TC_INGRESS_MONITOR_MAP)
		netlink.LinkDel(fd)
	}

	err = netlink.LinkAdd(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: TC_INGRESS_MONITOR_MAP,
			MTU:  1500,
		},
	})

	if err != nil {
		log.Fatalf("error Setting up the Link for DPI used for egress redirection to Ingress")
		return err
	}

	link, err := netlink.LinkByName(TC_INGRESS_MONITOR_MAP)
	if err := netlink.LinkSetUp(link); err != nil {
		fmt.Println("error setting the monitoring link for kernel")
		return err
	}

	if err != nil {
		log.Fatal("Error finding the link with name ", TC_INGRESS_MONITOR_MAP)
		return err
	}

	err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: net.ParseIP("10.2.0.0"), Mask: net.CIDRMask(16, 32)},
		Protocol:  unix.ETH_P_ALL,
		Scope:     unix.RT_SCOPE_UNIVERSE,
		Priority:  1,
		Table:     254,
	})

	if err != nil {
		fmt.Println("Error Adding the route for the ingress monitor redirected traffic control qdisc")
		return err
	}

	return nil
}

func (tc *TCHandler) AttachTcHandler(ctx *context.Context, prog *ebpf.Program) error {

	for _, link := range tc.Interfaces {
		log.Println("Attaching TC qdisc to the interface ", link.Attrs().Name)
		_, err := netlink.QdiscList(link)
		if err != nil {
			panic(err.Error())
		}

		log.Println("Attaching a qdisc handler")
		qdisc_clsact := &netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(0xffff, 0),
			},
		}
		if err := netlink.QdiscReplace(qdisc_clsact); err != nil {
			panic(err.Error())
		}

		filter := netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_MIN_EGRESS,
				Handle:    netlink.MakeHandle(1, 0),
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           prog.FD(),
			Name:         prog.String(),
			DirectAction: true,
		}

		if netlink.FilterReplace(&filter); err != nil {
			panic(err.Error())
		}
	}
	return nil
}

func (tc *TCHandler) processDNSCaptureForDPi(packet gopacket.Packet) error {
	eth := packet.Layer(layers.LayerTypeEthernet)
	if eth == nil {
		return fmt.Errorf("no ethernet layer")
	}
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)

	if ipLayer == nil || ipv6Layer == nil {
		return fmt.Errorf("An Empty layer 4 packet cannot be processed")
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)

	if udpLayer == nil || tcpLayer == nil {
		return fmt.Errorf("Empty tcp segment or udp datagram passed")
	}

	// init conside for pcap over udp dg only for now
	dnsLayer := packet.Layer(layers.LayerTypeDNS)

	if dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		fmt.Println("Question count ", dns.QDCount, "Answer count", dns.ANCount)
		fmt.Println(dns.Questions, dns.Answers)
	}

	return nil
}

func (tc *TCHandler) ProcessSniffDPIPacketCapture(ifaceHandler *netinet.NetIface, prog *ebpf.Program) error {
	nsHandle, err := ifaceHandler.GetNetworkNamespace("egress")
	if err != nil {
		log.Println(err.Error())
		return err
	}

	fmt.Println(nsHandle.UniqueId(), nsHandle.String())
	cap, err := pcap.OpenLive("enp0s1", 1500, true, pcap.BlockForever)
	if err != nil {
		fmt.Println("error opening packet capture over hte interface from kernel")
		return err
	}
	defer cap.Close()

	if err := cap.SetBPFFilter("udp and port 53"); err != nil {
		log.Fatalf("Error setting BPF filter: %v", err)
	}

	packets := gopacket.NewPacketSource(cap, cap.LinkType())
	for packet := range packets.Packets() {
		err := tc.processDNSCaptureForDPi(packet)
		if err != nil {
			log.Println("Error parsing the dns packet for DPI")
		}
	}
	return nil
}

func (tc *TCHandler) DetachHandler(ctx *context.Context) error {
	for _, link := range tc.Interfaces {
		err := netlink.QdiscDel(&netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: link.Attrs().Index,
				Parent:    netlink.HANDLE_CLSACT,
				Handle:    netlink.MakeHandle(0xffff, 0),
			},
		})
		if err != nil {
			fmt.Println("No Matching clsact desc found to delete")
		}
	}
	return nil
}
