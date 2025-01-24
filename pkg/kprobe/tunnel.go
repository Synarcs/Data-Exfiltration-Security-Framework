package kprobe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/tc"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	TUNTAP_NET_OPEN  = "tun_chr_open"
	TUNTAP_NET_CLOSE = "tun_chr_close"
)

type KernelNetlinkSocket struct {
	ProcessId     uint32
	Uid           uint32
	GroupId       uint32
	ThreadGroupId uint32
	ProcessInfo   [200]byte
}

type NetKProbes struct {
	NetlinkSocket     *ebpf.Program
	NetlinkSupportMap *ebpf.Map
	KprobelLink       link.Link
}

func GenerateKprobeEventFactory() *NetKProbes {
	return &NetKProbes{}
}

func (k *NetKProbes) ProcessTunnelEvent(ctx context.Context,
	iface *netinet.NetIface, eventChannel chan events.KernelNetlinkSocket, tc *tc.TCHandler) {
	for {
		select {
		case netlinkEvent, ok := <-eventChannel:
			if !ok {
				log.Println("the tuntap receive event channle is closed ")
				return
			}
			if utils.DEBUG {
				log.Println("Tunnel interface received command from channel")
			}
			if tunnelInterface := iface.FetchNewNetlinkPppSocket(); tunnelInterface == nil {
				// attach the kernel hook over encap tuntap interface for DPI in kernel
			} else {
				if err := tc.AttachTcProgramTunTap(
					ctx,
					tunnelInterface.Attrs().Name,
				); err != nil {
					log.Println("error attaching the kernel dynamic tunneling ebpf for tunnel interface", err)
				}

				go events.ExportPromeEbpfExporterEvents[events.KernelNetlinkSocket](netlinkEvent)
			}
		default:
			time.Sleep(time.Millisecond)
		}
	}

}

func (k *NetKProbes) AttachNetlinkSockHandler(iface *netinet.NetIface, produceChannel chan events.KernelNetlinkSocket) error {
	log.Println("Attaching the Netlink Tunnel Tap Socket Handler Scanner")

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err.Error())
	}

	handler, err := ebpf.LoadCollectionSpec(utils.SOCK_TUNNEL_CODE_EBPF)

	if err != nil {
		log.Fatal("error loading the xdp program over interface")
		return err
	}

	var objs struct {
		NetlinkSocket                                     *ebpf.Program `ebpf:"netlink_socket"`
		ExfilSecurityDetectedC2CTunnelingNetlinkSockEvent *ebpf.Map     `ebpf:"exfil_security_detected_c2c_tunneling_netlink_sock_event"`
	}

	if err := handler.LoadAndAssign(&objs, nil); err != nil {
		panic(err.Error())
	}

	k.NetlinkSocket = objs.NetlinkSocket
	k.NetlinkSupportMap = objs.ExfilSecurityDetectedC2CTunnelingNetlinkSockEvent

	// "tracepoint/syscalls/sys_enter_socket"
	//  Kernel Tracepoint for socket syscall for an open socket fd inside kernel of AF_FAMILY AF_NETLINK
	sockettp, err := link.Kprobe(TUNTAP_NET_OPEN, objs.NetlinkSocket, nil)
	if err != nil {
		log.Fatal("error loading the kprobe program over sys_enter sock")
		return err
	}

	k.KprobelLink = sockettp

	defer objs.NetlinkSocket.Close()
	defer objs.ExfilSecurityDetectedC2CTunnelingNetlinkSockEvent.Close()

	defer sockettp.Close()

	var netlinkEvent KernelNetlinkSocket

	ringBuff, err := ringbuf.NewReader(objs.ExfilSecurityDetectedC2CTunnelingNetlinkSockEvent)

	if err != nil {
		log.Fatal("Error in creating the ring buffer reader")
		return err
	}
	defer ringBuff.Close()

	var netlinkKernelProcMap map[int]bool = make(map[int]bool)

	for {
		if err != nil {
			log.Fatal("Error in creating the ring buffer reader")
			return err
		}

		record, err := ringBuff.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Fatal("Error in reading the ring buffer reader")
			return err
		}

		if utils.CpuArch() == "arm64" {
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &netlinkEvent)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}
		} else {
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.BigEndian, &netlinkEvent)
			if err != nil {
				log.Fatalf("Failed to parse event: %v", err)
			}
		}

		go events.ExportPromeEbpfExporterEvents[events.KernelNetlinkSocket](events.KernelNetlinkSocket(netlinkEvent))

		if !utils.DEBUG {
			log.Println("EBPF node agent detected new kernel tun tap link setup for tunnelling interface link via ioctl call")
		}

		if netlinkEvent.ProcessId != uint32(os.Getpid()) {
			// dont monitor the node agent inteself
			_, ok := netlinkKernelProcMap[int(netlinkEvent.ProcessId)]
			if !ok {
				produceChannel <- events.KernelNetlinkSocket(netlinkEvent)
				netlinkKernelProcMap[int(netlinkEvent.ProcessId)] = true
				if utils.DEBUG {
					log.Println("Polled from Kernel Tracepoint for netlink socket event", netlinkEvent.ProcessId, netlinkEvent.ProcessInfo)
				}
			}
		}

		time.Sleep(time.Second)
	}
}

func (k *NetKProbes) DetachSockHandler() error {
	if k.NetlinkSocket == nil {
		log.Println("Cannot call raw detach before the required kprobe is first attached in kernel")
		return fmt.Errorf("Delete of Kprobe from a non attached Kprobe Object over Tunner / io Driver")
	}

	if err := k.KprobelLink.Close(); err != nil {
		log.Printf("Error detaching the Kprobe for Kernel hooks over netfilter %+v", err)
		return err

	}
	return nil
}
