package tc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type KernelNetlinkSocket struct {
	ProcessId   uint32
	Uid         uint32
	ProcessInfo [200]byte
}

func ProcessTunnelEvent(iface *netinet.NetIface, eventChannel chan bool) {
	for {
		select {
		case <-eventChannel:
			if utils.DEBUG {
				log.Println("Tunnel interface received command from channel")
			}
			iface.VerifyNewNetlinkPppSockets()
		default:
			time.Sleep(time.Millisecond)
		}
	}
}

func AttachNetlinkSockHandler(iface *netinet.NetIface, produceChannel chan bool) error {
	log.Println("Attaching the Netlink Tunnel Tap Socket Handler Scanner")
	handler, err := ebpf.LoadCollectionSpec(SOCK_TUNNEL_CODE_EBPF)

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

	// "tracepoint/syscalls/sys_enter_socket"
	//  Kernel Tracepoint for socket syscall for an open socket fd inside kernel of AF_FAMILY AF_NETLINK
	sockettp, err := link.Kprobe("tun_chr_open", objs.NetlinkSocket, nil)
	if err != nil {
		log.Fatal("error loading the kprobe program over sys_enter sock")
		return err
	}

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

		if !utils.DEBUG {
			log.Println("EBPF node agent detected new kernel tun tap link setup for tunnelling interface link via ioctl call")
			log.Println(netlinkEvent)
		}

		if netlinkEvent.ProcessId != uint32(os.Getpid()) {
			// dont monitor the node agent inteself
			_, ok := netlinkKernelProcMap[int(netlinkEvent.ProcessId)]
			if !ok {
				produceChannel <- true
				netlinkKernelProcMap[int(netlinkEvent.ProcessId)] = true
				if utils.DEBUG {
					log.Println("Polled from Kernel Tracepoint for netlink socket event", netlinkEvent.ProcessId, netlinkEvent.ProcessInfo)
				}
			}
		}

		time.Sleep(time.Second)
	}
}

func DetachSockHandler() error {
	return nil
}
