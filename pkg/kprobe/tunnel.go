/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

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
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils/agenterr"
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

type TunTapKprobes struct {
	KprobesEDRAgentComm
	NetlinkSocket     *ebpf.Program
	NetlinkSupportMap *ebpf.Map
	Link              link.Link
}

func NewTunTapKprobes(globalErrorKernelChan chan<- *agenterr.AgentError, iface *netinet.NetIface) *TunTapKprobes {
	tkprobes := &TunTapKprobes{}
	tkprobes.GlobalErrorKernelChan = globalErrorKernelChan
	tkprobes.Iface = iface
	return tkprobes
}

func (k *TunTapKprobes) ProcessTunnelEvent(ctx context.Context,
	iface *netinet.NetIface, eventChannel chan events.KernelNetlinkSocket, tc *tc.TCHandler) {
	for {
		select {
		case netlinkEvent, ok := <-eventChannel:
			if !ok {
				utils.Log("the tuntap receive event channle is closed ")
				return
			}
			if utils.DEBUG {
				utils.Log("Tunnel interface received command from channel")
			}
			if tunnelInterface := iface.FetchNewNetlinkPppSocket(); tunnelInterface == nil {
				// attach the kernel hook over encap tuntap interface for DPI in kernel
			} else {
				if err := tc.AttachTcProgramTunTap(
					ctx,
					tunnelInterface.Attrs().Name,
				); err != nil {
					utils.Log("error attaching the kernel dynamic tunneling ebpf for tunnel interface", err)
				}

				go events.ExportPromeEbpfExporterEvents[events.KernelNetlinkSocket](netlinkEvent)
			}
		default:
			time.Sleep(time.Millisecond)
		}
	}

}

// Attach the kprobe over the
func (k *TunTapKprobes) AttachTunTapKprobeHandler(ctx context.Context, iface *netinet.NetIface, produceChannel chan events.KernelNetlinkSocket) {
	utils.Log("Attaching the Netlink Tunnel Tap Socket Handler Scanner")

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err.Error())
	}

	handler, err := utils.ReadEbpfFromSpec(ctx, utils.SOCK_TUNNEL_CODE_EBPF)

	if err != nil {
		k.GlobalErrorKernelChan <- agenterr.EmitNewError(err, "TC_TUNTAP", fmt.Sprintf("Error injecting egress eBPF TC program %s", utils.SOCK_TUNNEL_CODE_EBPF))
		return
	}

	// static determine the program and maps and load and assign, rather creating new collection from spec
	var objs struct {
		NetlinkSocket                                     *ebpf.Program `ebpf:"tuntap_kprobe"`
		ExfilSecurityDetectedC2CTunnelingNetlinkSockEvent *ebpf.Map     `ebpf:"exfil_security_detected_c2c_tunneling_netlink_sock_event"`
	}

	if err := handler.LoadAndAssign(&objs, nil); err != nil {
		utils.Log("error loading the kprobe in kerenl ... ", err)
		k.GlobalErrorKernelChan <- agenterr.EmitNewError(
			err, "TC_TUNTAP", "error loading the egress TC program attached to TUNTAP interface",
		)
		return
	}

	k.NetlinkSocket = objs.NetlinkSocket
	k.NetlinkSupportMap = objs.ExfilSecurityDetectedC2CTunnelingNetlinkSockEvent

	// "tracepoint/syscalls/sys_enter_socket"
	//  Kernel Tracepoint for socket syscall for an open socket fd inside kernel of AF_FAMILY AF_NETLINK
	sockettp, err := link.Kprobe(TUNTAP_NET_OPEN, objs.NetlinkSocket, nil)
	if err != nil {
		utils.Logger.Fatal("error loading the kprobe program over sys_enter sock")
		k.GlobalErrorKernelChan <- agenterr.EmitNewError(
			err, "TC_TUNTAP", "error loading the egress TC program attached to TUNTAP interface",
		)
		return
	}

	k.Link = sockettp

	defer objs.NetlinkSocket.Close()
	defer objs.ExfilSecurityDetectedC2CTunnelingNetlinkSockEvent.Close()

	defer sockettp.Close()

	var netlinkEvent KernelNetlinkSocket

	ringBuff, err := ringbuf.NewReader(objs.ExfilSecurityDetectedC2CTunnelingNetlinkSockEvent)

	if err != nil {
		utils.Logger.Fatal("Error in creating the ring buffer reader")
		k.GlobalErrorKernelChan <- agenterr.EmitNewError(
			err, "TC_TUNTAP", "error in creating ringbuffer reader for tuntap interface egress events ",
		)
		return
	}
	defer ringBuff.Close()

	var netlinkKernelProcMap map[int]bool = make(map[int]bool)

	for {
		record, err := ringBuff.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				continue
			}
			utils.Logger.Fatal("Error in reading the ring buffer reader")
			k.GlobalErrorKernelChan <- agenterr.EmitNewError(
				err, "TC_TUNTAP", "error reading events from the egress TUNTAP interface",
			)
			return
		}

		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &netlinkEvent)
		if err != nil {
			log.Fatalf("Failed to parse event: %v", err)
		}

		go events.ExportPromeEbpfExporterEvents[events.KernelNetlinkSocket](events.KernelNetlinkSocket(netlinkEvent))

		if !utils.DEBUG {
			utils.Log("EBPF node agent detected new kernel tun tap link setup for tunnelling interface link via ioctl call")
		}

		if netlinkEvent.ProcessId != uint32(os.Getpid()) {
			// dont monitor the node agent inteself
			_, ok := netlinkKernelProcMap[int(netlinkEvent.ProcessId)]
			if !ok {
				produceChannel <- events.KernelNetlinkSocket(netlinkEvent)
				netlinkKernelProcMap[int(netlinkEvent.ProcessId)] = true
				if utils.DEBUG {
					utils.Log("Polled from Kernel Tracepoint for netlink socket event", netlinkEvent.ProcessId, netlinkEvent.ProcessInfo)
				}
			}
		}

		time.Sleep(time.Second)
	}
}

func (k *TunTapKprobes) DetachTunTapKprobeHandlers() error {
	if k.NetlinkSocket == nil {
		utils.Log("Cannot call raw detach before the required kprobe is first attached in kernel")
		return nil
	}

	if err := k.Link.Close(); err != nil {
		utils.Logger.Printf("Error detaching the Kprobe for Kernel hooks over netfilter %+v", err)
		return err
	}
	return nil
}
