/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package events

import (
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

const (
	KERNEL_DATAPATH_MAX_ERR_MESSAGE_SIZE = 1 << 7
)

// lower protocol packet information
type DnsEvent struct {
	DstPort          uint32
	SrcPort          uint32
	DnsTransactionId uint16
	IsUdp            uint8
	IsTcp            uint8
	ProcessId        uint32
	ThreadId         uint32
}

type KernelGlobalDPError struct {
	Err [KERNEL_DATAPATH_MAX_ERR_MESSAGE_SIZE]rune
}

func PrettyPrintMaliciousDNSEvent(ev *DnsEvent) {
	utils.Log("Potential DNS tunnel from kernel detected, polled from kernel non standard port tunnel transfer")
	utils.Logger.Printf("\n Dest Port :: %d \n Src Port :: %d \n DNS Query ID :: %d \n Process Id :: %d \n Thread Id :: %d", ev.DstPort,
		ev.SrcPort, ev.DnsTransactionId, ev.ProcessId, ev.ThreadId)
}

type DnsMapPayloadNonOverlayPort struct {
	ProcessId uint32
	ThreadId  uint32
}

type DnsMapPayloadNonOverlayPortValue struct {
	MalDetectedCount uint32
	DestPort         uint32
}

type DPIRedirectionKernelMap struct {
	Checksum     uint16
	KernelTimets uint64
	ProcId       uint32
	ThreadId     uint32
	SkbIndex     uint32
	L3Address    uint32
}

// Page align with ring buff page size and alighment of bytes
type DPIVxlanKernelEncapEvent struct {
	Transport_Dest_Port uint16 `align:"4"`
	Transport_Src_Port  uint16 `align:"4"`
}

type RemoteStreamInferenceControllerAnalyzed struct {
	Fqdn            string `json:"fqdn"`
	Tld             string `json:"tld"`
	RecordType      string `json:"recordType"`
	IsForcedUnblock bool   `json:"isForcedUnBlocked"`
	// node ip or endpoint where data breach occured for other nodes to loga and event source
	DetectedThreadNodeIpv4           string   `json:"detectedThreadNodeIpv4"`
	DetectedThreadNodeIpv6           string   `json:"detectedThreadNodeIpv6"`
	ResolveAddressMaliciousC2Domains []string `json:"resolveAddressMaliciousC2Domains"`
}

type RemoteSLDNodeCacheUpdate struct {
	SLD   string
	IsTld bool
}

// will be removed due to race condition issue
type ExfilRawPacketMirror struct {
	DstPort                      uint16
	SrcPort                      uint16
	IsUdp                        uint8
	IsPacketRescanedAndMalicious uint8
}

type ExfilNSPDportPayload struct {
	Processid uint32
	Dport     uint16
}

// load the kernel config inside the kernel
type ExfilKernelConfig struct {
	BridgeIndexId           uint32
	NfNdpBridgeIndexId      uint32
	RedirectIpv4            uint32 // redirect to the linux network namesapce
	NfNdpBridgeRedirectIpv4 uint32
	KernelTCSKBMark         uint32
	IsAgressiveSec          uint8
}

// nf_filter bridge config processing the eBPF maps as input to kernel netfilter ingress route over veth for linux ns
type NetfilterMapConfig struct {
	Bridge_if_index uint32
	SKB_Mark        uint32
}

type DPIRedirectionTimestampVerify struct {
	Kernel_timets           uint64
	UserSpace_Egress_Loaded uint8
}

// tb rate limit for egress tc
type TokenBucketEgressDnsConf struct {
	Timer     [16]byte
	MaxTokens uint64
}

// benchmark measure for DPI in kernel
type DPIPerformanceTime struct {
	Kernel_dpi_time uint64
	PacketSize      uint32
}

type LoopbacktransportInfo struct {
	SrcPort        uint16
	DestPort       uint16
	IngressIfIdnex uint32
}
