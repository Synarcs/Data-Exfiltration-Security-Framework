package events

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

type DnsMapPayloadNonOverlayPort struct {
	ProcessId uint32
	ThreadId  uint32
}

type DPIRedirectionKernelMap struct {
	Checksum      uint16
	_             [6]byte // padding to align memory for cpu to fetch data
	Kernel_timets uint64
	ProcId        uint32
	ThreadId      uint32
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
	IsFprcedUnblock bool   `json:"isForcedUnBlocked"`
	// node ip or endpoint where data breach occured for other nodes to loga and event source
	DetectedThreadNodeIpv4           string   `json:"detectedThreadNodeIpv4"`
	DetectedThreadNodeIpv6           string   `json:"detectedThreadNodeIpv6"`
	ResolveAddressMaliciousC2Domains []string `json:"resolveAddressMaliciousC2Domains"`
}

type ExfilRawPacketMirror struct {
	DstPort                      uint16
	SrcPort                      uint16
	IsUdp                        uint8
	IsPacketRescanedAndMalicious uint8
}

// load the kernel config inside the kernel
type ExfilKernelConfig struct {
	BridgeIndexId           uint32
	NfNdpBridgeIndexId      uint32
	RedirectIpv4            uint32 // redirect to the linux network namesapce
	NfNdpBridgeRedirectIpv4 uint32
	KernelTCSKBMark         uint32
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

// kernel eBPF maps over kernel network stack
const (
	EXFILL_SECURITY_EGRESS_REDIRECT_MAP                   = "exfil_security_egress_redirect_map"
	EXFILL_SECURITY_EGRESS_REDIRECT_TC_VERIFY_MAP         = "exfil_security_egress_redurect_ts_verify"
	EXFILL_SECURITY_KERNEL_CONFIG_MAP                     = "exfil_security_config_map"
	EXFILL_SECURITY_KERNEL_DNS_LIMITS_MAP                 = "exfil_security_egress_dns_limites"
	EXFOLL_SECURITY_KERNEL_REDIRECT_COUNT_MAP             = "exfil_security_egress_redirect_count_map"
	EXFILL_SECURITY_EGRESS_REDIRECT_KERNEL_DROP_COUNT_MAP = "exfil_security_egress_redirect_drop_count_map"
	EXFILL_SECURITY_EGRESS_REDIRECT_LOOP_TIME             = "exfil_security_egress_redirect_loop_time"
	EXFIL_VXLAN_BLOCK_EGRESS_PORT                         = "exfil_vxlan_block_egress_port"
	EXFIL_TC_BRIDGE_CONFIG_MAP                            = "exfil_security_tc_bridge_config_map"

	// controller aware l3, proxy maps for all maps kernel will drop traffic
	EXFIL_SECURITY_EGRESS_L3_IPV4_DYNAMIC_NETPOOL_C2_FILTER = "exfil_security_egress_l3_ipv4_dynamic_netpool_c2_filter"
	EXFIL_SECURITY_EGRESS_L3_IPV6_DYNAMIC_NETPOOL_C2_FILTER = "exfil_security_egress_l3_ipv6_dynamic_netpool_c2_filter"

	// tunnel map
	EXFIL_TUNNEL_DNS_ENCAP_TRANSFER = "exfil_tunnel_dns_encap_transfer"

	EXFIL_SECURITY_EGRESS_RECONNISANCE_MAP_SCAN                = "exfil_security_egress_reconnisance_map_scan"
	EXFIL_SECURITY_EGREES_CLONE_REDIRECT_MAP_NON_STANDARD_PORT = "exfil_security_egrees_clone_redirect_map_non_standard_port"
)

// kernel eBPF ring buffers over kernel network stack
const (
	EXFIL_SECURITY_EGREES_REDIRECT_RING_BUFF_NON_STANDARD_PORT = "exfil_security_egrees_clone_redirect_ring_buff_non_standard_port"
	EXFIL_SECURITY_EGRESS_VXLAN_ENCAP_DROP                     = "exfil_security_egress_vxlan_encap_drop"
)
