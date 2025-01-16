package events

// lower protocol packet information
type DnsEvent struct {
	DstPort          uint32
	SrcPort          uint32
	DnsTransactionId uint16
	IsUdp            uint8
	IsTcp            uint8
}

type DPIRedirectionKernelMap struct {
	Checksum      uint16
	_             [6]byte // padding for offset, since in kernel the ring buffer objects are packed and aligned to fix size memory blocks.
	Kernel_timets uint64
}

type DPIVxlanKernelEncapEvent struct {
	Transport_Dest_Port uint16
	Transport_Src_Port  uint16
}

type RemoteStreamInferenceAnalyzed struct {
	Fqdn               string      `json:"fqdn"`
	Tld                string      `json:"tld"`
	RecordType         string      `json:"RecordType"`
	AuthZoneSoaservers interface{} `json:"AuthZoneSoaservers"`
	IsMalicious        bool        `json:"IsMalicious"`
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

	// tunnel map
	EXFIL_TUNNEL_DNS_ENCAP_TRANSFER = "exfil_tunnel_dns_encap_transfer"

	EXFIL_SECURITY_EGRESS_RECONNISANCE_MAP_SCAN = "exfil_security_egress_reconnisance_map_scan"
)

// kernel eBPF ring buffers over kernel network stack
const (
	EXFIL_SECURITY_EGREES_REDIRECT_RING_BUFF_NON_STANDARD_PORT = "exfil_security_egrees_redirect_ring_buff_non_standard_port"
	EXFIL_SECURITY_EGRESS_VXLAN_ENCAP_DROP                     = "exfil_security_egress_vxlan_encap_drop"
)
