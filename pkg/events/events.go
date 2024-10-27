package events

// lower protocol packet information
type DnsEvent struct {
	SrcIP    uint32
	DstIP    uint32
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

type DPIRedirectionKernelMap struct {
	Checksum      uint16
	_             [6]byte // padding for offset
	Kernel_timets uint64
}

// load the kernel config inside the kernel
type ExfilKernelConfig struct {
	BridgeIndexId uint32
	RedirectIpv4  uint32 // redirect to the linux network namesapce
}

type DPIRedirectionTimestampVerify struct {
	Kernel_timets           uint64
	UserSpace_Egress_Loaded uint8
}

const (
	EXFILL_SECURITY_EGRESS_REDIRECT_MAP             = "exfil_security_egress_redirect_map"
	EXFILL_SECURITY_EGRESS_REDIRECT_KERNEL_DROP_MAP = "exfil_security_egress_redirect_drop_count_map"
	EXFILL_SECURITY_EGRESS_REDIRECT_TC_VERIFY_MAP   = "exfil_security_egress_redurect_ts_verify"
	EXFILL_SECURITY_KERNEL_CONFIG_MAP               = "exfil_security_config_map"
	EXFILL_SECURITY_KERNEL_DNS_LIMITS_MAP           = "exfil_security_egress_dns_limites"
	EXFOLL_SECURITY_KERNEL_REDIRECT_COUNT_MAP       = "exfil_security_egress_redirect_count_map"
)
