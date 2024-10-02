package events

// lower protocol packet information
type DnsEvent struct {
	PID          uint32
	SrcIP        uint32
	DstIP        uint32
	SrcPort      uint16
	DstPort      uint16
	PayloadSize  uint32
	UdpFrameSize uint32
	IsUdp        uint8
	IsTcp        uint8
}

const (
	EXFIL_SECURITY_EGRESS_REDIRECT_MAP = "exfil_security_egress_redirect_map"
	EXFIL_SECURITY_KERNEL_CONFIG_MAP   = "exfil_security_config_map"
)
