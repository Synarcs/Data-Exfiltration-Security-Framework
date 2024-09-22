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
