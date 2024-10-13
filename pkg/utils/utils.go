package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

const DEBUG = false

const (
	TC_CONTROL_PROG  = "classify" // CLSACT
	XDP_CONTROL_PROG = "xdp"      // XDP Non Offloaded
)

const (
	BRIDGE_IPAM_IPV4_CIDR = "10.200.0.0/24"
	BRIDGE_IPAM_IPV4_IP   = "10.200.0."
)

type DomainNodeAgentCacheBlock struct {
	TLD            string
	CompleteDomain string
}

// later implement the nodeagent service cachine layer on this
var NODE_AGENT_BLACKLISTED_DOMAINS map[string]DomainNodeAgentCacheBlock = make(map[string]DomainNodeAgentCacheBlock)

func ParseIp(saddr uint32) string {
	var s1 uint8 = (uint8)(saddr>>24) & 0xFF
	var s2 uint8 = (uint8)(saddr>>16) & 0xFF
	var s3 uint8 = (uint8)(saddr>>8) & 0xFF
	var s4 uint8 = (uint8)(saddr & 0xFF)
	return fmt.Sprintf("%d.%d.%d.%d", uint8(s1), uint8(s2), uint8(s3), uint8(s4))
}

func ParseIpV6(saddr uint32) string {
	var s1 uint16 = (uint16)(saddr>>40) & 0xFF
	var s2 uint16 = (uint16)(saddr>>32) & 0xFF
	var s3 uint16 = (uint16)(saddr>>24) & 0xFF
	var s4 uint16 = (uint16)(saddr>>16) & 0xFF
	var s5 uint16 = (uint16)(saddr>>8) & 0xFF
	var s6 uint16 = (uint16)(saddr & 0xFF)
	return fmt.Sprintf("%x.%x.%x.%x.%x.%x", s1, uint16(s2), uint16(s3), uint16(s4), uint16(s5), uint8(s6))
}

func GenerateBigEndianIpv4(ipv4 string) uint32 {
	ip := net.ParseIP(ipv4).To4()
	// convert to big endian for the kernel to store dest address
	return binary.BigEndian.Uint32(ip)
}

func GenerateBigEndianIpv6(ipv6 string) (uint64, uint64) {
	ip := net.ParseIP(ipv6).To16()
	return binary.BigEndian.Uint64(ip[:len(ipv6)/2]), binary.BigEndian.Uint64(ip[len(ipv6)/2:])
}

func GetIpv4Address(id int) string {
	return BRIDGE_IPAM_IPV4_IP + strconv.Itoa(id)
}
