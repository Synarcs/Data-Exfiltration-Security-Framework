package utils

import (
	"encoding/binary"
	"fmt"
	"net"
)

const DEBUG = false

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

func ConvertIpHex(ipv4 string, isIpv4 bool) (uint32, error) {
	var ip net.IP

	if isIpv4 {
		ip = net.ParseIP(ipv4).To4()
	} else {
		ip = net.ParseIP(ipv4).To16()
	}
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 address")
	}

	return uint32(binary.BigEndian.Uint32(ip)), nil
}
