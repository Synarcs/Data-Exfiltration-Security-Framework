package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
)

const DEBUG = false

const (
	TC_CONTROL_PROG        = "classify" // CLSACT
	TC_CONTROL_PROG_BRIDGE = "classify" // CLSACT CLASSLESS QDISC
	XDP_CONTROL_PROG       = "xdp"      // XDP Non Offloaded

	TC_CLSACT_PARENT_QDISC_HANDLE = 0xffff
)

const (
	SUSPICIOUS_NETNS_IPV6 = "fe80::d091:3cff:fe25:6d96"
	MALICIOUS_NETNS_IPV6  = "fe80::d091:3cff:fe25:6d97"
)

const (
	BRIDGE_IPAM_IPV4_CIDR = "10.200.0.0/24"
	BRIDGE_IPAM_IPV4_IP   = "10.200.0."
)

// user space remote inferencing support for unix domain sockets
const (
	ONNX_INFERENCE_UNIX_SOCKET_EGRESS  = "/run/onnx-inference-out.sock"
	ONNX_INFERENCE_UNIX_SOCKET_INGRESS = "/run/onnx-inference-in.sock"
)

type Limites struct {
	MIN_DOMAIN_LENGTH              int
	MAX_DOMAIN_LENGTH              int
	MIN_SUBDOMAIN_LENGTH_PER_LABEL int
	MIN_LABEL_COUNT                int
}

// node agent caching from the userspace memory and not kernel heap pointed onto the kernel map FD
const (
	MAX_NODE_AGENT_CACHE_SIZE = 1000
)

const (
	DEFAULT_IPV6_CHECKSUM_MAP = 0xff
)

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

func GetIpv4AddressUserSpaceDpIString(id int) string {
	return BRIDGE_IPAM_IPV4_IP + strconv.Itoa(id)
}

func GetIpv4AddressUserspaceDPI(id int) net.IP {
	return []byte(BRIDGE_IPAM_IPV4_IP + strconv.Itoa(id))
}

func ExtractTldFromDomain(fqdn string) string {
	vv := strings.Split(fqdn, ".")
	if len(vv) <= 2 {
		return fqdn
	}
	return strings.Join(vv[len(vv)-2:], ".")
}

func cpuArch() string {
	return runtime.GOARCH
}

func getCPUCores() int {
	return runtime.NumCPU()
}
