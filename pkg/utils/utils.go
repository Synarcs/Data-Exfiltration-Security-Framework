package utils

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

var DEBUG = false

// kernel network traffic control and xdp ingress layer
const (
	TC_CONTROL_PROG        = "classify"        // CLSACT
	TC_CONTROL_PROG_BRIDGE = "bridge_classify" // CLSACT CLASSLESS QDISC
	XDP_CONTROL_PROG       = "xdp"             // XDP Non Offloaded

	TC_CLSACT_PARENT_QDISC_HANDLE = 0xffff
)

const (
	SOCK_TUNNEL_CODE = "netlink_socket"
)

const (
	SUSPICIOUS_NETNS_IPV6 = "fe80::d091:3cff:fe25:6d96"
	MALICIOUS_NETNS_IPV6  = "fe80::d091:3cff:fe25:6d97"
)

const (
	BRIDGE_IPAM_IPV4_CIDR          = "10.200.0.0/24"
	BRIDGE_IPAM_IPV4_IP            = "10.200.0."
	BRIDGE_IPAM_MAL_TUNNEL_IPV4_IP = "10.210.0.0" // send to the router bridge gateway for now
)

const (
	DNS_EGRESS_PORT           = 53
	DOT_EGRESS_PORT           = 853
	DNS_EGRESS_MULTICAST_PORT = 5353
)

// user space remote inferencing support for unix domain sockets
const (
	ONNX_INFERENCE_UNIX_SOCKET_EGRESS  = "/run/onnx-inference-out.sock"
	ONNX_INFERENCE_UNIX_SOCKET_INGRESS = "/run/onnx-inference-in.sock"
)

const (
	NODE_CONFIG_FILE = "config.yaml"
)

type NodeAgentConfig struct {
	StreamServer struct {
		Host string `yaml:"host" reflect:"host"`
		Ip   string `yaml:"ip" reflect:"ip"`
		Port string `yaml:"port" reflect:"port"`
	} `yaml:"streamServer" reflect:"streamServer"`

	DNSServer struct {
		Host string `yaml:"host" reflect:"host"`
		Ip   string `yaml:"ip" reflect:"ip"`
		Port string `yaml:"port" reflect:"port"`
	} `yaml:"dnsServer" reflect:"dnsServer"`
	MetricServer struct {
		Host string `yaml:"host" reflect:"host"`
		Ip   string `yaml:"ip" reflect:"ip"`
		Port string `yaml:"port" reflect:"port"`
	} `yaml:"metricServer" reflect:"metricServer"`
	MetricsExporter struct {
		Port string `yaml:"port" reflect:"port"`
		Ip   string `yaml:"ip" reflect:"ip"`
	} `yaml:"metricsExporter" reflect:"metricsExporter"`
}

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

func ReadEbpfFromSpec(ctx *context.Context, ebpfProgCode string) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(ebpfProgCode)
	if err != nil {
		return nil, err
	}
	return spec, nil
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

func CpuArch() string {
	return runtime.GOARCH
}

func GetCPUCores() int {
	return runtime.NumCPU()
}
