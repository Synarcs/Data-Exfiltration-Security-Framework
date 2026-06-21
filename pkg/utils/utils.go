/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package utils

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils/agenterr"
	"github.com/cilium/ebpf"
	"github.com/google/gopacket"
)

// works as a bridge between kernel netdev (tc) layer and kernel syscall layer eBPF hooks to kill if multiple malicious count found
type MaliciousKernelTaskCommExportedProcInfo struct {
	ProcessId uint32
	ThreadId  uint32
}

type Limites struct {
	MIN_DOMAIN_LENGTH              int
	MAX_DOMAIN_LENGTH              int
	MIN_SUBDOMAIN_LENGTH_PER_LABEL int
	MIN_LABEL_COUNT                int
}

type Utsname struct {
	Sysname    [65]int8
	Nodename   [65]int8
	Release    [65]int8
	Version    [65]int8
	Machine    [65]int8
	Domainname [65]int8
}

// node agent caching from the userspace memory and not kernel heap pointed onto the kernel map FD
const (
	MAX_NODE_AGENT_CACHE_SIZE           = 1000
	INFERENED_DOMAIN_CACHE_SIZE_PER_TLD = 1000
	MAX_NODE_AGENT_CACHE_LOOKUP_SIZE    = 1000
)

const (
	DEFAULT_IPV6_CHECKSUM_MAP = 0xff
)

// Generate the bpf filter for sniff in zero copy of DNS over udp or TCP
func GenerateBpfFIlterForDNS(isEgress bool, isudp bool) string {
	var dir string
	var transport string
	if isEgress {
		dir = "dst"
	} else {
		dir = "src"
	}
	if isudp {
		transport = "udp"
	} else {
		transport = "tcp"
	}
	bpf_filter := strings.Builder{}
	bpf_filter.WriteString(fmt.Sprintf("%s %s port %d", transport, dir, DNS_EGRESS_PORT))
	bpf_filter.WriteString(" or ")
	bpf_filter.WriteString(fmt.Sprintf("%s %s port %d", transport, dir, DNS_EGRESS_MULTICAST_PORT))
	bpf_filter.WriteString(" or ")
	bpf_filter.WriteString(fmt.Sprintf("%s %s port %d", transport, dir, LLMNR_EGRESS_LOCAL_MULTICAST_PORT))
	return bpf_filter.String()
}

func VerifyNonDnsTransportPorts(port uint16) bool {
	return port != DNS_EGRESS_PORT &&
		port != DNS_EGRESS_MULTICAST_PORT &&
		port != LLMNR_EGRESS_LOCAL_MULTICAST_PORT
}

func InitGlobalErrorControlChannel() chan *agenterr.AgentError {
	return make(chan *agenterr.AgentError)
}

func ParseIp(saddr uint32) string {
	var s1 uint8 = (uint8)(saddr>>24) & 0xFF
	var s2 uint8 = (uint8)(saddr>>16) & 0xFF
	var s3 uint8 = (uint8)(saddr>>8) & 0xFF
	var s4 uint8 = (uint8)(saddr & 0xFF)
	return fmt.Sprintf("%d.%d.%d.%d", uint8(s1), uint8(s2), uint8(s3), uint8(s4))
}

func ParseIpV6(saddr uint64) string {
	var s1 uint16 = (uint16)(saddr>>40) & 0xFF
	var s2 uint16 = (uint16)(saddr>>32) & 0xFF
	var s3 uint16 = (uint16)(saddr>>24) & 0xFF
	var s4 uint16 = (uint16)(saddr>>16) & 0xFF
	var s5 uint16 = (uint16)(saddr>>8) & 0xFF
	var s6 uint16 = (uint16)(saddr & 0xFF)
	return fmt.Sprintf("%x.%x.%x.%x.%x.%x", s1, uint16(s2), uint16(s3), uint16(s4), uint16(s5), uint8(s6))
}

func BigEndianToIPv4(ipInt uint32) string {
	ipBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ipBytes, ipInt)
	return net.IP(ipBytes).String()
}

func LittleEndianToIpv4(ipaddr uint32) string {
	ipBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(ipBytes, ipaddr)
	return net.IP(ipBytes).String()
}

func GetNodeHostName() (string, error) {
	nodeName, err := os.Hostname()
	if err != nil {
		Log("Error getting hostname", err)
		return "", err
	}
	return nodeName, nil
}

// generate the required chanel for controller to stream those remote ipv4 / ipv6 c2 server addresses
func GenerateC2BlacklistAddressChannels() (chan net.IP, chan net.IP) {
	return make(chan net.IP), make(chan net.IP)
}

func GenerateBigEndianIpv4(ipv4 string) uint32 {
	ip := net.ParseIP(ipv4).To4()
	if ip == nil {
		Logger.Fatalf("Cannot configure incorrect Ipv4 l3 address in ebPF map for kernel for deep scan")
	}
	// convert to big endian for the kernel to store dest address
	return binary.BigEndian.Uint32(ip)
}

func GenerateLittelEndianIpv4(ipv4 string) uint32 {
	ip := net.ParseIP(ipv4).To4()
	if ip == nil {
		Logger.Fatalf("Cannot configure incorrect Ipv4 l3 address in ebPF map for kernel for deep scan")
	}
	// convert to big endian for the kernel to store dest address
	return binary.LittleEndian.Uint32(ip)
}

func ReadEbpfFromSpec(ctx context.Context, ebpfProgCode string) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(ebpfProgCode)
	if err != nil {
		return nil, err
	}
	return spec, nil
}

func ReadEbpfProgRaw(path string) ([]byte, error) {
	prog, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return prog, nil
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

func CpuArch() string {
	return runtime.GOARCH
}

func GetCPUCores() int {
	return runtime.NumCPU()
}

func VerifyKernelSupportTaskComms(processId uint32, threadId uint32) bool {
	return processId != 0 && threadId != 0
}

func int8ToStr(arr []int8) string {
	b := make([]byte, 0, len(arr))
	for _, v := range arr {
		if v == 0x00 {
			break
		}
		b = append(b, byte(v))
	}
	return string(b)
}

func GetKernelRelease() (string, error) {
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return "", err
	}
	return int8ToStr(uname.Release[:]), nil
}

func GenerateUniqueConsumerGroupId() string {
	var rd []byte = make([]byte, 6)
	if _, err := rand.Read(rd); err != nil {
		Logger.Info("Error generating the unique consumer group id ", err.Error())
		return ""
	}
	return hex.EncodeToString(rd)
}

func GetKernelReleaseSubVersions(release string) []string {
	return strings.Split(release, ".")
}

func VerifyKernelEgressTCClsactTaskCommSuppert() bool {
	release, err := GetKernelRelease()
	if err != nil {
		Logger.Info("Error getting the kernel release version ", err.Error())
		return false
	}

	release_patches := GetKernelReleaseSubVersions(release)
	majorRelease, err := strconv.Atoi(release_patches[0])
	if err != nil {
		return false
	}
	patchRelease, err := strconv.Atoi(release_patches[1])
	if err != nil {
		return false
	}
	return majorRelease >= 6 && patchRelease >= 10
}

func VerifyTcxSupportEgressLink() bool {
	release, err := GetKernelRelease()
	if err != nil {
		return false
	}
	release_patches := GetKernelReleaseSubVersions(release)
	majorRelease, err := strconv.Atoi(release_patches[0])
	if err != nil {
		return false
	}
	patchRelease, err := strconv.Atoi(release_patches[1])
	if err != nil {
		return false
	}

	return majorRelease >= TCX_KERNEL_SUPPORT_MAJOR_RELEASE &&
		patchRelease >= TCX_KERNEL_SUPPORT_SUB_RELEASE &&
		false // for now return false until kernel program with eBPF section is modified
}

func ForceGc() {
	runtime.GC()
}

/*
Removes the pinned eBPF maps mounts from bpf fs
*/
func UnPinPinnedMaps(collection *ebpf.Collection, unupinMaps []string) error {

	for _, pinMaps := range unupinMaps {
		if _, fd := collection.Maps[pinMaps]; fd {
			if collection.Maps[pinMaps].IsPinned() {
				if err := collection.Maps[pinMaps].Unpin(); err != nil {
					return err
				}
				collection.Maps[pinMaps].Close()
			}
		}
	}

	return nil
}

func GetPacketPayloadSize(layer gopacket.Layer, protocol string) int {
	return len(layer.LayerContents())
}

func KillProc(procId uint32) error {
	proc, err := os.FindProcess(int(procId))
	if err != nil {
		return err
	}

	// the agent runs in CAP_SYS_ADMIN with no internal mac via selinux policies to enforce limited security, thereby having full support to kill userspace malicious C2 implant process
	if err := proc.Kill(); err != nil {
		return err
	}

	return nil
}
