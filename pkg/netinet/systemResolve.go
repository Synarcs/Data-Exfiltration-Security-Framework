/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package netinet

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strings"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

type DnsResolverServerConfig struct {
	Ipv4              []net.IP
	Ipv6              []net.IP
	IsLoopBackEnabled bool // any stub resolver for system resolve
}

const (
	SYSTEMD_RESOLVED_PATH = "/etc/resolv.conf"
)

func ReadDNSResolvedConf() (*DnsResolverServerConfig, error) {
	// we dont need parallel i/o since the dns resolv is not much huge file
	fd, err := os.Open(SYSTEMD_RESOLVED_PATH)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		utils.Logger.Error("Error Reading the file descriptor for resolv.conf", err)
		return nil, err
	}
	defer fd.Close()

	line := bufio.NewScanner(fd)
	dnsResolver := DnsResolverServerConfig{}

	for line.Scan() {
		info := line.Text()
		if strings.HasPrefix(info, "nameserver") {
			dnsServer := strings.Split(info, " ")
			isIpv4 := net.ParseIP(dnsServer[1]).To4()
			if isIpv4 != nil {
				dnsResolver.Ipv4 = append(dnsResolver.Ipv4, isIpv4) // only take the ipv4 dns address with highest priority in systemd resolved
				if isIpv4.String() == "127.0.0.53" {
					dnsResolver.IsLoopBackEnabled = true
				}
			} else {
				ipv6 := net.ParseIP(dnsServer[1]).To16()
				if ipv6 != nil {
					dnsResolver.Ipv6 = append(dnsResolver.Ipv6, ipv6)
				}
			}
		}
	}
	return &dnsResolver, nil
}
