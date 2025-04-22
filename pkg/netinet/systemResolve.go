package netinet

import (
	"bufio"
	"errors"
	"net"
	"os"
	"strings"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

type DnsResolverServer struct {
	Ipv4 net.IP
	Ipv6 net.IP
}

const (
	SYSTEMD_RESOLVED_PATH = "/etc/resolv.conf"
)

func ReadDNSResolvedConf() (*DnsResolverServer, error) {
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
	dnsResolver := DnsResolverServer{}

	for line.Scan() {
		info := line.Text()
		if strings.HasPrefix(info, "nameserver") {
			dnsServer := strings.Split(info, " ")
			isIpv4 := net.ParseIP(dnsServer[1]).To4()
			if isIpv4 != nil {
				if dnsResolver.Ipv4 == nil {
					dnsResolver.Ipv4 = isIpv4 // only take the ipv4 dns address with highest priority in systemd resolved
				}
			} else {
				dnsResolver.Ipv6 = net.ParseIP(dnsServer[1]).To16()
			}
		}
	}
	return &dnsResolver, nil
}
