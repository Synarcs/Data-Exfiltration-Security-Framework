package netinet

import (
	"bufio"
	"log"
	"net"
	"os"
	"strings"
)

type DnsResolverServer struct {
	Ipv4 net.IP
	Ipv6 net.IP
}

func ReadPackageConfig() (*DnsResolverServer, error) {
	// we dont need parallel i/o since the dns resolv is not much huge file
	fd, err := os.Open("/etc/resolv.conf")
	if err != nil {
		log.Println("Error Reading the fild descriptor for resolv.conf")
		return nil, err
	}

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
