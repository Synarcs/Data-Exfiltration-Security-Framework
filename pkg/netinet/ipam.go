package netinet

import (
	"context"
	"log"
	"net"
)

// use netlink to find discrete ipam over all brides and links on the device for discete IPAM over the virtual NS and bridges ofr the Deep scan

type IpamBlock struct {
	CidrRange   net.IP
	SubnetRange int
	IsIpv4      bool
}

func (ipam *NetIface) LookUpdiscreteIpv4(ctx context.Context) (*IpamBlock, error) {
	routes := ipam.AddrV4
	for _, route := range routes {
		log.Println(route)
	}
	return nil, nil
}

func (ipam *NetIface) LookUpdiscreteIpv6(ctx context.Context) (*IpamBlock, error) {
	routes := ipam.AddrV4
	for _, route := range routes {
		log.Println(route)
	}
	return nil, nil
}
