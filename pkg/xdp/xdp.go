package xdp

import "fmt"

type XdpHandler struct {
	NetIfIndex int // stores the ingress rx/wx interface index over non offloaded NIC
}

func (xdp *XdpHandler) LinkXdp(xdpHandle func(interfaceId *int) error) func(id int) error {
	return func(id int) error {
		if id < 0 {
			return fmt.Errorf("Nehative Size Index for Netlink Socket")
		}
		return nil
	}
}
