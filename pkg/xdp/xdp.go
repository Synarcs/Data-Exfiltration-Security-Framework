package xdp

import "fmt"

func LinkXdp(xdpHandle func(interfaceId *int) error) func(id int) error {
	return func(id int) error {
		if id < 0 {
			return fmt.Errorf("Nehative Size Index for Netlink Socket")
		}
		return nil
	}
}
