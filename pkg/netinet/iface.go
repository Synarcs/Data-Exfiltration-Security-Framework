package netinet

import (
	"fmt"
	"log"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type NetIface struct {
	links  []netlink.Link
	routes map[string][]netlink.Route
}

func (nf *NetIface) ReadInterfaces() error {
	links, err := netlink.LinkList()
	if err != nil {
		log.Println(err)
		return err
	}
	customLinks := make([]netlink.Link, 0)

	for _, link := range links {
		if link.Attrs().Name == "enp0s1" {
			fmt.Println("found a link ", link.Attrs().Name)
			customLinks = append(customLinks, link)
		}
	}
	fmt.Println("the custom link to process are ", customLinks)
	nf.links = links
	return nil
}

func (nf *NetIface) ReadRoutes() error {

	for _, link := range nf.links {
		routes, err := netlink.RouteList(link, unix.ETH_P_ALL)
		if err != nil {
			log.Println(err)
			return err
		}
		nf.routes[link.Attrs().Name] = routes
	}
	return nil
}
