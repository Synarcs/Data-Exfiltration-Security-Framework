package conntrack

import (
	"log"
	"net/netip"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
)

type ConntrackSock struct {
	ConntrackSock *conntrack.Conn
}

type ConntrackCleanEntry struct {
	SrcAddress netip.Addr
	DestAddres netip.Addr
	Protocol   uint8
	SrcPort    uint16
	Destport   uint16
}

func NewContrackSock(netns int) (*ConntrackSock, error) {
	c, err := conntrack.Dial(&netlink.Config{
		NetNS: 0,
	})
	if err != nil {
		log.Println("Error Getting the the Contrack Netlink Socket")
		return nil, err
	}

	log.Println("Init complete for Conntrakc Socket over Netlink ..")

	if utils.DEBUG {
		stats, _ := c.Stats()
		for _, stat := range stats {
			log.Println("Successfully Booted with Kernel Conntrack Fd over Netlink sock", stat.String())
		}
	}

	return &ConntrackSock{
		ConntrackSock: c,
	}, nil
}

func (c *ConntrackSock) CleanCloneDanglingEntries(flowEntry *ConntrackCleanEntry) error {
	flow := conntrack.Flow{
		TupleOrig: conntrack.Tuple{
			IP: conntrack.IPTuple{
				SourceAddress:      flowEntry.SrcAddress, // IPv6 address
				DestinationAddress: flowEntry.DestAddres, // IPv6 address
			},
			Proto: conntrack.ProtoTuple{
				Protocol:        flowEntry.Protocol,
				SourcePort:      flowEntry.SrcPort,
				DestinationPort: flowEntry.Destport,
			},
		},
	}

	c.ConntrackSock.Delete(flow)
	return nil
}

func (c *ConntrackSock) CloseConntrackNetlinkSock() error {
	if err := c.ConntrackSock.Close(); err != nil {
		return err
	}
	return nil
}
