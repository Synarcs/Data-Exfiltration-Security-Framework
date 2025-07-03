package netinet

import (
	"context"
	"testing"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/stretchr/testify/assert"
)

var iface *NetIface

func init() {

	utils.NewLogger(context.Background())

	iface = NewNetIface()
	iface.ReadInterfaces(false)
	iface.InitconnTrackSockHandles()
	iface.ReadRoutes()
}

func TestRootNetdevExist(t *testing.T) {
	assert := assert.New(t)

	if len(iface.PhysicalLinks) == 0 {
		assert.Fail("Error cannot process the agent prior required physical netlink interfaces exist at endpoint ")
	}

	assert.True(true)
}

func TestRouteGateway(t *testing.T) {
	assert := assert.New(t)

	assert.NotEmpty(iface.PhysicalNodeBridgeIpv4)
	if len(iface.ConnTrackNsHandles) == 0 {
		assert.Fail("error the conntract handles per netns created by the node agent cannot be empty")
	}

	assert.True(true)
}
