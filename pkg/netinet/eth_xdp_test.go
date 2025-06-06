/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package netinet

import (
	"fmt"
	"testing"

	"github.com/asavie/xdp"
	"github.com/stretchr/testify/assert"
)

func TestXDPEthtoollQueues(t *testing.T) {

	queue, err := GetCurrentTXQueues("enp0s1")
	if err != nil {
		t.Error("Error getting the number of queues , AF_XDP socket is not supported on this interface")
	}

	t.Log("XDP sockets are supported on this interface", queue)
}

func TestXskSockCreate(t *testing.T) {
	assert := assert.New(t)
	// phsyical wire of the netdev
	xsk, err := xdp.NewSocket(2, 0, nil)
	if err != nil {
		assert.Fail(err.Error())
	}

	// slots downstream for xsk framew
	desc := xsk.GetDescs(xsk.NumFreeTxSlots())
	for _ = range desc {
	}

	fmt.Println(xsk.FD())
}
