/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package netinet

import (
	"testing"
)

func TestXDPEthtoollQueues(t *testing.T) {

	queue, err := GetCurrentTXQueues("enp0s1")
	if err != nil {
		t.Error("Error getting the number of queues , AF_XDP socket is not supported on this interface")
	}

	t.Log("XDP sockets are supported on this interface", queue)
}
