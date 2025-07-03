/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package inference

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

// works over REST for inference request/response with onnx runtime, slow relies on http/1.1 over unix l4 for ipc, major bottleneck for ipc overhead due to http serialization
// TODO: In process to replace this with ttrpc rpc over unix socket for faster stream based inference with onnx inference socket

// process and start a Unix Domain socket for inference
func GetInferenceUnixClient(isEgress bool) (*http.Client, net.Conn, error) {

	var conn net.Conn
	var err error

	// TODO: fix and load from node agent mount config
	if isEgress {
		conn, err = net.Dial("unix", utils.ONNX_INFERENCE_UNIX_SOCKET_EGRESS)
		if err != nil {
			utils.Log("Error binding the inferencce unix server socket ", err)
			return nil, nil, err
		}
	} else {
		conn, err = net.Dial("unix", utils.ONNX_INFERENCE_UNIX_SOCKET_INGRESS)
		if err != nil {
			utils.Log("Error binding the inferencce unix server socket ", err)
			return nil, nil, err
		}
	}

	if utils.DEBUG {
		utils.Log("Connected to the Inference Unix Sock ", conn.RemoteAddr())
	}

	// faster and easier layer 7 parse over unix oscket
	// the kernel all applies on netfilter conntrack layer for IPC
	client := http.Client{
		Timeout: time.Second * 20,

		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	if utils.DEBUG {
		utils.Log("Http Client build over unix server transport")
	}

	return &client, conn, nil
}
