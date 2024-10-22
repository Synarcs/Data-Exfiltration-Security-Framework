package model

import (
	"context"
	"log"
	"net"
	"net/http"
	"time"
)

const (
	ONNX_INFERENCE_UNIX_SOCKET = "/run/onnx-inference.sock"
)

// process and start a Unix Domain socket for inference
func GetInferenceUnixClient() (*http.Client, net.Conn, error) {

	conn, err := net.Dial("unix", ONNX_INFERENCE_UNIX_SOCKET)
	if err != nil {
		log.Println("Error binding the inferencce unix server socket ", err)
		return nil, nil, err
	}

	log.Println("Connected to the Inference Unix Sock ", conn.RemoteAddr())

	// faster and easier layer 7 parse over unix oscket
	// the kernel all applies on netfilter conntrack layer for IPC
	client := http.Client{
		Timeout: time.Second * 20,

		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
			DisableKeepAlives: true,
		},
	}
	log.Println("Inference Unix Socket Listenning")

	return &client, conn, nil
}
