package model

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
)

// process and start a Unix Domain socket for inference
func GetInferenceUnixClient(isEgress bool) (*http.Client, net.Conn, error) {

	var conn net.Conn
	var err error

	if isEgress {
		conn, err = net.Dial("unix", utils.ONNX_INFERENCE_UNIX_SOCKET_EGRESS)
		if err != nil {
			log.Println("Error binding the inferencce unix server socket ", err)
			return nil, nil, err
		}
	} else {
		conn, err = net.Dial("unix", utils.ONNX_INFERENCE_UNIX_SOCKET_INGRESS)
		if err != nil {
			log.Println("Error binding the inferencce unix server socket ", err)
			return nil, nil, err
		}
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
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	log.Println("Inference Unix Socket Listenning")

	return &client, conn, nil
}
