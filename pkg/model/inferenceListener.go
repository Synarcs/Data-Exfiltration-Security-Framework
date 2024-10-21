package model

import (
	"log"
	"net"
)

const (
	ONNX_INFERENCE_UNIX_SOCKET = "/run/onnx-inference.sock"
)

// process and start a Unix Domain socket for inference
func ListenInferenceUnixClient() (*net.Conn, error) {

	listen, err := net.Dial("unix", ONNX_INFERENCE_UNIX_SOCKET)
	if err != nil {
		log.Println("Error binding the inferencce unix server socket ", err)
		return nil, err
	}

	log.Println("Inference Unix Socket Listenning")

	return &listen, nil
}
