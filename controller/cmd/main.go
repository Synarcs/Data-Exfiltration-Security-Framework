/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/Synarcs/DNSObelisk/controller/conf"
	"github.com/Synarcs/DNSObelisk/controller/consumer"
	"github.com/Synarcs/DNSObelisk/controller/rpc"
	"github.com/Synarcs/DNSObelisk/controller/utils"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
)

const (
	CNI_CONTROLLER_SOCK = "/tmp/controller-cni.sock"
	Version             = "0.0.1"
)

func LoadConfigFromController() (*conf.GlobalControllerConfig, *consumer.StreamConsumer) {
	if err := consumer.VerifyControllerSockHealthy(); err != nil {
		panic(err.Error())
	}
	globalControllerConfig, streamConsumerConfig := consumer.InitControllerBrokerConfig()
	if globalControllerConfig == nil {
		panic(fmt.Errorf("Cannot boot the cni controller config unless the parent controller is healthy"))
	}
	return globalControllerConfig, streamConsumerConfig
}

// Start the local CA for processing the request and signing eBPF program raw payload
// this can be replaced with any CA and trust store at global level for signing request
func InitLocalCa() (*utils.ControlelrCertConfig, error) {
	key := &csr.KeyRequest{
		A: "ecdsa",
		S: 1 << 8,
	}

	// generate csr
	csr := &csr.CertificateRequest{
		CN:         "synarcs.controlelr",
		KeyRequest: key,
		Names: []csr.Name{
			{O: "controller eBPF security"},
		},
		CA: &csr.CAConfig{
			Expiry: fmt.Sprintf("%dh", 365*24),
		},
	}

	cert, _, privateKey, err := initca.New(csr)

	block, _ := pem.Decode(cert)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	pblock, _ := pem.Decode(privateKey)
	if pblock == nil || pblock.Type != "EC PRIVATE KEY" {
		return nil, err
	}

	pKey, err := x509.ParseECPrivateKey(pblock.Bytes)
	if err != nil {
		return nil, err
	}

	return &utils.ControlelrCertConfig{
		Cert:     certificate,
		Key:      pKey,
		Duration: 365 * 24,
		KeySize:  (1 << 8),
	}, nil

}

func main() {
	log.Print("Add the required network policies enforced by the eBPF Node Agent to controller for dynamic network policies for remote c2 servers")
	var opts conf.ControllerCliOpts
	flag.IntVar(&opts.Port, "rpc_port", 3200, "Port for handling data plane sign requests for eBPF bytecode")
	flag.Parse()
	flag.Usage = func() {
		flag.PrintDefaults()
	}

	controllerCa, err := InitLocalCa()
	if err != nil {
		log.Println("Cannot start controller unless the the controller has started local or connected to remote CA")
		panic(err.Error())
	}

	sock, err := net.Listen("unix", CNI_CONTROLLER_SOCK)

	controlSigKillChan := make(chan os.Signal, 1)
	globalControllerErrorChan := make(chan error)
	signal.Notify(controlSigKillChan, syscall.SIGINT, syscall.SIGTERM)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	if err != nil {
		log.Printf("Error in starting the controller CNI server %s", err.Error())
	}

	// read the controller config from the kafka consumer for infer controller events
	// globalControllerConfig, streamConsumer := LoadConfigFromController()

	configRpcChan := make(chan interface{})
	nodeAgentServer := rpc.NodeAgentServer{
		ConfigChannel: configRpcChan,
		CryptoConfig:  controllerCa,
	}

	go nodeAgentServer.StartControllerRpcServer(opts.Port, controllerCa, globalControllerErrorChan)


	defer func() {
		log.Println("Closing the controller unix socket stream Consumer")
		// streamConsumer.CloseConsumer()
		nodeAgentServer.CloseRpcServer()

		log.Println("Closing the Unix Socket Server for the controller")
		// server.Close()
		if sock != nil {
			sock.Close()
		}

		if _, err := os.Stat(CNI_CONTROLLER_SOCK); err == nil {
			if err := os.Remove(CNI_CONTROLLER_SOCK); err != nil {
				log.Println("Error removing mounted CNI socket:", err)
			}
		}
	}()

	for {
		select {
		case err := <-globalControllerErrorChan:
			log.Println("Received error  ", err.Error())
			return
		case <-controlSigKillChan:
			log.Println("the CNI socket would be closed on the controller cleanning all controller sock")
			cancel()
			return
		}
	}
}
