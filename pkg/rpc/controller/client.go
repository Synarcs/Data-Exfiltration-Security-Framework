/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package controller

import (
	"context"
	"crypto/x509"
	"os"

	pb "github.com/Synarcs/Data-Exfiltration-Security-Framework/exfil_sec_api"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	CERT_DIR = "keys/certificate.pem"
)

// the service impl for all the core controller services the endpoint agent uses
type AgentControllerRpcServices struct {
	conn           *grpc.ClientConn
	CryptoServices pb.NodeAgentCryptoServiceClient
	FeatureService pb.NodeAgentFeatureServiceClient
}

func NewAgentControllerRpcServices() (*AgentControllerRpcServices, error) {
	// grpc (http2 over tcp) for connecting with remote controller
	conn, err := grpc.NewClient(":3200", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	// Implement the core crypot kernel LSM services with the controller
	cryptoService := pb.NewNodeAgentCryptoServiceClient(conn)
	featureService := pb.NewNodeAgentFeatureServiceClient(conn)

	return &AgentControllerRpcServices{
		conn:           conn,
		CryptoServices: cryptoService,
		FeatureService: featureService,
	}, nil
}

func readCerts() (credentials.TransportCredentials, error) {
	cert, err := os.ReadFile(CERT_DIR)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(&x509.Certificate{
		Raw: cert,
	})

	cred := credentials.NewClientTLSFromCert(pool, "localhost.com")
	return cred, nil
}

func (client *AgentControllerRpcServices) NodeAgentControllerEnforceSecRpc(ctx context.Context) error {

	return nil
}

func (client *AgentControllerRpcServices) CloseAgentRpcClient() error {
	if client.conn != nil {
		if err := client.conn.Close(); err != nil {
			return err
		}
	}
	return nil
}
