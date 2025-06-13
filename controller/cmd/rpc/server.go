/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package rpc

import (
	"log"
	"net"

	"github.com/Synarcs/DNSObelisk/controller/utils"
	pb "github.com/Synarcs/Data-Exfiltration-Security-Framework/exfil_sec_api"
	"google.golang.org/grpc"
)

type NodeAgentServer struct {
	pb.UnimplementedNodeAgentFeatureServiceServer
	pb.UnimplementedNodeAgentCryptoServiceServer
	ConfigChannel chan interface{}
	Server        *grpc.Server
	CryptoConfig  *utils.ControlelrCertConfig
}

func (rpc *NodeAgentServer) StartControllerRpcServer(port int,
	cotnrollerCryptoOpts *utils.ControlelrCertConfig, globalControllerErrorChan chan error) {
	list, err := net.Listen("tcp", ":3200")
	if err != nil {
		globalControllerErrorChan <- err
		return
	}

	log.Println("Node Agent RPC Server Listen on Port :: ", 3200)
	s := grpc.NewServer(grpc.EmptyServerOption{})

	rpc.Server = s
	pb.RegisterNodeAgentFeatureServiceServer(s, &NodeAgentServer{})
	if err := s.Serve(list); err != nil {
		log.Println(err.Error())
		globalControllerErrorChan <- err
		return
	}

}

func (rpc *NodeAgentServer) CloseRpcServer() {
	if rpc.Server == nil {
		return
	}

	rpc.Server.GracefulStop()
}
