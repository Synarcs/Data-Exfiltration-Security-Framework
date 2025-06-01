/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package rpc

import (
	"context"
	"log"
	"net"
	"time"

	pb "github.com/Synarcs/Data-Exfiltration-Security-Framework/exfil_sec_api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type NodeAgentServer struct {
	pb.UnimplementedNodeAgentFeatureServiceServer
	pb.UnimplementedNodeAgentCryptoServiceServer
	ConfigChannel chan interface{}
	Server        *grpc.Server
}

func (s *NodeAgentServer) GetExfilDomains(domain *pb.ExfilDomains, stream grpc.ServerStreamingServer[pb.ExfilDomains]) error {
	for {
		if err := stream.Send(&pb.ExfilDomains{
			Domain:         domain.Domain,
			Tld:            domain.Tld,
			FeatureVectors: []uint32{},
			Status: map[string]pb.DNS_MALICIOUS_FLAGS{
				domain.Domain: pb.DNS_MALICIOUS_FLAGS_MALICIOUS,
			},
		}); err != nil {
			return err
		}
		time.Sleep(time.Second)
	}
}

func (s *NodeAgentServer) BidirstreamLimits(stream grpc.BidiStreamingServer[pb.ExfillSecurityLengthLimits,
	pb.ExfillSecurityLengthLimits]) error {
	return status.Errorf(codes.Unimplemented, "method BidirstreamLimits not implemented")
}

func (s *NodeAgentServer) GenExfilDomainsLength(ctx context.Context, domain *pb.ExfilDomains) (*pb.ExfilDomainsLength, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GenExfilDomainsLength not implemented")
}

func (rpc *NodeAgentServer) StartControllerRpcServer() {
	list, err := net.Listen("tcp", ":3200")
	if err != nil {
		panic(err.Error())
	}

	log.Println("Node Agent RPC Server Listen on POrt :: ", 3200)
	s := grpc.NewServer(grpc.EmptyServerOption{})

	rpc.Server = s
	pb.RegisterNodeAgentFeatureServiceServer(s, &NodeAgentServer{})
	if err := s.Serve(list); err != nil {
		log.Println(err.Error())
		panic(err.Error())
	}

}

func (rpc *NodeAgentServer) CloseRpcServer() {
	if rpc.Server == nil {
		return
	}

	rpc.Server.GracefulStop()
}
