package rpc

import (
	"context"
	"net"
	"time"

	pb "github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/rpc/pb"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
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

func (rpc *NodeAgentServer) StartAgentStreamServer() {
	list, err := net.Listen("tcp", ":3200")
	if err != nil {
		panic(err.Error())
	}

	utils.Log("Node Agent RPC Server Listen on POrt :: ", 3200)
	s := grpc.NewServer(grpc.EmptyServerOption{})

	rpc.Server = s
	pb.RegisterNodeAgentFeatureServiceServer(s, &NodeAgentServer{})
	if err := s.Serve(list); err != nil {
		utils.Log(err.Error())
		panic(err.Error())
	}

}

func (rpc *NodeAgentServer) CloseRpcServer() {
	if rpc.Server == nil {
		return
	}

	rpc.Server.GracefulStop()
}
