package rpc

import (
	"context"
	"log"
	"net"
	"strings"
	"time"

	pb "github.com/Data-Exfiltration-Security-Framework/pkg/rpc/pb"
	"google.golang.org/grpc"
)

type NodeAgentService struct {
	pb.UnimplementedNodeAgentServiceServer
	ConfigChannel chan interface{}
}

func (s *NodeAgentService) GetExfilDomains(context.Context, *pb.ExfilDomains) (*pb.ExfilDomains, error) {
	maliciousDomain := "google.com"
	return &pb.ExfilDomains{
		Domain:      maliciousDomain,
		Tld:         strings.Split(maliciousDomain, ".")[1],
		TotalLength: int64(len(maliciousDomain)),
	}, nil
}

func (s *NodeAgentService) GenExfilDomainsLength(ctx context.Context, req *pb.ExfilDomains) (*pb.ExfilDomainsLength, error) {
	return &pb.ExfilDomainsLength{Len: int64(len(req.Domain))}, nil
}

func (s *NodeAgentService) DomainStream(req *pb.ExfilDomainsLength, stream grpc.ServerStreamingServer[pb.ExfilDomains]) error {
	maliciousDomain := "sample.com"
	for {
		stream.Send(&pb.ExfilDomains{
			Domain:      time.Now().GoString(),
			Tld:         strings.Split(maliciousDomain, ".")[1],
			TotalLength: req.Len,
		})
		time.Sleep(time.Second)
	}
}

func (rpc *NodeAgentService) Server() {
	list, err := net.Listen("tcp", ":3200")
	if err != nil {
		panic(err.Error())
	}

	log.Println("Node Agent RPC Server Listen on POrt :: ", 33333)
	s := grpc.NewServer(grpc.EmptyServerOption{})

	pb.RegisterNodeAgentServiceServer(s, &NodeAgentService{})
	if err := s.Serve(list); err != nil {
		log.Println(err.Error())
		panic(err.Error())
	}

}
