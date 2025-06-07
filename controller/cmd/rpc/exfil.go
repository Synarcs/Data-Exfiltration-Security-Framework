package rpc

import (
	"context"
	"time"

	pb "github.com/Synarcs/Data-Exfiltration-Security-Framework/exfil_sec_api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

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
