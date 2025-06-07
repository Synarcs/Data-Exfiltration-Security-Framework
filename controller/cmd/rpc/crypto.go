package rpc

import (
	"context"
	"fmt"

	pb "github.com/Synarcs/Data-Exfiltration-Security-Framework/exfil_sec_api"
	"go.mozilla.org/pkcs7"
)

func (rpc *NodeAgentServer) signPayload(payload []byte) ([]byte, error) {
	sign, err := pkcs7.NewSignedData(payload)
	if err != nil {
		return nil, err
	}

	if err := sign.AddSigner(rpc.CryptoConfig.Cert, rpc.CryptoConfig.Key, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, err
	}

	p7Sign, err := sign.Finish()
	if err != nil {
		return nil, err
	}

	return p7Sign, nil
}

func (rpc *NodeAgentServer) EBPFElfSignature(ctx context.Context, req *pb.ElfSignatureRequest) (*pb.ElfSignatureResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("error signing a cancelled eBPF program sign request")
	}
	requestPayload := req.EBPFProgramPayload
	signPayload, err := rpc.signPayload(requestPayload)
	if err != nil {
		return nil, err
	}

	return &pb.ElfSignatureResponse{
		Signature: signPayload,
	}, nil
}
