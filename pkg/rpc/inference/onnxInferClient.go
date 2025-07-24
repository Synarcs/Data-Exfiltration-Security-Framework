/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package inference

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	pb "github.com/Synarcs/Data-Exfiltration-Security-Framework/exfil_sec_api"
	rpc "github.com/Synarcs/Data-Exfiltration-Security-Framework/exfil_sec_api/consts"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"google.golang.org/grpc/credentials/insecure"
)

type DNSOnnxInferenceService struct {
	conn           *grpc.ClientConn
	dnsInferClient pb.DNSOnnxInferenceServiceClient
}

type OnxxInferenceServer struct {
	Path string
	Pid  int
}

var (
	DELAY_PROCESS_ATTACH_TIME = time.Second * 3 // time for the child fork owned by the endpoint agent to boot the inference server at the endpoint
)

func NewOnxxInferenceServer() *OnxxInferenceServer {
	return &OnxxInferenceServer{}
}

func (server *OnxxInferenceServer) StartRemoteOnnxInferenceListener(onnxInferServerBinPath string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	releaseWaitLock := make(chan bool)
	utils.Log("starting the remote grpc onnx inference server .....", onnxInferServerBinPath)
	if _, err := os.Stat(onnxInferServerBinPath); err != nil {
		return err
	}

	cmd := exec.Command(onnxInferServerBinPath)
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// let the endpoint agent spawn child process to start the onnx inference server
	if err := cmd.Start(); err != nil {
		utils.Log("error in starting inference server ", stderr.String())
		return err
	}

	time.AfterFunc(time.Second*3, func() {
		releaseWaitLock <- true
	})

	<-releaseWaitLock
	server.Pid = cmd.Process.Pid
	utils.Log(stdout.String())
	return nil
}

func (server *OnxxInferenceServer) StopRemoteOnnxInferenceListener() error {
	utils.Log("stopping the remote grpc onnx inference server .....")
	if err := utils.KillProc(uint32(server.Pid)); err != nil {
		return err
	}
	return nil
}

func NewNodeAgentUnixCLISocket() (*DNSOnnxInferenceService, error) {
	utils.Log("init the onnx inference grpc client for endpoint agent")
	conn, err := grpc.NewClient(fmt.Sprintf("unix:%s", rpc.ONNX_INFER_UNIX_MNT), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	if pb.NewDNSOnnxInferenceServiceClient(conn) == nil {
		return nil, fmt.Errorf("error create new inference client daemon")
	}
	return &DNSOnnxInferenceService{
		conn:           conn,
		dnsInferClient: pb.NewDNSOnnxInferenceServiceClient(conn),
	}, nil
}

func (infer *DNSOnnxInferenceService) GetInferenceServiceVersion(ctx context.Context) (string, error) {
	versions, err := infer.dnsInferClient.VersionInfo(ctx, &emptypb.Empty{})
	if err != nil {
		utils.Logger.Error(err)
		return "", err
	}
	return versions.Version, err
}

func (infer *DNSOnnxInferenceService) reshapeFeatures(features [][]float32, reshappedFeatures []*pb.DnsFeatures) []*pb.DnsFeatures {
	for _, feature := range features {
		reshappedFeatures = append(reshappedFeatures, &pb.DnsFeatures{
			Features: feature,
		})
	}
	return reshappedFeatures
}

func (infer *DNSOnnxInferenceService) EgressInference(ctx context.Context, features [][]float32) (*pb.DnsInferenceResponseEgress, error) {
	reshappedFeatures := infer.reshapeFeatures(features, []*pb.DnsFeatures{})

	resp, err := infer.dnsInferClient.EgressInfer(ctx, &pb.DnsInferenceRequest{
		Reshaped: reshappedFeatures,
	})
	if err != nil {
		utils.Logger.Error("Egress inference failed: ", err.Error())
	}
	return resp, err
}

func (infer *DNSOnnxInferenceService) IngressInference(ctx context.Context, features [][]float32) (*pb.DnsInferenceResponseIngress, error) {
	reshappedFeatures := infer.reshapeFeatures(features, []*pb.DnsFeatures{})

	resp, err := infer.dnsInferClient.IngressInfer(ctx, &pb.DnsInferenceRequest{
		Reshaped: reshappedFeatures,
	})
	if err != nil {
		utils.Logger.Error("Ingress inference failed: ", err.Error())
	}
	return resp, err
}

func (infer *DNSOnnxInferenceService) CloseRpcInferenceServer() error {
	if err := infer.conn.Close(); err != nil {
		return err
	}
	return nil
}
