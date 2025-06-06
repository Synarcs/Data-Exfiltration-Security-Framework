/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/conf"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// only covers the integration test required for the eBPF node agent to boot up at the endpoint

// convers all the integration test for the user space entire node agent with kernel code, and kernel compatibility

var linkHandler netinet.NetIface

type TestConifgOptions struct {
	agentConfigPath string
}

var configOpts TestConifgOptions

// cover most of the integration test with kernel netlink sockets / interfaces and ebpf  compiled programs loader to be inject into the kernel network stack
type KernelEbpfMockInjectors struct {
	mock.Mock
}

type NodeAgentMockInjectors struct {
	mock.Mock
}

func (k *KernelEbpfMockInjectors) TestKernelTCEbpfInject(prog string) error {
	k.Called(prog)
	return nil
}

func (mock *NodeAgentMockInjectors) ReadGlobalNodeAgentConfig() (*conf.NodeAgentConfig, error) {
	args := mock.Called()
	return args.Get(0).(*conf.NodeAgentConfig), args.Error(1)
}

func init() {
	for i := 1; i < len(os.Args); i++ {
		if strings.HasPrefix(os.Args[i], "-test") && strings.Split(os.Args[i], ".")[1] == "config" {
			configOpts.agentConfigPath = strings.Split(os.Args[i], ".")[1]
		}
	}
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func TestMain(t *testing.M) {
	utils.NewLogger(context.Background())
	utils.Log("Starting the test for kernel netlink sockets and interfaces  ....")

	linkHandler = netinet.NetIface{}
	linkHandler.ReadInterfaces(false)
	linkHandler.ReadRoutes()
	linkHandler.InitconnTrackSockHandles()

	os.Exit(t.Run())
}

func TestKernelEbpfProgPath(t *testing.T) {
	assert := assert.New(t)
	kernelProgs := map[string]bool{
		"bridge_egress.o": true, // kernel bridge egress filters
		"bridge_ing.o":    true,
		"netlink.o":       true,
		"tc.o":            true, // root kernel egress tc filter clsact for dns egress exfil control on host net_device
		"tun.o":           true, // tun_chr_open (tun/tap) kprobe
		"sock.o":          true, // sock_ops_filter
		"lsm_bpf.o":       true, // lsm bpf hooks integrated for BPF_PROG_LOAD
	}

	ff, err := os.ReadDir("ebpf")
	if err != nil {
		assert.Fail("Error the required eBPF programs not found")
	}
	for _, files := range ff {
		delete(kernelProgs, files.Name())
	}
	if len(kernelProgs) != 0 {
		assert.Fail("All the required kernel programs not found for the eBPF node agent")
	}

	assert.True(true)
}

// Add netiface netlink test for more deep coverage of tests
func TestNetworkInterfaces(t *testing.T) {
	assert := assert.New(t)

	if len(linkHandler.PhysicalLinks) == 0 {
		assert.Fail("Error the node agent cannot boot and inject kernel programs until the required netlink links are found")
	}
	assert.True(true)
}

func TestOnnxDnsUnixMounts(t *testing.T) {
	agentOnnxMountPaths := "/run/dnsobelisk"
	dirs, err := os.ReadDir(agentOnnxMountPaths)
	if err != nil {
		t.Fatalf("Error the required onnx unix mount paths not found %s", agentOnnxMountPaths)
	}
	assert := assert.New(t)
	expectCt := 2
	onnxMountsct := 0

	for _, dir := range dirs {
		// check for both ingress and egress onnx inference mounts
		if strings.Contains(dir.Name(), "onnx-inference") {
			onnxMountsct++
		}
	}

	assert.EqualValues(expectCt, onnxMountsct)
}

func TestBridgeInterfaces(t *testing.T) {
	assert := assert.New(t)

	requiredNodeAgentBridgeLinks := map[string]bool{
		"br0": true, "nx-br0": true,
	}

	if len(linkHandler.BridgeLinks) > 0 {
		for _, link := range linkHandler.BridgeLinks {
			delete(requiredNodeAgentBridgeLinks, link.Attrs().Name)
		}
		if len(requiredNodeAgentBridgeLinks) == 0 {
			assert.True(true)
			return
		}
	}
	assert.Fail("Error Required Kernel Bridge interfaces not found managed by the node agent")
}

func getConfigAgentPath() string {
	var path string
	if configOpts.agentConfigPath != "" {
		path = configOpts.agentConfigPath
	} else {
		path = "config.yaml"
	}
	return path
}

func TestRequireNodeAgentConfig(t *testing.T) {
	path := getConfigAgentPath()
	if _, err := os.Stat(path); err != nil {
		assert.Fail(t, "Error the Node Agent cannot be booted without loadable config ...")
	}
	assert.True(t, true)
}

func TestEachNodeAgentConfigAddress(t *testing.T) {
	assert := assert.New(t)

	path := getConfigAgentPath()

	var config conf.AgentConfig = &conf.Config{}
	config.ReadNodeAgentConfig(path)
	globalConfig := config.GetAgentConfig()

	var wg sync.WaitGroup

	wg.Add(3)
	go func() {
		defer wg.Done()
		// verify connection upstream dns server
		_, err := net.Dial("udp", fmt.Sprintf("%s:%d", globalConfig.DNSServer.Ip, 53))
		if err != nil {
			utils.Log("error connecting to dns server")
			assert.Error(err)
		}
	}()

	go func() {
		defer wg.Done()
		// verify connection upstream metric server (prometheus)
		_, err := net.Dial("tcp", fmt.Sprintf("%s:%s", globalConfig.MetricServer.Ip, globalConfig.MetricServer.Port))
		if err != nil {
			assert.Error(err)
		}
	}()

	go func() {
		defer wg.Done()
		// verify connection upstream metric explore server (grafana)
		_, err := net.Dial("tcp", fmt.Sprintf("%s:%s", globalConfig.GrafanaServer.Ip, globalConfig.MetricServer.Port))
		if err != nil {
			assert.Error(err)
		}
	}()

	wg.Wait()
	assert.True(true)
}

func TestAgentBenignDomainCacheLoaded(t *testing.T) {
	assert := assert.New(t)

	_, err := utils.VerifyTopDomainsData()
	if err != nil {
		assert.Fail(err.Error())
	}
	assert.True(true)
}

func TestControllerRpcReach(t *testing.T) {
	assert := assert.New(t)
	path := getConfigAgentPath()

	var agentConfigLoader conf.AgentConfig = &conf.Config{}
	if err := agentConfigLoader.ReadNodeAgentConfig(path); err != nil {
		panic(err.Error())
	}

	assert.True(true)
}

func TestNodeAgentStreamProducerConn(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	ctx, _ = context.WithTimeout(ctx, time.Second*3)

	path := getConfigAgentPath()

	var config conf.AgentConfig = &conf.Config{}

	config.ReadNodeAgentConfig(path)
	globalConfig := config.GetAgentConfig()
	globalKakfBrokerConfig := stream.InitBrokerConfig(globalConfig, nil)

	streamProducer := &stream.StreamProducer{
		KafkaBrokerConfig: globalKakfBrokerConfig,
	}

	if err := streamProducer.NewStreamKafkaProducer(ctx); err != nil {
		utils.Log("The Remote Kafka stream broker not found for threat stream analytics continue...", err)
		assert.Fail(err.Error())
	}

	assert.True(true)
}

func TestNetworkNamespaceCreation(t *testing.T) {
	assert := assert.New(t)
	requiredLabeledNamespaces := map[string]bool{
		"sx1": true,
		"sx2": true,
		"sx3": true,
	}
	if nsMounts, err := os.ReadDir("/run/netns/"); err != nil {
		assert.Fail("Error the required network namespaces not found, eBPF TC kernel require it for TC_forward and DNAT ")
	} else {
		for _, file := range nsMounts {
			delete(requiredLabeledNamespaces, file.Name())
		}
		assert.Equal(len(requiredLabeledNamespaces), 0)
	}
}

func TestMasterNetworkBridges(t *testing.T) {
	assert := assert.New(t)
	bridges := map[string]bool{
		"nx-br0": true,
		"br0":    true,
	}

	for _, brifr := range linkHandler.BridgeLinks {
		delete(bridges, brifr.Attrs().Name)
	}

	//  ensure all the required network master l3, l4 veth network bridges are created
	assert.Equal(len(bridges), 0)
}

func TestAgentConfigLoader(t *testing.T) {
	nodeAgentLoaderMock := new(NodeAgentMockInjectors)

	nodeAgentLoaderMock.IsMethodCallable(t, "ReadGlobalNodeAgentConfig")

	nodeAgentLoaderMock.On("ReadGlobalNodeAgentConfig").Return(&conf.NodeAgentConfig{}, nil)

	config, err := nodeAgentLoaderMock.ReadGlobalNodeAgentConfig()

	assert.Nil(t, err)
	assert.Equal(t, reflect.DeepEqual(config, &conf.NodeAgentConfig{}), true)
	nodeAgentLoaderMock.AssertExpectations(t)
}
