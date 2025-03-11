package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var linkHandler netinet.NetIface

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

func (conf *NodeAgentMockInjectors) ReadGlobalNodeAgentConfig() (*utils.NodeAgentConfig, error) {
	args := conf.Called()
	return args.Get(0).(*utils.NodeAgentConfig), args.Error(1)
}

func TestMain(t *testing.M) {
	log.Println("Starting the test for kernel netlink sockets and interfaces  ....")

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
		"tun.o":           true, // root kernel egress tc filter clsact for dns egress exfil control on tunnel interfaces
	}

	ff, err := os.ReadDir("ebpf")
	if err != nil {
		assert.Fail("Error the required eBPF programs not found")
	}
	for _, files := range ff {
		if fd := kernelProgs[files.Name()]; fd {
			delete(kernelProgs, files.Name())
		}
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

func TestBridgeInterfaces(t *testing.T) {
	assert := assert.New(t)

	requiredNodeAgentBridgeLinks := map[string]bool{
		"br0": true, "nx-br0": true,
	}

	if len(linkHandler.BridgeLinks) > 0 {
		for _, link := range linkHandler.BridgeLinks {
			if _, ok := requiredNodeAgentBridgeLinks[link.Attrs().Name]; ok {
				delete(requiredNodeAgentBridgeLinks, link.Attrs().Name)
			}
		}
		if len(requiredNodeAgentBridgeLinks) == 0 {
			assert.True(true)
			return
		}
	}
	assert.Fail("Error Required Kernel Bridge interfaces not found managed by the node agent")
}

func TestRequireNodeAgentConfig(t *testing.T) {
	if _, err := os.Stat("config.yaml"); err != nil {
		assert.Fail(t, "Error the Node Agent cannot be booted without loadable config ...")
	}
	assert.True(t, true)
}

func TestEachNodeAgentConfigAddress(t *testing.T) {
	assert := assert.New(t)
	config, err := ReadGlobalNodeAgentConfig()
	if err != nil {
		assert.Error(err)
	}

	// verify connection upstream dns server
	_, err = net.Dial("udp", fmt.Sprintf("%s:%d", config.DNSServer.Ip, 53))
	if err != nil {
		assert.Error(err)
	}

	// verify connection upstream metric server (prometheus)
	_, err = net.Dial("tcp", fmt.Sprintf("%s:%s", config.MetricServer.Ip, config.MetricServer.Port))
	if err != nil {
		assert.Error(err)
	}

	// verify connection upstream metric explore server (grafana)
	_, err = net.Dial("tcp", fmt.Sprintf("%s:%s", config.GrafanaServer.Ip, config.MetricServer.Port))
	if err != nil {
		assert.Error(err)
	}

	assert.True(true)

}

func TestNodeAgentStreamProducerConn(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()
	ctx, _ = context.WithTimeout(ctx, time.Second*3)
	globalConfig, err := ReadGlobalNodeAgentConfig()
	globalKakfBrokerConfig := stream.InitBrokerConfig(globalConfig)
	if err != nil {
		panic(err.Error())
	}

	streamProducer := &stream.StreamProducer{
		KafkaBrokerConfig: globalKakfBrokerConfig,
	}

	if err := streamProducer.GenerateStreamKafkaProducer(ctx); err != nil {
		log.Println("The Remote Kafka stream broker not found for threat stream analytics continue...", err)
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

func TestAgentConfigLoader(t *testing.T) {
	nodeAgentLoaderMock := new(NodeAgentMockInjectors)
	nodeAgentLoaderMock.IsMethodCallable(t, "ReadGlobalNodeAgentConfig")

	nodeAgentLoaderMock.On("ReadGlobalNodeAgentConfig").Return(&utils.NodeAgentConfig{}, nil)

	config, err := nodeAgentLoaderMock.ReadGlobalNodeAgentConfig()

	assert.Nil(t, err)
	assert.Equal(t, reflect.DeepEqual(config, &utils.NodeAgentConfig{}), true)
	nodeAgentLoaderMock.AssertExpectations(t)
}
