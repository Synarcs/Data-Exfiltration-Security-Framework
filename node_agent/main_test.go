package main

import (
	"os"
	"runtime"
	"testing"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type KernelEbpfMockInjectors struct {
	mock.Mock
}

func (k *KernelEbpfMockInjectors) TestKernelTCEbpfInject(prog string) error {
	k.Called(prog)
	return nil
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

	iface := netinet.NetIface{}
	iface.ReadInterfaces(false)
	iface.ReadRoutes()
	iface.InitconnTrackSockHandles()

	if len(iface.PhysicalLinks) == 0 {
		assert.Fail("Error the node agent cannot boot and inject kernel programs until the required netlink links are found")
	}

	assert.True(true)
}

func TestMain(t *testing.T) {
	assert.Equal(t, runtime.GOARCH, "arm64", "Architecture should match")
	t.Log("Runnign tests for main eBPF node Agent in user space")
}
