package envoy

import (
	"log"
	"os/exec"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

type wasmFilterVm struct {
	types.DefaultVMContext
}

func StartEnvoyFilter() error {
	cmd := exec.Command("envoy", "-c", "envoy.yaml")
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to start Envoy: %v", err)
	}
	return nil
}

func InitTCPWasmFilter() {
	utils.Log("Initializing Envoy TCP Wasm Filter for DNS deep scan filter to prevent DNS exfiltration")
	proxywasm.SetVMContext(&wasmFilterVm{})
}
