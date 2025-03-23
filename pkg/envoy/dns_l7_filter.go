package envoy

import (
	"log"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

type wasmFilterVm struct {
	types.DefaultVMContext
}

func InitTCPWasmFilter() {
	log.Println("Initializing Envoy TCP Wasm Filter for DNS deep scan filter to prevent DNS exfiltration")
	proxywasm.SetVMContext(&wasmFilterVm{})
}
