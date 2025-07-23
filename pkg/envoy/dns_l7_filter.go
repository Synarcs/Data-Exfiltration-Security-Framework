/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package envoy

import (
	"bytes"
	"context"
	"os/exec"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

const (
	ENVOY_CONFIG_FILE  = "dpi-wasm.yaml"
	ENVOY_DPI_TCP_PORT = 9801
)

type wasmFilterVm struct {
	types.DefaultVMContext
}

// override the core plugin contxt for all envoy filter methods
type pluginContext struct {
	types.DefaultPluginContext
}

func InitTCPWasmFilter(ctx context.Context) {
	utils.Log("Initializing Envoy TCP Wasm Filter for DNS deep scan filter to prevent DNS exfiltration")
	proxywasm.SetVMContext(&wasmFilterVm{})
}

func (pluging *pluginContext) OnNewConnection(contextId uint32) types.Action {
	return types.Action(contextId)
}

func BootStrapEnvoyServer(ctx context.Context) error {
	cmd := exec.Command("envoy", "-c", ENVOY_CONFIG_FILE)
	var stdout *bytes.Buffer = &bytes.Buffer{}
	cmd.Stdout = stdout
	if err := cmd.Run(); err != nil {
		return err
	}

	if utils.DEBUG {
		utils.Log(stdout.String())
	}
	utils.Log("Envoy Server started with DPI filter loaded in filter chain ")
	return nil
}
