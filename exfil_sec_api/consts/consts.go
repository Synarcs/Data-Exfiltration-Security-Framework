/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package consts

// LSM crypto, controller, and features grpc over tcp
var (
	CONTROLLER_RPC_PORT = 3200
)

// inference grpc over UDS
const (
	ONNX_INFER_UNIX_MNT = "/run/dnsobelisk/onnx-inference.sock"
)
