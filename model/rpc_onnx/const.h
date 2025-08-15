/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#pragma once 

#include <string>

static const std::string ONNX_INFER_UNIX_MNT = "/run/dnsobelisk/onnx-inference.sock";
static const std::string ONNX_CONTROLLER_UNIX_TCP_MNT = "/etc/powerdns/onnx-inference.sock"; // assumes the controller uses PowerDNS as the DNS Auth, recursor server 


static const std::string INFER_MNT_PTH = "/run/dnsobelisk";

static bool debug = false;

// TODO: fix this loadable dynamic for anywhere is fs
const std::string QNNX_QT_PATH = "../dns_sec_qint8.onnx";
const std::string ONNX_PATH_STD = "../dns_sec.onnx";
const std::string ONNX_PATH_NSTD = "../model/dns_sec.onnx";


std::string get_modelPath(int isQuantized, int standalone) {
    if (isQuantized) return QNNX_QT_PATH;
    return standalone ? ONNX_PATH_STD : ONNX_PATH_NSTD;
}
