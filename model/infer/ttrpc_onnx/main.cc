/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#include <iostream>
#include <memory.h>
#include <vector>
#include <stdint.h>

#include "onnxInferencer.hpp" // core memory loaded onnx model for inference covers multithreaded ttrpc (grpc over UDS) and unix 

using namespace std;

int main() {
    unique_ptr<OnnxInferencer::OnnxRequestProcessingHandler> handler = 
                    make_unique<OnnxInferencer::OnnxRequestProcessingHandler>();
    cout << "checking the loaded libboost modules " << endl;
}