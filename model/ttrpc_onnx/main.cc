/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#include <iostream>
#include <memory.h>
#include <vector>
#include <stdint.h>

// core memory loaded onnx model for inference covers multithreaded ttrpc (grpc over UDS) and unix 
#include "onnxInferencer.hpp" 

// thread pools for parallel execution of inference over onnx 
#include <boost/thread/thread.hpp>
#include <boost/thread/mutex.hpp>

using namespace std;

int main() {
    unique_ptr<OnnxInferencer::OnnxRequestProcessingHandler> handler = 
                    make_unique<OnnxInferencer::OnnxRequestProcessingHandler>();
    
    unique_ptr<LocalInferenceTest::FeatureLoaderExtractor> featureExtractor = make_unique<LocalInferenceTest::FeatureLoaderExtractor>();

    std::string domain = "mail.google.com";
    
    std::vector<float> features = featureExtractor.get()->extractFeatures(domain);
    cout << "checking the loaded libboost modules " << endl;
    cout << "is_malicious " << (handler.get()->infer(features) == 0 ? "false" : "true") << std::endl;
}