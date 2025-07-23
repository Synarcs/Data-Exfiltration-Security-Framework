/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#pragma once

#include <vector>
#include <stdint.h>
#include <iomanip>
#include <thread>
#include <map>

// ort inference
#include "onnxruntime_cxx_api.h"

const std::string backend = "CPU";

namespace OnnxInferencer {
    // the default path the inference server lookup for 
    #if defined(ONNX_QUANTIZED)
        const std::string model_path = "../dns_sec_qint8.onnx";
    #else
        #if defined(ONNX_ISOLATED_BOOT)
            const std::string model_path = "../dns_sec.onnx";
        #else
            const std::string model_path = "../model/dns_sec.onnx"; // the core endpoint agent bootstraps this as a child fork 
        #endif 
    #endif

    // configure global session for all inferencer
    class BaseClassificationModelInferencer {
        public:
            BaseClassificationModelInferencer() = default;
            virtual ~BaseClassificationModelInferencer() {}
            virtual bool infer(std::vector<float>&) = 0;
            virtual float getClassificationThreshold() = 0;
            virtual Ort::Session& getOnnxInferenceSession() = 0;
    };

    class DNSOnnxCPUInference : public BaseClassificationModelInferencer {
    protected:
        std::vector<int32_t> addr_pool;
        Ort::SessionOptions session_options;
        Ort::Session session;
        Ort::Env env;
        Ort::AllocatorWithDefaultOptions allocator;
        float classifer_threshold;
        bool evalInference(std::vector<float>& features) {
            Ort::MemoryInfo mem_info = Ort::MemoryInfo::CreateCpu(OrtDeviceAllocator, OrtMemTypeCPU);

            std::array<int64_t, 2> input_shape{1, 8};
                        Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
                        mem_info, features.data(), features.size(), input_shape.data(), input_shape.size()
            );

            std::string alloc_input = mem_info.GetAllocatorName();

            Ort::AllocatedStringPtr in = session.GetInputNameAllocated(0, allocator);
            Ort::AllocatedStringPtr out = session.GetOutputNameAllocated(0, allocator);
            const char* input_names[] = {in.get()};
            const char* output_names[] = {out.get()};
            auto output_tensors = session.Run(Ort::RunOptions{nullptr},
                                            input_names, &input_tensor, 1,
                                            output_names, 1);
            auto classify_out = output_tensors.front().GetTensorMutableData<float>();
            #if 0
                if (classify_out != nullptr) {
                    std::cout << "the classify result for this is " << *classify_out << " " << classifer_threshold << std::endl;
                }
            #endif
            return classify_out == nullptr ? false : !(*classify_out < classifer_threshold);
        }
    public:
        DNSOnnxCPUInference(const std::string& model_path, const float& binary_classifer) noexcept
            : session(nullptr),
              env(ORT_LOGGING_LEVEL_WARNING, "dns_exfil_infer"),
              classifer_threshold(binary_classifer)
        {
            session_options.SetIntraOpNumThreads(std::thread::hardware_concurrency());
            session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_BASIC);
            session = Ort::Session(env, model_path.c_str(), session_options);
            session = Ort::Session(env, model_path.c_str(), session_options);
            session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);

            session = Ort::Session(env, model_path.c_str(), session_options);

        }

        DNSOnnxCPUInference() noexcept : DNSOnnxCPUInference(model_path, 0.5) {}

        // binary classification threshold value 
        float getClassificationThreshold() override;
        
        // runs onnx inference return if found as malicious over model strong lexical analysis 
        bool infer (std::vector<float>&) override;

        Ort::Session& getOnnxInferenceSession() override;
    };

    float DNSOnnxCPUInference::getClassificationThreshold() {
        return this->classifer_threshold;
    }

    bool DNSOnnxCPUInference::infer(std::vector<float>& features) {
        return this->evalInference(features);
    }

    Ort::Session& DNSOnnxCPUInference::getOnnxInferenceSession() {
        return this->session;
    }
};
