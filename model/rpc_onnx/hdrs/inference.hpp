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

namespace OnnxInferencer {
    static const int DEFAULT_BACKEDN = 0;
    enum class Inference_Backends: uint8_t {
        CPU = 0,
        GPU = 1,
        NPU = 2,
    };

    // configure global session for all inferencer
    class BaseClassificationModelInferencer {
        protected:
            uint8_t inferenceBackend; // generic inferencer to support ONNX inference over different backends
        public:
            BaseClassificationModelInferencer() = default;
            BaseClassificationModelInferencer(uint8_t backend) {}
            virtual ~BaseClassificationModelInferencer() {}
            virtual bool infer(std::vector<float>&) = 0;
            virtual float getClassificationThreshold() = 0;
            virtual Ort::Session& getOnnxInferenceSession() = 0;
    };

    class DNSOnnxGpuInference: public BaseClassificationModelInferencer {
    	public:
	   DNSOnnxGpuInference() = default;
    };

    static const char * log_indexId = "dns_exfil_infer";
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
            : BaseClassificationModelInferencer(static_cast<uint8_t>(Inference_Backends::CPU)),
              session(nullptr),
              env(ORT_LOGGING_LEVEL_WARNING, log_indexId),
              classifer_threshold(binary_classifer)
        {
            session_options.SetIntraOpNumThreads(std::thread::hardware_concurrency());
            session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_BASIC);
            session = Ort::Session(env, model_path.c_str(), session_options);
            session = Ort::Session(env, model_path.c_str(), session_options);
            session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);

            session = Ort::Session(env, model_path.c_str(), session_options);
        }

        // binary classification threshold value 
        float getClassificationThreshold() override;
        
        // runs onnx inference return if found as malicious over model strong lexical analysis 
        bool infer (std::vector<float>&) override;

        Ort::Session& getOnnxInferenceSession() override;
    };

    float DNSOnnxCPUInference::getClassificationThreshold() {
        return this->classifer_threshold;
    }

    inline bool DNSOnnxCPUInference::infer(std::vector<float>& features) {
        return this->evalInference(features);
    }

    inline Ort::Session& DNSOnnxCPUInference::getOnnxInferenceSession() {
        return this->session;
    }
};
