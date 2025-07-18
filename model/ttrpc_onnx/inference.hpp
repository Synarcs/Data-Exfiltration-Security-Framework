/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#include <vector>
#include <stdint.h>
#include <iomanip>
#include <thread>
#include <map>

// ort inference
#include "onnxruntime_cxx_api.h"

const std::string backend = "CPU";

namespace OnnxInferencer {
    #if ONNX_QUANTIZED
        const std::string model_path = "../dns_sec_qint8.onnx";
    #else
        const std::string model_path = "../dns_sec.onnx";
    #endif 
    const float binary_class_threshold = 0.5;
    class OnnxRequestProcessingHandler {
    private:
        std::vector<int32_t> addr_pool;
        Ort::SessionOptions session_options;
        Ort::Session session;
        Ort::Env env;
        Ort::AllocatorWithDefaultOptions allocator;
        float classifer_threshold;
    public:
        OnnxRequestProcessingHandler(const std::string& model_path, const float binary_classifer)
            : env(ORT_LOGGING_LEVEL_WARNING, "dns_exfil_infer"),
              session(nullptr), classifer_threshold(binary_classifer)
        {
            session_options.SetIntraOpNumThreads(std::thread::hardware_concurrency());
            session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_BASIC);
            session = Ort::Session(env, model_path.c_str(), session_options);
            session = Ort::Session(env, model_path.c_str(), session_options);
            session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);

            session = Ort::Session(env, model_path.c_str(), session_options);

        }

        OnnxRequestProcessingHandler() : OnnxRequestProcessingHandler(model_path, binary_class_threshold) {}

        ~OnnxRequestProcessingHandler() {}

        // rruns onnx inferencer return if found as malicious 
        bool infer (std::vector<float>& features) {
            std::array<int64_t, 2> input_shape{1, 8};

            Ort::MemoryInfo mem_info = Ort::MemoryInfo::CreateCpu(OrtDeviceAllocator, OrtMemTypeCPU);
            std::string alloc_input = mem_info.GetAllocatorName();
            std::cout << "alloc name check " << alloc_input << std::endl;

            Ort::Value input_tensor = Ort::Value::CreateTensor<float>(
                mem_info, features.data(), features.size(), input_shape.data(), input_shape.size()
            );

            Ort::AllocatedStringPtr in = session.GetInputNameAllocated(0, allocator);
            Ort::AllocatedStringPtr out = session.GetOutputNameAllocated(0, allocator);

            const char* input_names[] = {in.get()};
            const char* output_names[] = {out.get()};

            auto output_tensors = session.Run(Ort::RunOptions{nullptr},
                                              input_names, &input_tensor, 1,
                                              output_names, 1);
            auto classify_out = output_tensors.front().GetTensorMutableData<float>();
            return classify_out == nullptr ? false : *classify_out >= classifer_threshold;
        }
    };
};

