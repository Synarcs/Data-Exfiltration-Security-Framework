/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#include <vector>
#include <stdint.h>
#include <iomanip>
#include <thread>

// ort inference
#include "onnxruntime_cxx_api.h"
#include "map"


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


namespace LocalInferenceTest {
    class FeatureLoaderExtractor {
        private:
            OnnxInferencer::OnnxRequestProcessingHandler inference;
            float calculate_entropy(std::string& domain) {
                std::vector<float> freq(256, 0);
                for (char c : domain) freq[static_cast<unsigned char>(c)] += 1.0f;
                float entropy = 0.0f;
                for (float count : freq) {
                    if (count > 0) {
                        float p = count / domain.size();
                        entropy -= p * std::log2(p);
                    }
                }
                return entropy;
            }
        public:
            FeatureLoaderExtractor() noexcept : inference() { }
            ~FeatureLoaderExtractor() {}

            // extract DNS exfil lexical scan deep features 
            std::vector<float> extractFeatures(std::string& domain) {
                std::vector<float> features;

                int total_chars = domain.length();

                size_t dot1 = domain.rfind('.');
                size_t dot2 = domain.rfind('.', dot1 == std::string::npos ? std::string::npos : dot1 - 1);

                std::string subdomain = (dot2 != std::string::npos) ? domain.substr(0, dot2) : "";

                std::cout << "subdomain is " << subdomain << std::endl;

                int total_chars_subdomain = subdomain.length();
                int number = std::count_if(domain.begin(), domain.end(), ::isdigit);
                int upper = std::count_if(domain.begin(), domain.end(), ::isupper);
                float entropy = calculate_entropy(domain);
                int total_dots = std::count(domain.begin(), domain.end(), '.');

                std::vector<std::string> labels;
                size_t start = 0, end;
                while ((end = domain.find('.', start)) != std::string::npos) {
                    labels.push_back(domain.substr(start, end - start));
                    start = end + 1;
                }
                labels.push_back(domain.substr(start));
                int max_label_length = 0;
                float avg_label_length = 0.0;
                for (const auto& label : labels) {
                    int len = label.length();
                    max_label_length = std::max(max_label_length, len);
                    avg_label_length += len;
                }
                avg_label_length /= labels.size();

                return {
                    static_cast<float>(total_chars),
                    static_cast<float>(total_chars_subdomain),
                    static_cast<float>(number),
                    static_cast<float>(upper),
                    entropy,
                    static_cast<float>(total_dots),
                    static_cast<float>(max_label_length),
                    avg_label_length
                };
            }
    };
}