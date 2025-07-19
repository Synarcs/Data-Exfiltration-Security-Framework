/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#include "inference.hpp"
#include <iostream>
#include <map>
#include <vector>

namespace LocalInferenceTest {
    class FeatureLoaderExtractor {
        private:
            OnnxInferencer::DNSOnnxInference inference = OnnxInferencer::DNSOnnxInference();
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
            FeatureLoaderExtractor() {}
            ~FeatureLoaderExtractor() {}

            void infer(std::string& domain) {
                std::vector<float> features = extractFeatures(domain);
                if (inference.infer(features) >= inference.getClassificationThreshold()) {
                    std::cout << "Malicious domain contain DNS exfil: " << domain << std::endl;
                    return;
                }
                std::cout << "Benign domain contain DNS exfil: " << domain << std::endl;
            }
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