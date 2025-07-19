/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#include <stdlib.h>
#include <stdint.h>

#include <grpcpp/grpcpp.h>
#include "../../exfil_sec_api/cxx/exfil_sec_inference.grpc.pb.h"
#include "../../exfil_sec_api/cxx/exfil_sec_inference.pb.h"
#include "inference.hpp"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

using exfil_kernel::DNSOnnxInferenceService;
using exfil_kernel::DnsInferenceRequest;
using exfil_kernel::DnsInferenceResponseIngress;
using exfil_kernel::DnsInferenceResponseEgress;

namespace InferenceRPC {
    class BaseInference {
        public:
            OnnxInferencer::DNSOnnxInference onnx;
            BaseInference() {}
            BaseInference(const std::string& model_path, const float& classify_threshold)
                    : onnx(model_path, classify_threshold) {}
            virtual ~BaseInference() {}
    };

    class ImplDNSOnnxInferenceService final : public DNSOnnxInferenceService::Service, BaseInference {
        private:
            const std::string protocol = "DNS";
            std::vector<std::vector<float>> getfloatvectors(const DnsInferenceRequest * req) {
                std::vector<std::vector<float>> features;
                for (const auto& dns_feat : req->reshaped()) {
                    const auto& feats = dns_feat.features();
                    features.emplace_back(feats.begin(), feats.end());
                }
                return features;
            }
        public:
            ImplDNSOnnxInferenceService() noexcept : BaseInference() {}
            ImplDNSOnnxInferenceService(const std::string& model_path, const float& binary_threshold) noexcept : BaseInference(model_path, binary_threshold) {}
            ~ImplDNSOnnxInferenceService() {}
            Status IngressInfer(ServerContext * ctx, const DnsInferenceRequest * request, DnsInferenceResponseIngress * response) override {
                bool isAnyMal = false;
                for (std::vector<float> feature : getfloatvectors(request)) {
                    if (onnx.infer(feature)) {
                        isAnyMal = true;
                        break;
                    }
                }
                response->set_protocol(protocol);
                response->add_threadtype(isAnyMal);
                return Status::OK;
            }
            Status EgressInfer(ServerContext * ctx, const DnsInferenceRequest * request, DnsInferenceResponseEgress * response) override {

                std::vector<std::vector<float>> features = getfloatvectors(request);
                if (features.size() == 0 || features.size() > 1) {
                    return Status::CANCELLED;
                }
                
                response->set_threadtype(onnx.infer(features[0]));
                return Status::OK;
            }
    };
};
