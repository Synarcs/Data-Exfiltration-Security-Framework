/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/
#pragma once

#include <stdlib.h>
#include <stdint.h>

#include <grpcpp/grpcpp.h>
#include "../../../exfil_sec_api/cxx/exfil_sec_inference.grpc.pb.h"
#include "../../../exfil_sec_api/cxx/exfil_sec_inference.pb.h"
#include "inference.hpp"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;
using google::protobuf::Empty;

using exfil_kernel::DNSOnnxInferenceService;
using exfil_kernel::DnsInferenceRequest;
using exfil_kernel::DnsInferenceResponseIngress;
using exfil_kernel::DnsInferenceResponseEgress;
using exfil_kernel::ServiceHeartBeatVersion;

namespace InferenceRPC {
    class BaseInference {
        public:
            OnnxInferencer::DNSOnnxCPUInference onnx;
            BaseInference(const std::string& model_path, const float& classify_threshold)
                    : onnx(model_path, classify_threshold) {}
            virtual ~BaseInference() {}
    };

    class ImplDNSOnnxInferenceService final : public DNSOnnxInferenceService::Service, BaseInference {
        protected:
            const std::string protocol = "DNS";
            std::vector<std::vector<float>> getfloatvectors(const DnsInferenceRequest * req) {
                std::vector<std::vector<float>> features;
                for (const auto& dns_feat : req->reshaped()) 
                    features.emplace_back(dns_feat.features().begin(), dns_feat.features().end());
                return features;
            }
            bool runInference(const DnsInferenceRequest * request) {
                for (std::vector<float> feature : getfloatvectors(request)) {
                    if (onnx.infer(feature)) {
                        return true;
                    }
                }
                return false;
            }
        public:
            explicit ImplDNSOnnxInferenceService(const std::string& model_path, const float& binary_threshold) noexcept : BaseInference(model_path, binary_threshold) {}
            Status IngressInfer(ServerContext * ctx, const DnsInferenceRequest * request, DnsInferenceResponseIngress * response) override {

                std::vector<std::vector<float>> features = getfloatvectors(request);
                response->set_protocol(protocol);
                response->add_threattype(runInference(request) ? true : false);
                return Status::OK;
            }
            Status EgressInfer(ServerContext * ctx, const DnsInferenceRequest * request, DnsInferenceResponseEgress * response) override {
                response->set_threattype(runInference(request) ? true : false);
                return Status::OK;
            }

            Status VersionInfo(ServerContext * ctx, const Empty * request, ServiceHeartBeatVersion * response) override {
                response->set_version("1.0.1");
                return Status::OK;
            }
    };
};
