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
            OnnxInferencer::OnnxRequestProcessingHandler onnx;
            BaseInference() : onnx() {}
            virtual ~BaseInference() {}
    };

    class ImplDNSOnnxInferenceService final : public DNSOnnxInferenceService::Service, BaseInference {
        private:
            std::vector<float> getfloatvectors(const DnsInferenceRequest * req) {
                std::vector<float> features;
                for (const auto& dns_feat : req->reshaped()) {
                    const auto& feats = dns_feat.features();
                    features.insert(features.end(), feats.begin(), feats.end());
                }
                return features;
            }
        public:
            ImplDNSOnnxInferenceService() noexcept : BaseInference() {}
            ~ImplDNSOnnxInferenceService() {}
            Status IngressInfer(ServerContext * ctx, const DnsInferenceRequest * request, DnsInferenceResponseIngress * response) override {
                std::vector<float> features = getfloatvectors(request);
                response->set_threadtype(onnx.infer(features) == 0);
                return Status::OK;
            }
            Status EgressInfer(ServerContext * ctx, const DnsInferenceRequest * request, DnsInferenceResponseEgress * response) override {
                return Status::OK;
            }
    };
};
