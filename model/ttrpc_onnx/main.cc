/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#include <iostream>
#include <memory.h>
#include <vector>
#include <stdint.h>

#include <filesystem>
#include <sys/socket.h>
#include <sys/un.h>
#include <grpcpp/grpcpp.h>
#include <signal.h>

// core memory loaded onnx model for inference covers multithreaded ttrpc (grpc over UDS) and unix 
#include "server.hpp"
#include "const.h"

using namespace std;

static std::unique_ptr<grpc::Server> rpcServer;
static std::atomic<bool> guardShutdownLock;

static void removeMountedSocks();

static 
void killRPCServerHandler(int sig_num) {
    std::cout << "signal close kill inference server " << endl;
    if (rpcServer && guardShutdownLock.load()) {
        guardShutdownLock.store(true);
        rpcServer.get()->Shutdown();
    }
}

static 
void removeMountedSocks() {
    // ensure the mnt is clean 
    try {
        filesystem::remove_all(INFER_MNT_PTH);
    }catch(const std::filesystem::filesystem_error& e) {
        perror("erro cleaning previous mnt server");
        exit(EXIT_FAILURE);
    }
}

class InferenceServer {
    public:
        void start(const float& threshold) {
            mountInferSockFs();
            iniUDS();
            startinferencerpc(threshold);
        }

        InferenceServer()  {
            const float default_threhold = 0.5;
            start(default_threhold);
        }

        InferenceServer(const string& model_path, const float& threshold) noexcept {
            this->model_path = model_path;
            this->threshold = threshold;
            start(threshold);
        }

        ~InferenceServer() {}

        void startinferencerpc(const float& binary_threshold) {
            std::string server_address("unix:" + ONNX_INFER_UNIX_MNT);
            grpc::ServerBuilder builder;
            unique_ptr<InferenceRPC::ImplDNSOnnxInferenceService> inferrpc;
            if (model_path == "") {
                inferrpc = make_unique<InferenceRPC::ImplDNSOnnxInferenceService>();
            }else {
                inferrpc = make_unique<InferenceRPC::ImplDNSOnnxInferenceService>(model_path,binary_threshold);
            }
                           
            builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
            builder.RegisterService(inferrpc.get());
            std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
            std::cout << "Inference grpc server started on port 32001 with onnx binary classification threshold " << binary_threshold << std::endl;
            rpcServer = std::move(server);
            // Add signal handlers for graceful interrupt shutdowns 
            rpcServer->Wait();
        }

        void shutdownServer() { rpcServer->Shutdown(); }

    private:
        string model_path;
        float threshold;
        // runfs mnt all unix socket the agent will use 
        void mountInferSockFs() {
            filesystem::path fd_path = INFER_MNT_PTH;
            if (filesystem::is_directory(fd_path)) {
                removeMountedSocks();
            }
            cout << "creating the unix mount path " << fd_path << endl;
            filesystem::create_directory(fd_path);
        }

        void iniUDS() {
            int in_fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (in_fd < 0) return;

            struct sockaddr_un in;
            memset(&in, 0, sizeof(struct sockaddr_un));

            in.sun_family = AF_UNIX;
            strncpy(in.sun_path, ONNX_INFER_UNIX_MNT.c_str(), sizeof(in.sun_path) - 1);

            unlink(ONNX_INFER_UNIX_MNT.c_str());

            if (bind(in_fd, (struct sockaddr*)&in, sizeof(in)) < 0) {
                perror("bind");
                close(in_fd);
                return;
            }
        }
};

#if !defined(LDX)
extern "C" {
    int main(int argc, char *argv[]) { 
        int opt;
        string model_path;
        float threshold = 0.5;
        while ((opt = getopt(argc, argv, "t:m:v")) != -1) {
            switch(opt) {
                case 't':
                    threshold = atof(optarg);
                    break;
                case 'm':
                    // model path 
                    model_path = optarg;
                    break;
                case 'v':
                    debug = true;
                    break;
                default:
                    cout << "option not supported" << endl;
                    return 0;
            }
        }
        
        unique_ptr<InferenceServer> srv = make_unique<InferenceServer>(model_path, threshold);
        signal(SIGKILL, killRPCServerHandler);
        signal(SIGINT, killRPCServerHandler);
    }
}
#endif 