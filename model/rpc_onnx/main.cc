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
#include "inferencesock.hpp"
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


struct InferenceControllerOpts {
    float threshold = 0.5;
    string model_path;
    bool verbose = false;
    int help = 0; 
    int standalone = 0;
    int isQuantized = 0;
    int controller = 0;
};

class InferenceServer {
    public:
        void start() {
            inferenceSockHandler.get()->mountInferSockFs();
            inferenceSockHandler.get()->iniUDS();
        }
        InferenceServer(struct InferenceControllerOpts cliOpts)
            : opts(cliOpts) {
               inferenceSockHandler = make_unique<InferenceServerSocketHandler>();
            }

        void startinferencerpc();

        void shutdownServer();

    private:
        struct InferenceControllerOpts opts;
        unique_ptr<InferenceServerSocketHandler> inferenceSockHandler;
        // runfs mnt all unix socket the agent will use 
};

void InferenceServer::startinferencerpc() {

    std::string srv_mount = this->opts.controller ? ONNX_CONTROLLER_UNIX_TCP_MNT : ONNX_INFER_UNIX_MNT;
    std::string server_address("unix:" + srv_mount);
    grpc::ServerBuilder builder;
    unique_ptr<InferenceRPC::ImplDNSOnnxInferenceService> inferrpc;
    if (this->opts.model_path == "") {
        this->opts.model_path = get_modelPath(opts.standalone, opts.isQuantized);
    }
    inferrpc = make_unique<InferenceRPC::ImplDNSOnnxInferenceService>(this->opts.model_path, this->opts.threshold);
                   
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(inferrpc.get());
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
    std::cout << "Inference grpc server started over UDS transport path " << srv_mount << "with binary classification threshold for model " << 
                        this->opts.threshold << std::endl;
    rpcServer = std::move(server);
    // Add signal handlers for graceful interrupt shutdowns 
    rpcServer->Wait();
}  

void InferenceServer::shutdownServer() { rpcServer->Shutdown(); }

static 
inline void printArgs() {
    cout << "-t float32 \n \t\t The threshold used for binary classification of ONNX model. " <<
            "\n -m string \n \t\t ONNX Model serialized path. " << 
            "\n -v bool \n \t\t Debug output." << 
            "\n -h bool \n \t\t Print options." << 
            "\n -s bool \n \t\t Boot agent in standalone mode (no bootstrap as a child fork from main endpoint agent)." <<
            "\n -q bool \n \t\t Boot agent in quantized mode (uses ONNX model quantization for faster inference at endpoint)." <<
            "\n -c bool \n \t\t Boot agent to be ran on controller on DNS server for DNS over tcp traffic inference as DNS query interceptor" << endl;
}

#if defined(LDX)
extern "C" {
#endif
    int main(int argc, char *argv[]) { 
        struct InferenceControllerOpts opts;
        signal(SIGKILL, killRPCServerHandler);
        signal(SIGINT, killRPCServerHandler);
        int opt;
        while ((opt = getopt(argc, argv, "t:m:v:h:s:q:c")) != -1) {
            switch(opt) {
                case 't':
                    opts.threshold = atof(optarg);;
                    break;
                case 'm':
                    // model path 
                    opts.model_path = optarg;
                    break;
                case 'v':
                    opts.verbose = (strncmp(optarg, "true", strlen("true")) == 0 || atoi(optarg) == 1) ? true : false;
                    break;
                case 'h':
                    opts.help = 1;
                    break;
                case 's':
                    opts.standalone = 1;
                    break;
                case 'q':
                    opts.isQuantized = 1;
                    break;
                case 'c':
                    opts.controller = 1;
                default:
                    cout << "option not supported" << endl;
                    return EXIT_FAILURE;
            }
        }

        if (opts.help) {
            printArgs();
            exit(EXIT_SUCCESS);
        }
        unique_ptr<InferenceServer> srv = make_unique<InferenceServer>(opts);
        srv.get()->start();
    }
#if defined(LDX)
}
#endif
