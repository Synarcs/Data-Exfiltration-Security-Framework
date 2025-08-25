/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#pragma once 

#include <iostream>
#include <filesystem>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>

#include "const.h"

using namespace std;

static 
void removeMountedSocks() {
    // ensure the mnt is clean 
    try {
        int runfs_sock_mount = 0;
        for (const auto& file : std::filesystem::directory_iterator(INFER_MNT_PTH)) {
            if (file.is_socket()) {
                if (file.path().filename() == ONNX_INFER_UNIX_MNT) {
                    std::filesystem::remove(ONNX_INFER_UNIX_MNT);
                }
            }
            runfs_sock_mount++;
        }
        if (runfs_sock_mount == 1) {
            std::filesystem::remove_all(INFER_MNT_PTH);
        }
    }catch(const std::filesystem::filesystem_error& e) {
        perror("erro cleaning previous mnt server");
        exit(EXIT_FAILURE);
    }
}

class InferenceServerSocketHandler {
    public:
        InferenceServerSocketHandler() = default;
        virtual ~InferenceServerSocketHandler() {}
        void mountInferSockFs();
        void iniUDS();
};

void InferenceServerSocketHandler::mountInferSockFs() {
    filesystem::path fd_path = INFER_MNT_PTH;
    if (filesystem::is_directory(fd_path)) {
        removeMountedSocks();
    }
    cout << "creating the unix mount path " << fd_path << endl;
    filesystem::create_directory(fd_path);
}

void InferenceServerSocketHandler::iniUDS() {
    int in_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (in_fd < 0) {
        cerr << "error mounting the unix socket " << endl;
        return;
    }
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