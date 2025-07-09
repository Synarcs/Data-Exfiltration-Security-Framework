/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

#include <vector>
#include <stdint.h>

// thread pools for parallel execution of inference over onnx 
#include <boost/thread/thread.hpp>
#include <boost/thread/mutex.hpp>

namespace OnnxInferencer {
    class OnnxRequestProcessingHandler {
    private:
        std::vector<int32_t> addr_pool;
    public:
        OnnxRequestProcessingHandler() {

        }

        ~OnnxRequestProcessingHandler() {

        }
    };
};
