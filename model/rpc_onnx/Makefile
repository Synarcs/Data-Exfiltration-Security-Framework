# SPDX-License-Identifier: AGPL-3.0

CXX := clang++
CXXFLAGS := -O2 -Wall -std=c++17
LDFLAGS = -L/usr/local/lib `pkg-config --libs protobuf grpc++`\
           -Wl,--no-as-needed -lgrpc++_reflection -Wl,--as-needed\
           -ldl
PROTO_PATH = "../../exfil_sec_api/cxx/"
LIBONNX = -lonnxruntime
INFER := infer

SRC := main.cc \
       $(PROTO_PATH)/*.cc 

TEST := infer_test.cc 
TEST_OUT := test

.PHONY: all compile run clean test

all: compile run

compile:
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(SRC) -o $(INFER) $(LIBONNX)

run:
	sudo ./$(INFER)

test:
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $(TEST) -o $(TEST_OUT) $(LIBONNX)

clean:
	rm -f $(INFER)