# SPDX-License-Identifier: AGPL-3.0

CXX := clang++
CXXFLAGS := -O2 -Wall
INFER := infer
SRC := main.cc

# If libonnxruntime.so is custom mounted at endpoitn  in /usr/lib, add:
# LDFLAGS += -L/path/to/onnxruntime/lib
# CXXFLAGS += -I/path/to/onnxruntime/include

.PHONY: all compile run clean

all: compile run

compile:
	$(CXX) $(CXXFLAGS) $(SRC) $(LDFLAGS) -o $(INFER) -lonnxruntime

run:
	./infer
	
clean:
	rm -f $(INFER)