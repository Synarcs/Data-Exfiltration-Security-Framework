
CC ?= clang 
CXX := clang++
CXXFLAGS ?= -O2 -Wall


.PHONY: all
all: compile run 

compile:
	$(CXX) $(CXXFLAGS) -o infer  infer.cc

run:
	./infer