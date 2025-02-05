

node_agent := main.go 
output := node_agent 
debug ?= false 

.PHONY: compile 
compile:
	@echo "Compiling the eBPF Node Agent for $(shell go env GOOS && go env GOARCH)"
	go build $(node_agent) 

.PHONY: compile-kernel
compile-kernel:
	@echo "Compiling all kernel ebpf programs"
	cd ../kernel && make

.PHONY: compile-kernel-x86
compile-kernel-x86: 
	@echo "Compiling eBPF Kernel Programs for x86-64 architecture"
	cd ../kernel && make compile-x86

.PHONY: build-cli 
build-cli:
	@echo "Building eBPF Node Agent CLI for unix IPC"
	cd ../cmd && make build 

.PHONY: build
build:
	@echo "Building and compiling the eBPF Node Agent {Kernel, User-Space}"
	make compile-kernel
	make build-cli 
	make compile

.PHONY: build-x86
build-x86:
	@echo "Building and compiling eBPF Node Agent {Kernel, User-space}"
	make compile-kernel-x86
	make build-cli 
	make compile

.PHONY: run-inference
run-inference:
	@echo "Running the Remote unix socket inference server" 
	sudo python3 ../model/infer/inference.py

.PHONY: run-inference-controller
run-inference-controller:
	@echo "Running the Remote unix socket inference server on controller server"
	python3 ../model/infer/inference.py -c true 


.PHONY: netinet
netinet:
	@echo "Creating Network Overlay topology for eBPF Node agent via kernel veth brdiges and linux namespaces"
	bash ../scripts/brctl.sh

.PHONY: infer-build
infer-build:
	@echo "Building the python compiled binary"
	pyinstaller -n infer --onefile  ../model/infer/inference.py ../model/infer/infer.py ../model/infer/consts.py 
	rm -rf build

.PHONY: infer-run 
infer-`:
	@echo "Running the compiled Python Binary"
	sudo ./dist/infer

.PHONY: run
start: 
	sudo ./main 

.PHONY: build-run 
build-run:
	@echo "building and running eBPF node_agent"
	make build
	sudo ./main 

.PHONY: build-run-x86 
build-run-x86:
	@echo "building and running eBPF node_agent"
	make build-x86 
	sudo ./main 

.PHONY: build-run-pidns
build-run-pidns:
	@echo "building and runnign eBPF node_agent with isolated process namespace for security"
	make build 
	sudo unshare --pid --fork ./main


.PHONY: build-run-pidns-x86
build-run-pidns-x86:
	@echo "building and runnign eBPF node_agent with isolated process namespace for security"
	make build-x86 
	sudo unshare --pid --fork ./main

.PHONY: disas 
disas:
	if [ "$(debug)" = "true" ]; then llvm-objdump -d $(node_agent); fi
	gdb main 
