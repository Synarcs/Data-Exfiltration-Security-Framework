

node_agent := main.go 
output := node_agent 
debug ?= false 

.PHONY: compile 
compile:
	@echo "Compiling the Ebpf Node Agent for $(shell go env GOOS && go env GOARCH)"
	go build $(node_agent) 


.PHONY: compile-kernel
compile-kernel:
	@echo "Compiling all kernel ebpf programs"
	cd ../kernel && make

.PHONY: compile-kernel-x86
compile-kernel-x86: 
	@echo "Compiling eBPF Kernel Programs for x86-64 architecture"
	cd ../kernel && make compile-x86

.PHONY: build
build:
	@echo "Building and compiling the eBPF Node Agent {Kernel, User-Space}"
	make compile-kernel
	make compile

.PHONY: build-x86
build-x86:
	@echo "Building and compiling eBPF Node Agent {Kernel, User-space}"
	make compile-kernel-x86
	make compile

.PHONY: run-inference
run-inference:
	@echo "Running the Remote unix socket inference server" 
	sudo python3 ../model/infer/inference.py

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
infer-run:
	@echo "Running the compiled Python Binary"
	sudo ./dist/infer

.PHONY: run
start: 
	sudo ./main 

.PHONY: build-run 
build-run:
	@echo "building and running the node_agent"
	make build
	sudo ./main 

.PHONY: disas 
disas:
	if [ "$(debug)" = "true" ]; then llvm-objdump -d $(node_agent); fi
	gdb main 
