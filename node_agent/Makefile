

node_agent := main.go 
output := node_agent 
debug ?= false 

.PHONY: compile 
compile:
	@echo "Compiling the Ebpf Node Agent" 
	go build $(node_agent) 

.PHONY: compile-kernel
compile-kernel:
	@echo "Compiling all kernel ebpf programs"
	cd ../kernel && make

.PHONY: build
build:
	@echo "Building and compiling the Ebpf Node Agent"
	make compile-kernel
	go build $(node_agent) 

.PHONY: run-inference
run-inference:
	@echo "Running the Remote unix socket inference server" 
	sudo python3 ../model/infer/inference.py

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
