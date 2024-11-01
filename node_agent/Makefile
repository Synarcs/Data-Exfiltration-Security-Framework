

node_agent := main.go 
output := node_agent 
debug ?= false 

.PHONY: build
build:
	@echo "Building and compiling the Ebpf Node Agent"
	go build $(node_agent) 

.PHONY: run-inference
run-inference:
	@echo "Running the Remote unix socket inference server" 
	sudo python3 ../model/infer/inference.py

.PHONY: start 
start: 
	sudo ./main 

.PHONY: build-run 
build-run:
	@echo "running the node_agent"
	go build $(node_agent) 
	sudo ./main 

.PHONY: disas 
disas:
	if [ "$(debug)" = "true" ]; then objdump -d "main"; fi
	gdb main 
