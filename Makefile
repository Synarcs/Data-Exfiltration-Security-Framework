# node agent build and run., requires all dependencies installed at the endpoint to build and run the agent 

node_agent ?= main.go 
output ?= main 
debug ?= false 
ARCH := $(shell uname -m)

CC ?= clang 
CXX ?= clang++
CFLAGS ?= -O2 -Wall

MODEL_PATH ?= "../dns_sec.onnx"
DNS_SERVER_DIR ?= "/etc/powerdns" # for running the DNS over TCP lua interceptor over the DNS recursor config build path 

# SPDX-License-Identifier: AGPL-3.0
model_path ?= model/dns_sec.onnx
DEBUG ?= false 

CONTROLLER_PORT ?= 8080
CONTROLLER_IMAGE_NAME ?= controller
CONTROLLER_IMAGE_TAG ?= latest


.PHONY: all
build-framework:
	@echo "building the framework"
	make build
	make build-controller


###---------------------------------------- Data Plane ---------------------------------------###
.PHONY: build-dep-agent
build-dep-agent:
	bash infrastructure/agent.sh

.PHONY: build-dep-controller 
build-dep-controller:
	bash infrastructure/controller.sh

.PHONY: node-metrics
node-metrics:
	@echo "starting the node exported metrics for monitor infrastructure at the node"
	cd bin/ && bash start.sh &

.PHONY: netinet
netinet:
	@echo "Creating Network Overlay topology for eBPF Node agent via kernel veth brdiges and linux namespaces"
	bash scripts/brctl.sh

.PHONY: build
build:
	@echo "Building and compiling the eBPF Node Agent {Kernel, User-Space}"
	make compile-kernel-bpf
	make infer-build
	make build-cli 
	make infer-build

.PHONY: compile-kernel-bpf
compile-kernel-bpf:
	@echo "Compiling all the eBPF kernel programs for $(shell uname -m) arch"
	cd kernel && make

.PHONY: build-cli 
build-cli:
	@echo "Building eBPF Node Agent CLI for unix IPC"
	cd cmd && make build 

.PHONY: compile-node-agent
compile-node-agent:
	@echo "Compiling the eBPF Node Agent for $(ARCH)"
	cd node_agent && go build -ldflags="-s -w" -o $(output)  $(node_agent) 

.PHONY: infer-build
infer-build:
	@echo "Building the ONXN RPC inference server"
	cd model/rpc_onnx && make compile

.PHONY: run-agent
run-agent:
	@echo "building and running eBPF node_agent"
	make build && cd node_agent && sudo ./main 

.PHONY: run-agent-pidns
build-run-pidns:
	@echo "building and runnign eBPF node_agent with isolated process namespace for security"
	make build 
	sudo unshare --pid --fork ./main

# for local testing to check compatibility of loaded onnx model ran by thte python ort inferencer
# note for live high throughput test its preferred to use the grpc cxx onnx inference for performance
.PHONY: run-inference-python-onnx 
run_node_agent:
	@echo "Running the Remote unix socket inference server" 
	sudo python3 ../model/infer/inference.py -m $(MODEL_PATH) 

.PHONY: run-inference-controller-python-onnx 
run-inference-controller-python-onnx:
	@echo "Running the Remote unix socket inference server on controller server"
	sudo python3 ../model/infer/inference.py  -m $(MODEL_PATH) -c true  &
	@echo "Configure the Unix socket permissions and ownership  for inference"
	sleep 1.5 && sudo chmod 777 /etc/powerdns/onnx-inference-out.sock && sudo chmod 777 /etc/powerdns/onnx-inference-in.sock

.PHONY: test-agent 
test-agent:
	@echo "Running the eBPF Node Agent Unit Tests"
	cd node_agent && go test --timeout 10s


###-------------------------------------Agent Crypto for Self-sign PKI and kernel keyring----------------------------------------###

KEY_DIR := keys
PRIVATE_KEY := $(KEY_DIR)/private.key
CERT := $(KEY_DIR)/cert.pem
CERT_DER := $(KEY_DIR)/cert.der

.PHONY: keys
keys:
	@mkdir -p $(KEY_DIR)
	@openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out $(PRIVATE_KEY)
	@openssl req -new -x509 -config conf/bpf_cert.conf -key $(PRIVATE_KEY) -out $(CERT) -days 365
	@openssl x509 -in $(CERT) -outform DER -out $(CERT_DER)
	@echo "Generated keys in $(KEY_DIR) directory"
	@echo "WARNING: Keep $(PRIVATE_KEY) private and secure!"

###----------------------------------------------------------------------------------------------###


###----------------------------------------------------------------------------------------------###


###---------------------------------------- Control Plane ---------------------------------------###
.PHONY: build-controller
build-controller:
	@echo "Building the controller"
	@if [ -d "controller/bin" ]; then \
		echo "Deleting directory for previous controller build"; \
		rm -rf controller/bin; \
	fi
	@mkdir controller/bin
	cd controller && mvn clean package && cp target/*.jar bin/ && mvn clean 
	@echo "Building the controller UNIX stream Inference NetworkPolicyHandlers"
	cd controller/cmd && go build -ldflags="-s -w" -o ../bin/main main.go 

.PHONY: build-controller-cni-sec
build-controller-cni-sec:
	@echo "Building the controller UNIX stream Inference NetworkPolicyHandlers"
	cd controller/cmd && go build -o ../bin/main main.go 

.PHONY: run-controller-cni-sec
run-controller-cni-sec:
	@echo "Running the controller UNIX stream Inference NetworkPolicyHandlers"
	cd controller/bin && ./main

.PHONY: build-controller-image
build-controller-image:
	@echo "Building the controller docker image"
	cd controller && docker build -t $(CONTROLLER_IMAGE_NAME) . 

.PHONY: run-controller-image
run-controller-image:
	@echo "Running the controller"
	docker run --name controller -p $(CONTROLLER_PORT):9000 -d $(CONTROLLER_IMAGE_NAME):$(CONTROLLER_IMAGE_TAG) 

.PHONY: stop-controller-image
stop-controller-image:
	@echo "Stopping the controller"
	docker kill controller

.PHONY: run-controller
run-controller:
	@echo "Running the controller"
	cd controller && java -jar bin/*.jar 

.PHONY: controller 
controller:
	@echo "Build and Run Controller" 
	make build-controller 
	make run-controller

.PHONY: test-controller 
test-controller:
	@echo "testing the controller"
	cd controller && mvn test 

###----------------------------------------------------------------------------------------------###

.PHONY: test-framework
test-framework:
	@echo "testing the framework"
	make test-agent
	make test-controller 

.PHONY: install-dep-build
install-dep:
	@echo "install kernel and user space dep and headers"
	bash infrastructure/agent.sh
	bash infrastructure/monitor.sh 

proto_path ?= exfil_sec_api/proto
go_out ?= exfil_sec_api
cxx_out ?= exfil_sec_api
cxx_proto_out ?= cxx 
proto_file_c := exfil_sec_controller.proto
proto_file_i := exfil_sec_inference.proto

.PHONY: build-framework-protos
build-framework-protos:
	@echo "Generating all the protos for the exfil_sec framework endpoint security for control plane and data plane"
	protoc --proto_path="$(proto_path)" \
		--go_out="paths=source_relative:$(go_out)" \
		--go-grpc_out="paths=source_relative,require_unimplemented_servers=false:$(go_out)" \
		"$(proto_path)/$(proto_file_c)"

	protoc --proto_path="$(proto_path)" \
		--go_out="paths=source_relative:$(go_out)" \
		--go-grpc_out="paths=source_relative,require_unimplemented_servers=false:$(go_out)" \
		"$(proto_path)/$(proto_file_i)"
	
	@if [ -d "$(cxx_out)/cxx" ]; then \
		echo "Deleting directory for previous ONNX grpc inference protos"; \
		rm -rf "$(cxx_out)/cxx"; \
	fi
	@mkdir $(cxx_out)/cxx 
	protoc --proto_path="$(proto_path)"		 	\
		--cpp_out="$(cxx_out)"/cxx 				\
		--grpc_out=$(cxx_out)/cxx				\
		--plugin=protoc-gen-grpc=$(shell which grpc_cpp_plugin) \
		$(proto_path)/$(proto_file_i) 


.PHONY: build-proto-dep
build-proto-dep: 
	@echo "Installing all the required proto build deps" 
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	

QPS ?= 100000
DURATION ?= 20

.PHONY: bench
bench:
	cd scripts/bench  && bash bench.sh dnsperf $(QPS) $(DURATION)


.PHONY: kernel-prof
kernel-prof:
	@echo "running kernel eBPF maps profile, require bpftop to be installed"
	sudo bpftop

pprof_port ?= 8080
pprof_duration ?= 10 

.PHONY: profile-agent
profile-agent:
	@echo "Running Pprof profile over the node agent in user-space"
	go tool pprof -http=0.0.0.0:$(pprof_port) http://localhost:6262/debug/pprof/profile?seconds=$(pprof_duration)

archive ?= agent.gz
archive_cli ?= cli.gz
infer ?= infer
infer_gz ?= infer.gz
output ?= main
archive_out ?= out
controller_gz ?= controller.gz 



# generate compress archive for all exec for the agent to be deployed at endpoint 
.PHONY: build-archive-all
build-archive-all: clean_archives archive-endpoint-agent archive_cli archive_infer_server archive_controller  # Removed archive unless you define it

.PHONY: clean_archives
clean_archives:
	@if [ -d "$(archive_out)" ]; then \
		echo "Deleting directory $(archive_out)"; \
		rm -rf "$(archive_out)"; \
	fi
	@mkdir -p "$(archive_out)"

.PHONY: archive_cli
archive_cli:
	@echo "Compressing the endpoint security agent CLI..."
	cd cmd && rm -f "$(output)" && make build && tar -czaf "../$(archive_out)/$(archive_cli)" $(output)
	
.PHONY: archive_infer_server
archive_infer_server:
	@echo "Compressing the ONNX grpc inference server"
	cd model/rpc_onnx && make compile && tar -czaf $(infer_gz) infer && mv $(infer_gz) ../../$(archive_out)

.PHONY: archive_controller 
archive_controller:
	@echo "Compressing the controller jars, binaries"
	make build-controller && cd controller/bin && tar -czaf $(controller_gz) * && mv $(controller_gz) ../../$(archive_out)

.PHONY: archive-endpoint-agent
archive-endpoint-agent:
	go clean --cache 
	@echo "compressing the endpoint security agent ..."
	make build 
	cd package && tar -czaf "../$(archive_out)/$(archive)" .