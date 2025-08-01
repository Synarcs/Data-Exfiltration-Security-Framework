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

all:
	@echo "building the framework"
	make build
	make build-controller

build-dep-framework:
	@echo "install kernel and user space dep and headers"
	make build-dep-agent:
	make build-dep-controller

###---------------------------------------- Data Plane ---------------------------------------###
.PHONY: build-dep-agent build-dep-controller build-dep-framework
		node-metrics build compile-kernel-bpf  
		build-cli compile-node-agent compile-node-agent-ld
		nfer-build run-agent run-agent-pidns 
		run-inference-python-onnx run-inference-controller-python-onnx 
		test-agent 

build-dep-agent:
	bash infrastructure/agent.sh

build-dep-controller:
	bash infrastructure/controller.sh

node-metrics:
	@echo "starting the node exported metrics for monitor infrastructure at the node"
	cd bin/ && bash start.sh &

netinet:
	@echo "Creating Network Overlay topology for eBPF Node agent via kernel veth brdiges and linux namespaces"
	bash scripts/brctl.sh

build:
	@echo "Building and compiling the eBPF Node Agent {Kernel, User-Space}"
	make compile-kernel-bpf
	make infer-build
	make build-cli 
	make infer-build

compile-kernel-bpf:
	@echo "Compiling all the eBPF kernel programs for $(shell uname -m) arch"
	cd kernel && make

build-cli:
	@echo "Building eBPF Node Agent CLI for unix IPC"
	cd cmd && make build 

# use this for smaller binaries for storage restricted endpoints 
compile-node-agent:
	@echo "Compiling the eBPF Node Agent for $(ARCH)"
	cd node_agent && go build -ldflags="-s -w" -o $(output)  $(node_agent) 

# static link for larger binary sizes 
compile-node-agent-ld:
	cd node_agent && go build -o $(output) $(node_agent)

infer-build:
	@echo "Building the ONXN RPC inference server"
	cd model/rpc_onnx && make compile

run-agent:
	@echo "building and running eBPF node_agent"
	make build && cd node_agent && sudo ./main 

build-run-pidns:
	@echo "building and runnign eBPF node_agent with isolated process namespace for security"
	make build 
	sudo unshare --pid --fork ./main

# for local testing to check compatibility of loaded onnx model ran by thte python ort inferencer
# note for live high throughput test its preferred to use the grpc cxx onnx inference for performance
run-inference-python-onnx:
	@echo "Running the Remote unix socket inference server" 
	sudo python3 ../model/infer/inference.py -m $(MODEL_PATH) 

run-inference-controller-python-onnx:
	@echo "Running the Remote unix socket inference server on controller server"
	sudo python3 ../model/infer/inference.py  -m $(MODEL_PATH) -c true  &
	@echo "Configure the Unix socket permissions and ownership  for inference"
	sleep 1.5 && sudo chmod 777 /etc/powerdns/onnx-inference-out.sock && sudo chmod 777 /etc/powerdns/onnx-inference-in.sock

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

.PHONY: build-controller build-controller-cni-sec run-controller-cni-sec
		build-controller-image run-controller-image stop-controller-image
		run-controller controller test-controller 

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

build-controller-cni-sec:
	@echo "Building the controller UNIX stream Inference NetworkPolicyHandlers"
	cd controller/cmd && go build -o ../bin/main main.go 

run-controller-cni-sec:
	@echo "Running the controller UNIX stream Inference NetworkPolicyHandlers"
	cd controller/bin && ./main

build-controller-image:
	@echo "Building the controller docker image"
	cd controller && docker build -t $(CONTROLLER_IMAGE_NAME) . 

run-controller-image:
	@echo "Running the controller"
	docker run --name controller -p $(CONTROLLER_PORT):9000 -d $(CONTROLLER_IMAGE_NAME):$(CONTROLLER_IMAGE_TAG) 

stop-controller-image:
	@echo "Stopping the controller"
	docker kill controller

run-controller:
	@echo "Running the controller"
	cd controller && java -jar bin/*.jar 

controller:
	@echo "Build and Run Controller" 
	make build-controller 
	make run-controller

test-controller:
	@echo "testing the controller"
	cd controller && mvn test 

###----------------------------------------------------------------------------------------------###

.PHONY: test-framework
test-framework:
	@echo "testing the framework"
	make test-agent
	make test-controller 

###------------------------------Framework RPC and protos (crypto, inference)--------------------###

.PHONY: build-framework-protos build-proto-dep

proto_path ?= exfil_sec_api/proto
go_out ?= exfil_sec_api
cxx_out ?= exfil_sec_api
cxx_proto_out ?= cxx 
proto_file_c := exfil_sec_controller.proto
proto_file_i := exfil_sec_inference.proto

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

build-proto-dep: 
	@echo "Installing all the required proto build deps" 
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	

###----------------------------------------------------------------------------------------------###


###------------------------------Framework becnh (data plane)------------------------------------###


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


###----------------------------------------------------------------------------------------------###



###----------------------------Archive framework components--------------------------------------###

.PHONY: build-archive-all clean_archives archive_cli archive_infer_server archive_controller out-archives-info

archive ?= agent.gz
archive_cli ?= cli.gz
infer ?= infer
infer_gz ?= infer.gz
output ?= main
archive_out ?= out
controller_gz ?= controller.gz 


# generate compress archive for all exec for the agent to be deployed at endpoint 
build-archive-all: clean_archives archive-endpoint-agent archive_cli archive_infer_server archive_controller out-archives-info

out-archives-info: 
	@echo "build and archived all the framework"
	tree -h $(archive_out)/

clean_archives:
	@if [ -d "$(archive_out)" ]; then \
		echo "Deleting directory $(archive_out)"; \
		rm -rf "$(archive_out)"; \
	fi
	@mkdir -p "$(archive_out)"

archive_cli:
	@echo "Compressing the endpoint security agent CLI..."
	cd cmd && rm -f "$(output)" && make build && tar -czaf "../$(archive_out)/$(archive_cli)" $(output)
	
archive_infer_server:
	@echo "Compressing the ONNX grpc inference server"
	cd model/rpc_onnx && make compile && tar -czaf $(infer_gz) infer && mv $(infer_gz) ../../$(archive_out)

archive_controller:
	@echo "Compressing the controller jars, binaries"
	make build-controller && cd controller/bin && tar -czaf $(controller_gz) * && mv $(controller_gz) ../../$(archive_out)

archive-endpoint-agent:
	go clean --cache 
	@echo "compressing the endpoint security agent ..."
	make build 
	cp run.sh package
	cd package && chmod +x run.sh && tar -czaf "../$(archive_out)/$(archive)" .

###----------------------------------------------------------------------------------------------###
