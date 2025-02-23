model_path ?= model/dns_sec.onnx
DEBUG ?= false 

.PHONY: build 
build:
	bash build.sh 

.PHONY: run_node_agent
run_node_agent:
	@echo "Booting up the node agent"
	echo "starting unix sock inference server $(model_path)"
	sudo python3 model/infer/inference.py -m $(model_path) &
	cd node_agent && sudo ./main

.PHONY: build-controller
build-controller:
	@echo "Building the controller"
	cd controller && mvn clean package  

.PHONY: run-controller
run-controller:
	@echo "Running the controller"
	cd controller && java -jar target/node-agent-controller-1.0-SNAPSHOT.jar

.PHONY: controller 
controller:
	@echo "Build and Run Controller" 
	make build-controller 
	make run-controller

.PHONY: build-framework 
build-framework:
	@echo "building the framework"
	make build
	make build-controller

QPS ?= 100000
DURATION ?= 20

.PHONY: bench
bench:
	cd scripts/bench  && bash bench.sh dnsperf $(QPS) $(DURATION)

.PHONY: gazelle-update-repos
gazelle-update-repos:
	bazel run //:gazelle -- update-repos -from_file=go.mod
    bazel run //:gazelle 

.PHONY: gazelle-build
gazelle-build:
	bazel build --repo_env=CC=clang  //... && bazel run //node_agent

.PHONY: gazelle
gazelle:
	bazel run //:gazelle 

.PHONY: node_agent
node_agent:
	bazel build //node_agent 

.PHONY: kernel
kernel:
	bazel run //:kernel 
