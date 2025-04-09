model_path ?= model/dns_sec.onnx
DEBUG ?= false 

.PHONY: build 
build:
	bash build.sh 

.PHONY: run_node_agent
run_node_agent:
	@echo "Creating required Network Topology for node agent"
	bash scripts/brctl.sh
	@echo "starting unix sock inference server $(model_path)"
	sudo python3 model/infer/inference.py -m $(model_path) &
	@echo "Booting up the node agent"
	cd node_agent && sudo ./main

.PHONY: build-controller
build-controller:
	@echo "Building the controller"
	cd controller && mvn clean package && cp target/node-agent-controller-1.0-SNAPSHOT.jar bin/ && mvn clean 
	@echo "Building the controller UNIX stream Inference NetworkPolicyHandlers"
	cd controller/cmd && go build -o ../bin/main main.go 

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
	cd controller && docker build -t controller . 

.PHONY: run-controller-image
run-controller-image:
	@echo "Running the controller"
	docker run --name controller -p 9000:9000 -d controller:latest 

.PHONY: run-controller
run-controller:
	@echo "Running the controller"
	cd controller && java -jar bin/node-agent-controller-1.0-SNAPSHOT.jar 

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

.PHONY: test-framework
test-framework:
	@echo "testing the framework"
	@echo "testing the eBPF node agent User space code"
	cd node_agent && make test
	
	@echo "testing the controller"
	cd controller && mvn test 

.PHONY: install-dep-build
install-dep:
	@echo "install kernel and user space dep and headers"
	bash infrastructure/agent.sh
	bash infrastructure/monitor.sh 

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
