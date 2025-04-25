model_path ?= model/dns_sec.onnx
DEBUG ?= false 

CONTROLLER_PORT ?= 8080
CONTROLLER_IMAGE_NAME ?= controller
CONTROLLER_IMAGE_TAG ?= latest

.PHONY: build 
build:
	bash build.sh 

.PHONY: node-metrics
node-metrics:
	@echo "starting the node exported metrics for monitor infrastructure at the node"
	cd bin/ && bash start.sh &

.PHONY: run_node_agent
run_node_agent:
	@echo "starting unix sock inference server $(model_path)"
	sudo python3 model/infer/inference.py -m $(model_path) &
	@echo "Booting up the node agent"
	cd node_agent && sudo ./main

.PHONY: build-controller
build-controller:
	@echo "Building the controller"
	@if [ -d "controller/bin" ]; then \
		echo "Deleting directory for previous controller build"; \
		rm -rf controller/bin; \
	fi
	@mkdir controller/bin
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
	cd controller && docker build -t $(CONTROLLER_IMAGE_NAME) . 

.PHONY: run-controller-image
run-controller-image:
	@echo "Running the controller"
	docker run --name controller -p $(CONTROLLER_PORT):9000 -d $(CONTROLLER_IMAGE_NAME):$(CONTROLLER_IMAGE_TAG) 

.PHONY: stop-controller-image
run-controller-image:
	@echo "Stopping the controller"
	docker kill controller

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
