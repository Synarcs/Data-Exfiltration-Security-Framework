

node_agent := main.go 
output ?= main 
debug ?= false 
ARCH := $(shell uname -m)

.PHONY: compile 
compile:
	@echo "Compiling the eBPF Node Agent for $(ARCH)"
	go build $(node_agent) 

.PHONY: run
run: 
	sudo setcap 'cap_bpf=ep cap_net_admin=ep cap_perfmon=ep ' main
	getcap ./main 

.PHONY: compile-kernel-ebpf
compile-kernel-ebpf:
	@echo "Compiling all the eBPF kernel programs for $(shell uname -m) arch"
	cd ../kernel && make

.PHONY: build-cli 
build-cli:
	@echo "Building eBPF Node Agent CLI for unix IPC"
	cd ../cmd && make build 

.PHONY: test
test:
	@echo "Running the eBPF Node Agent Unit Tests"
	go test --timeout 10s

.PHONY: build
build:
	@echo "Building and compiling the eBPF Node Agent {Kernel, User-Space}"
	make compile-kernel-ebpf
	make build-cli 
	make compile

.PHONY: run-inference
run-inference:
	@echo "Running the Remote unix socket inference server" 
	sudo python3 ../model/infer/inference.py  -m "../dns_sec.onnx"

.PHONY: run-inference-controller
run-inference-controller:
	@echo "Running the Remote unix socket inference server on controller server"
	sudo python3 ../model/infer/inference.py  -m "../dns_sec.onnx" -c true &
	@echo "Configure the Unix socket permissions and ownership  for inference"
	sleep 1.5 && sudo chmod 777 /etc/powerdns/onnx-inference-out.sock && sudo chmod 777 /etc/powerdns/onnx-inference-in.sock

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

