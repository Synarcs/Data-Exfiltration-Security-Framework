tc_kernel := dns_tc.c 
tc_kernel_out := tc.o 

bridge_tc_kernel_ingress := bridge_tc_ing.c
bridge_tc_kernel_ingress_out := bridge_ing.o 

bridge_tc_kernel_egress := bridge_tc_egress.c
bridge_tc_kernel_egress_out := bridge_egress.o 

xdp_kernel := dns_xdp.c 
xdp_kernel_out := xdp.o 

netlink_kernel := nf_sock.c
netlink_kernel_out := netlink.o

tracepoint_kernel := prockill.c 
tracepoint_kernel_out := tracepoint.o

p2p_kernel := dns_tun.c
p2p_kernel_out := tun.o

sock_sdr := dns_sock_ops.c 
sock_sdr_out := sock.o

CLANG := clang 
CXFLAGS := -g -O2 -Wall -DLLVM_USE_LINKER -fomit-frame-pointer
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
LLVM_IR_ARGS := -S -emit-llvm 
KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)
BPF_CFLAGS := -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -I$(KERNEL_HEADERS)


# tc bpf qdisc iprotue2 comm 
QDISC := clsact
QDISC_RM := sudo tc $(QDISC) del dev
QDISC_ADD := sudo tc $(QDISC) add dev

# for arm compilation of cpu 
.PHONY: compile
compile:
	$(CLANG) $(CXFLAGS) $(BPF_CFLAGS) -o $(tc_kernel_out) -c $(tc_kernel) 
	make vmlinux-btf
	$(CLANG) $(CXFLAGS) $(BPF_CFLAGS) -o  $(bridge_tc_kernel_ingress_out) -c $(bridge_tc_kernel_ingress)
	$(CLANG) $(CXFLAGS) $(BPF_CFLAGS) -o  $(bridge_tc_kernel_egress_out) -c $(bridge_tc_kernel_egress)
	make crypto
	make netlink 
	make tc_tun 
	make tracepoints
	make sock 
	make xdp 
	cp $(tc_kernel_out) ../node_agent/ebpf/ 
	cp $(bridge_tc_kernel_egress_out) ../node_agent/ebpf/ 
	cp $(bridge_tc_kernel_ingress_out) ../node_agent/ebpf/ 
	make clean-bpf-build

# kernel vmlinux compile for root struct header 
.PHONY: vmlinux-btf 
vmlinux-btf: 
	bpftool btf dump file /sys/kernel/btf/vmlinux format c   > vmlinux.h	

.PHONY: compile-llvm-arch 
compile-llvm-arch:
	@echo "emit llvm compile ir for the ebpf bytecode"
	$(CLANG) $(LLVM_IR_ARGS) $(BPF_CFLAGS) -o ir/tc_ir -c $(tc_kernel)


# Kernel traffic ccontrol layer agnostic to CPU architecture 
.PHONY: tc
tc: 
	$(QDISC_ADD) dev enp0s1 clsact
	$(QDISC_ADD) dev br0 clsact
	sudo tc qdisc show 

.PHONY: tc-remove-vm
tc-remove-vm:
	$(QDISC_RM) eth0 $(QDISC) 
	# cloud vm usually have eth0 for receiver link name 


.PHONY: tc-remove
tc-remove:
	$(QDISC_RM) enp0s1 $(QDISC)
	$(QDISC_RM) docker0 $(QDISC)
	$(QDISC_RM) br0 $(QDISC)


.PHONY: tc-filter 
tc-filter:
	$(QDISC_ADD) enp0s1 egress bpf direct-action obj $(tc_kernel_out) sec tc
	$(QDISC_ADD) br0 ingress bpf direct-action obj $(bridge_tc_kernel_ingress_out) sec tc
	# sudo tc filter add dev br0 egress bpf direct-action obj bridge.o sec tc 

.PHONY: tc-show 
tc-show:
	sudo tc qdisc show 
	sudo tc filter show dev enp0s1 egress 
	sudo tc filter show dev br0 ingress 

.PHONY: tc-tracing 
tc-tracing:
	sudo cat /sys/kernel/debug/tracing/trace_pipe

.PHONY: xdp
xdp: 
	$(CLANG) $(CXFLAGS) $(BPF_CFLAGS) -o $(xdp_kernel_out) -c $(xdp_kernel)

.PHONY: xdp-mount
xdp-mount:
	make xdp 
	sudo mount -t bpf bpf /sys/fs/bpf/
	sudo ip link set dev enp0s1 xdp obj $(xdp_kernel_out) sec xdp


.PHONY: xdp-show
xdp-show:
	sudo ip link show dev enp0s1 
	sudo xdp-loader status 

.PHONY: xdp-umount
xdp-umount:
	sudo umount /sys/fs/bpf/
	sudo ip link set dev enp0s1 xdp off 
	sudo xdp-loader unload enp0s1 -all 

.PHONY: netlink
netlink: 
	@echo "Compiling the ebpf kprobe for tun/tap driver kernel for tun_chr_ioctl open socket for arm64"
	$(CLANG) $(CXFLAGS) $(BPF_CFLAGS) -o  $(netlink_kernel_out) -c $(netlink_kernel) 
	cp $(netlink_kernel_out) ../node_agent/ebpf/ 

.PHONY: tracepoints
tracepoints:
	@echo "Compiling the ebpf tracepoints for arm64"
	$(CLANG) $(CXFLAGS) $(BPF_CFLAGS) -o  $(tracepoint_kernel_out) -c $(tracepoint_kernel) 
	cp $(tracepoint_kernel_out) ../node_agent/ebpf/ 

.PHONY: tc_tun 
tc_tun:
	@echo "Compiling the tunnel tc egress filter"
	$(CLANG) $(CXFLAGS) $(BPF_CFLAGS) -o  $(p2p_kernel_out) -c $(p2p_kernel) 
	cp $(p2p_kernel_out) ../node_agent/ebpf/ 

.PHONY: sock
sock:
	echo "Compiling the sock ebpf program for exfil security over kernel sock o setup operation for UDP socket"
	$(CLANG) $(CXFLAGS) $(BPF_CFLAGS) -o  $(sock_sdr_out) -c $(sock_sdr)
	cp $(sock_sdr_out) ../node_agent/ebpf/

.PHONY: clean-bpf-build
clean-bpf-build: 
	rm -rf *.o 
	rm -rf vmlinux.h 

crypto_kernel ?= $(shell pwd)/lsm_bpf.c
crypto_kernel_out ?= lsm_bpf.o 

.PHONY: crypto 
crypto:
	@echo "Compiling the crypto LSM hooks"
	$(CLANG) $(CXFLAGS) $(BPF_CFLAGS) -o  $(crypto_kernel_out) -c $(crypto_kernel) 
	cp $(crypto_kernel_out) ../node_agent/ebpf/ 
