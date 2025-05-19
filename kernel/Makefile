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

crypto_kernel ?= $(shell pwd)/lsm_bpf.c
crypto_kernel_out ?= lsm_bpf.o 

CC := clang 
CXFLAGS := -g -O2 -Wall -DLLVM_USE_LINKER -fomit-frame-pointer
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
LLVM_CX_IR_ARGS := -S -emit-llvm 
KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)
KERNEL_HEADERS_DEFS := /usr/include/$(shell uname -m)-linux-gnu
TARGET := bpf
BPF_CFLAGS := -target $(TARGET) \
              -D__TARGET_ARCH_$(ARCH) \
              -I$(KERNEL_HEADERS_DEFS) \
              -I$(KERNEL_HEADERS)

LLVM_STAT_COMPILER := llc 

TRACE_FS_PIPE := /sys/kernel/debug/tracing/trace_pipe
BPF_FS_MNT := /sys/fs/bpf					 # map and xdp prog mount over kernel bpfs   

# tc 
QDISC := clsact
QDISC_RM := sudo tc qdisc del 
QDISC_ADD := sudo tc qdisc add 
QDISC_FILTER_ADD := sudo tc filter add 
QDISC_FILTER_RM := sudo tc filter del 


# vmlinux for raw tc, rtkprobes, kprobes kernel eBPF programs 
VMLINUX_MNT ?= /sys/kernel/btf/vmlinux
EBPF_PROG_OUT_PATH ?= ../node_agent/ebpf/

.PHONY: compile vmlinux-btf bpf-compile compiled_loader clean-bpf-build

# for arm compilation of cpu 
compile: vmlinux-btf bpf-compile compiled_loader clean-bpf-build

bpf-compile:
	$(CC) $(CXFLAGS) $(BPF_CFLAGS) -o $(tc_kernel_out) -c $(tc_kernel) 
	$(CC) $(CXFLAGS) $(BPF_CFLAGS) -o  $(bridge_tc_kernel_ingress_out) -c $(bridge_tc_kernel_ingress)
	$(CC) $(CXFLAGS) $(BPF_CFLAGS) -o  $(bridge_tc_kernel_egress_out) -c $(bridge_tc_kernel_egress)
	$(CC) $(CXFLAGS) $(BPF_CFLAGS) -o $(xdp_kernel_out) -c $(xdp_kernel)
	@echo "Compiling the ebpf kprobe for tun/tap driver kernel for tun_chr_ioctl open socket for arm64"
	$(CC) $(CXFLAGS) $(BPF_CFLAGS) -o  $(netlink_kernel_out) -c $(netlink_kernel) 
	@echo "Compiling the ebpf tracepoints for arm64"
	$(CC) $(CXFLAGS) $(BPF_CFLAGS) -o  $(tracepoint_kernel_out) -c $(tracepoint_kernel) 
	@echo "Compiling the tunnel tc egress filter"
	$(CC) $(CXFLAGS) $(BPF_CFLAGS) -o  $(p2p_kernel_out) -c $(p2p_kernel) 
	echo "Compiling the sock ebpf program for exfil security over kernel sock o setup operation for UDP socket"
	$(CC) $(CXFLAGS) $(BPF_CFLAGS) -o  $(sock_sdr_out) -c $(sock_sdr)
	@echo "Compiling the crypto LSM hooks"
	$(CC) $(CXFLAGS) $(BPF_CFLAGS) -o  $(crypto_kernel_out) -c $(crypto_kernel) 

compiled_loader:
	cp $(tc_kernel_out) $(EBPF_PROG_OUT_PATH)
	cp $(bridge_tc_kernel_egress_out) $(EBPF_PROG_OUT_PATH)
	cp $(bridge_tc_kernel_ingress_out) $(EBPF_PROG_OUT_PATH)
	cp $(netlink_kernel_out) $(EBPF_PROG_OUT_PATH)
	cp $(p2p_kernel_out) $(EBPF_PROG_OUT_PATH)
	cp $(sock_sdr_out) $(EBPF_PROG_OUT_PATH)
	cp $(tracepoint_kernel_out) $(EBPF_PROG_OUT_PATH)
	cp $(crypto_kernel_out) $(EBPF_PROG_OUT_PATH)

# kernel vmlinux compile for root struct header 
vmlinux-btf: 
	bpftool btf dump file $(VMLINUX_MNT) format c   > vmlinux.h	

.PHONY: compile-llvm-ir 
compile-llvm-ir:
	@echo "emit llvm compile ir for the ebpf bytecode"
	make vmlinux-btf
	$(CC) $(LLVM_CX_IR_ARGS) $(BPF_CFLAGS) -o ir/tc_ir -c $(tc_kernel)
	$(CC) $(LLVM_CX_IR_ARGS) $(BPF_CFLAGS) -o ir/bridge_in_ir -c $(bridge_tc_kernel_ingress)
	$(CC) $(LLVM_CX_IR_ARGS) $(BPF_CFLAGS) -o ir/bridge_out_ir -c $(bridge_tc_kernel_egress)
	$(CC) $(LLVM_CX_IR_ARGS) $(BPF_CFLAGS) -o ir/xdp_ir -c $(xdp_kernel)
	$(CC) $(LLVM_CX_IR_ARGS) $(BPF_CFLAGS) -o ir/netlink_ir -c $(netlink_kernel)
	$(CC) $(LLVM_CX_IR_ARGS) $(BPF_CFLAGS) -o ir/tracepoint_ir -c $(tracepoint_kernel)
	$(CC) $(LLVM_CX_IR_ARGS) $(BPF_CFLAGS) -o ir/p2p_ir -c $(p2p_kernel) # socker over p2p netdev in kernel 
	$(CC) $(LLVM_CX_IR_ARGS) $(BPF_CFLAGS) -o ir/sock_ir -c $(sock_sdr) 
	$(CC) $(LLVM_CX_IR_ARGS) $(BPF_CFLAGS) -o ir/lsm_ir -c $(crypto_kernel) 
	make clean-bpf-build

# builds bpf object compiled back from llvm ir 
.PHONY: llvm-bpf
llvm-bpf:
	$(LLVM_STAT_COMPILER) -march=bpf -filetype=obj -o $(sock_sdr_out)  ir/sock_ir
	$(LLVM_STAT_COMPILER) -march=bpf -filetype=obj -o $(p2p_kernel_out) ir/p2p_ir
	$(LLVM_STAT_COMPILER) -march=bpf -filetype=obj -o $(tracepoint_kernel_out) ir/tracepoint_ir
	$(LLVM_STAT_COMPILER) -march=bpf -filetype=obj -o $(netlink_kernel_out) ir/netlink_ir
	$(LLVM_STAT_COMPILER) -march=bpf -filetype=obj -o $(crypto_kernel_out)  ir/lsm_ir
	$(LLVM_STAT_COMPILER) -march=bpf -filetype=obj -o $(bridge_tc_kernel_ingress_out) ir/bridge_in_ir
	$(LLVM_STAT_COMPILER) -march=bpf -filetype=obj -o $(bridge_tc_kernel_egress_out) ir/bridge_out_ir
	make clean-bpf-build


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
	$(QDISC_FILTER_ADD) dev enp0s1 egress bpf direct-action obj $(tc_kernel_out) sec tc
	$(QDISC_FILTER_ADD) dev br0 ingress bpf direct-action obj $(bridge_tc_kernel_ingress_out) sec tc
	# sudo tc filter add dev br0 egress bpf direct-action obj bridge.o sec tc 

.PHONY: tc-show 
tc-show:
	sudo tc qdisc show 
	sudo tc filter show dev enp0s1 egress 
	sudo tc filter show dev br0 ingress 

.PHONY: tc-tracing 
tc-tracing:
	sudo cat $(TRACE_FS_PIPE)

.PHONY: xdp-mount
xdp-mount:
	make xdp 
	sudo mount -t bpf bpf $(BPF_FS_MNT)
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

clean-bpf-build: 
	rm -rf *.o 
	rm -rf vmlinux.h 


