tc_kernel := dns_tc.c 
tc_kernel_out := tc.o 

bridge_tc_kernel := bridge_nf.c
bridge_tc_kernel_out := bridge.o 

xdp_kernel := dns_xdp.c 
xdp_kernel_out := xdp.o 

netlink_kernel := nf_sock.c
netlink_kernel_out := netlink.o

p2p_kernel := dns_tun.c
p2p_kernel_out := tun.o

sock_sdr := dns_sock.c 
sock_sdr_out := sock.o

# for arm compilation of cpu 
.PHONY: compile
compile:
	sudo clang -target bpf -fomit-frame-pointer -DLLVM_USE_LINKER -I/usr/include/aarch64-linux-gnu -g -O2 -o  $(tc_kernel_out) -c $(tc_kernel) 
	make vmlinux-btf
	sudo clang -target bpf -fomit-frame-pointer -DLLVM_USE_LINKER -I/usr/include/aarch64-linux-gnu -g -O2 -o  $(bridge_tc_kernel_out) -c $(bridge_tc_kernel)
	make netlink 
	make tc_tun 
	make xdp 
	cp $(tc_kernel_out) ../node_agent/ebpf/ 
	cp $(bridge_tc_kernel_out) ../node_agent/ebpf/ 
	make clean-bpf 


# kernel vmlinux compile for root struct header 
.PHONY: vmlinux-btf 
vmlinux-btf: 
	bpftool btf dump file /sys/kernel/btf/vmlinux format c   > vmlinux.h	

.PHONY: compile-llvm-arch 
compile-llvm-arch:
	@echo "emit llvm compile ir for the ebpf bytecode"
	sudo clang -target bpf -S -emit-llvm -I/usr/include/aarch64-linux-gnu -g -O3 -o ir/tc_ir -c $(tc_kernel)
	sudo clang -target bpf -S -I/usr/include/aarch64-linux-gnu -g -O2 -o ir/netlink_ir -c $(netlink_kernel) 


.PHONY: compile-llvm-x86
compile-llvm-x86:
	sudo clang -target bpf -flto -Wl,-plugin-opt=also-emit-llvm  -I/usr/include/x86_64-linux-gnu  -g -O3 -o $(tc_kernel_out) -c $(tc_kernel)
	cp tc.o ../node_agent
	cp bridge.o ../node_agent/ebpf/ 
	sudo llv-objdump -S tc.o 

# for x86 compilation of cpu 
.PHONY: compile-x86
compile-x86:
	sudo clang -target bpf -I/usr/include/x86_64-linux-gnu -g -O3 -o tc.o -o $(tc_kernel_out) -c $(tc_kernel) 
	make vmlinux-btf
	sudo clang -target bpf -I/usr/include/x86_64-linux-gnu -g -O3 -o bridge.o -o $(bridge_tc_kernel_out) -c $(bridge_tc_kernel)
	make netlink-x86  
	make tc-tun-x86
	make xdp-x86
	cp $(tc_kernel_out) ../node_agent/ebpf/ 
	cp $(bridge_tc_kernel_out) ../node_agent/ebpf/ 
	make clean-bpf 

# Kernel traffic ccontrol layer agnostic to CPU architecture 
.PHONY: tc
tc: 
	sudo tc qdisc add dev enp0s1 clsact
	sudo tc qdisc show 

.PHONY: tc-remove
tc-remove:
	sudo tc qdisc del dev enp0s1 clsact
	sudo tc qdisc del dev lo clsact
	sudo tc qdisc del dev docker0 clsact
	sudo tc qdisc del dev br0 clsact


.PHONY: tc-filter 
tc-filter:
	sudo tc filter add dev enp0s1 egress bpf direct-action obj tc.o sec tc
	# sudo tc filter add dev br0 egress bpf direct-action obj bridge.o sec tc 

.PHONY: tc-show 
tc-show:
	sudo tc qdisc show 
	sudo tc filter show dev enp0s1 egress 

.PHONY: tc-tracing 
tc-tracing:
	sudo cat /sys/kernel/debug/tracing/trace_pipe


.PHONY: xdp
xdp: 
	sudo clang -target bpf -I/usr/include/aarch64-linux-gnu  -g -O3 -o $(xdp_kernel_out) -c $(xdp_kernel)


.PHONY: xdp-x86
xdp-x86:
	sudo clang -target bpf -I/usr/include/x86_64-linux-gnu  -g -O3 -o $(xdp_kernel_out) -c $(xdp_kernel)


.PHONY: xdp-mount
xdp-mount:
	sudo clang -target bpf -I/usr/include/aarch64-linux-gnu  -g -O3 -o $(xdp_kernel_out) -c $(xdp_kernel)
	sudo mount -t bpf bpf /sys/fs/bpf/
	sudo ip link set dev enp0s1 xdp obj $(xdp_kernel_out) sec xdp


.PHONY: xdp-show
xdp-show:
	sudo ip link show dev enp0s1 
	sudo xdp-loader status 

.PHONY: xdp-mount-x86
xdp-mount-x86:
	sudo clang -target bpf -I/usr/include/x86_64-linux-gnu  -g -O3 -o $(xdp_kernel_out) -c $(xdp_kernel)
	sudo mount -t bpf bpf /sys/fs/bpf/
	sudo ip link set dev enp0s1 xdp obj $(xdp_kernel_out) sec xdp

.PHONY: xdp-umount
xdp-umount:
	sudo umount /sys/fs/bpf/
	sudo ip link set dev enp0s1 xdp off 
	sudo xdp-loader unload enp0s1 -all 

.PHONY: netlink
netlink: 
	@echo "Compiling the ebpf kprobe for tun/tap driver kernel for tun_chr_ioctl open socket for arm64"
	sudo clang -target bpf -fomit-frame-pointer  -DLLVM_USE_LINKER -I/usr/include/aarch64-linux-gnu -g -O2 -o  $(netlink_kernel_out) -c $(netlink_kernel) 
	cp $(netlink_kernel_out) ../node_agent/ebpf/ 

.PHONY: netlink-x86 
netlink-x86: 
	@echo "Compiling the ebpf kprobe for tun/tap driver kernel for tun_chr_ioctl open socket for x86" 
	sudo clang -target bpf -fomit-frame-pointer  -DLLVM_USE_LINKER -I/usr/include/x86_64-linux-gnu  -g -O2 -o  $(netlink_kernel_out) -c $(netlink_kernel) 
	cp $(netlink_kernel_out) ../node_agent/ebpf/ 


.PHONY: tc_tun 
tc_tun:
	@echo "Compiling the tunnel tc egress filter"
	sudo clang -target bpf -fomit-frame-pointer  -DLLVM_USE_LINKER -I/usr/include/aarch64-linux-gnu -g -O2 -o  $(p2p_kernel_out) -c $(p2p_kernel) 
	cp $(p2p_kernel_out) ../node_agent/ebpf/ 

.PHONY: tc-tun-x86 
	@echo "Compiling the tunnel tc egress filter for x86"
	sudo clang -target bpf -fomit-frame-pointer -DLLVM_USE_LINKER -I/usr/include/x86_64-linux-gnu  -g -O2 -o  $(p2p_kernel_out) -c $(p2p_kernel) 
	cp $(p2p_kernel_out) ../node_agent/ebpf/ 


.PHONY: sock_sdr
sock_sdr:
	echo "Compiling the ebpf kprobe for sock_sdr for kernel socket layer"
	sudo clang -target bpf -fomit-frame-pointer -DLLVM_USE_LINKER -I/usr/include/aarch64-linux-gnu -g -O2 -o  $(sock_sdr_out) -c $(sock_sdr)
	cp $(sock_sdr_out) ../node_agent/ebpf/

.PHONY: clean-bpf 
clean-bpf: 
	rm -rf *.o 
