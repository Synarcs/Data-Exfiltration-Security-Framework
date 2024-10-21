tc_kernel := dns_tc.c 
tc_kernel_out := tc.o 

bridge_tc_kernel := bridge_tc.c
bridge_tc_kernel_out := bridge.o 

xdp_kernel := dns_xdp.c 
xdp_kernel_out := xdp.o 


# for arm compilation of cpu 
.PHONY: compile
compile:
	sudo clang -target bpf -I/usr/include/aarch64-linux-gnu -g -O3 -o  $(tc_kernel_out) -c $(tc_kernel) 
	sudo clang -target bpf -I/usr/include/aarch64-linux-gnu -g -O3 -o  $(bridge_tc_kernel_out) -c $(bridge_tc_kernel)
	cp tc.o ../node_agent/
	cp bridge.o ../node_agent/


.PHONY: compile-llvm-arch 
compile-llvm-arch:
	sudo clang -target bpf -flto -Wl,-plugin-opt=also-emit-llvm -I/usr/include/aarch64-linux-gnu -g -O3 -o $(tc_kernel_out) -c $(tc_kernel)
	cp tc.o ../node_agent/
	cp bridge.o ../node_agent/
	sudo llv-objdump -S tc.o 

.PHONY: compile-llvm-x86
compile-llvm-x86:
	sudo clang -target bpf -flto -Wl,-plugin-opt=also-emit-llvm -g -O3 -o $(tc_kernel_out) -c $(tc_kernel)
	cp tc.o ../node_agent/
	cp bridge.o ../node_agent/
	sudo llv-objdump -S tc.o 

# for x86 compilation of cpu 
.PHONY: compile-x86
compile-x86:
	sudo clang -target bpf -g -O3 -o tc.o -c $(tc_kernel)
	sudo clang -target bpf -g -O3 -o bridge.o -c $(bridge_tc)
	cp tc.o ../node_agent/
	cp bridge.o ../node_agent/

.PHONY: tc
tc: 
	sudo tc qdisc add dev enp0s1 clsact
	sudo tc qdisc show 

.PHONY: tc-remove
tc-remove:
	sudo tc qdisc del dev enp0s1 clsact
	sudo tc qdisc del dev lo clsact
	sudo tc qdisc del dev docker0 clsact


.PHONY: tc-filter 
tc-filter:
	sudo tc filter add dev enp0s1 egress bpf direct-action obj tc.o sec tc

.PHONY: tc-show 
tc-show:
	sudo tc qdisc show 
	sudo tc filter show dev enp0s1 egress 

.PHONY: tc-tracing 
tc-tracing:
	sudo cat /sys/kernel/debug/tracing/trace_pipe


.PHONY: xdp-compile
xdp-compile:
	sudo clang -target bpf -I/usr/include/aarch64-linux-gnu  -g -O3 -o $(xdp_kernel_out) -c $(xdp_kernel)
	sudo mount -t bpf bpf /sys/fs/bpf/
	sudo ip link set dev enp0s1 xdp obj $(xdp_kernel_out) sec xdp


.PHONY: xdp-compile-x86
xdp-compile-x86:
	sudo clang -target bpf -I/usr/include/aarch64-linux-gnu  -g -O3 -o $(xdp_kernel_out) -c $(xdp_kernel)
	sudo mount -t bpf bpf /sys/fs/bpf/
	sudo ip link set dev enp0s1 xdp obj $(xdp_kernel_out) sec xdp

.PHONY: xdp-umount
xdp-umount:
	sudo umount /sys/fs/bpf/
	sudo ip link set dev enp0s1 xdp off 
	sudo xdp-loader unload enp0s1 --all 

