
run:
	sudo clang -target bpf -I/usr/include/aarch64-linux-gnu -g -O3 -o xdp.o -c xdp.c

load:
	sudo bpftool prog load xdp.o /sys/fs/bpf/xdp

unload:
	#sudo bpftool prog show name xdp
	sudo rm /sys/fs/bpf/xdp

attach:
	sudo bpftool net attach xdp id 172 dev docker0
	# network attach <sec> bpf prog id dev <interface>

list:
	sudo bpftool prog list

detach:
	 sudo bpftool net detach xdp dev docker0

map:
	sudo bpftool map list

mapDump:
	sudo bpftool map dump xdp.bss

llvmDump:
	sudo llvm-objdump -S xdp.o
