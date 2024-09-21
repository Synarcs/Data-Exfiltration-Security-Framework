
compile:
	sudo clang -target bpf -I/usr/include/aarch64-linux-gnu  -g -O3 -o icmp.o -c dns_tc.c  
	cp icmp.o ../node_agent/
	
tc:
	sudo tc qdisc add dev enp0s1 clsact
	sudo tc qdisc show 

tc-remove:
	sudo tc qdisc del dev enp0s1 clsact
	sudo tc qdisc del dev lo clsact
	sudo tc qdisc del dev docker0 clsact


tc-filter:
	sudo tc filter add dev enp0s1 egress bpf direct-action obj icmp.o sec tc

tc-show:
	sudo tc qdisc show 
	sudo tc filter show dev enp0s1 egress 

tc-tracing:
	sudo cat /sys/kernel/debug/tracing/trace_pipe
	