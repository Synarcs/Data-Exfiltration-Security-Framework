sudo ip netns 


# sx1 used for egress redirection done via same bridge 

sudo iptables --policy FORWARD ACCEPT 
sudo iptables -I FORWARD -i bridge -j ACCEPT

sudo ip6tables --policy FORWARD ACCEPT 
sudo ip6tables -I FORWARD -i bridge -j ACCEPT

sudo sysctl -w net.ipv6.conf.all.forwarding=1

sudo ip netns add sx1
sudo ip netns add sx2

sudo ip netns exec sx1 sysctl -w net.ipv6.conf.all.forwarding=1
sudo ip netns exec sx2 sysctl -w net.ipv6.conf.all.forwarding=1

# create a bridge
sudo ip link add br0 type bridge

# create a bridge for non root protocol packet dpi as host bridge packet transfer to host inet 
sudo ip link add nx-br0 type bridge
sudo ip link set dev nx-br0 up 
sudo ip addr add 10.210.0.0/24 dev nx-br0

sudo sysctl -w net.ipv6.conf.nx-br0.proxy_ndp=1
sudo sysctl -w net.ipv6.conf.nx-br0.disable_ipv6=0
sudo sysctl -w net.ipv4.conf.all.forwarding=1
sudo ip -6 addr add fe80::c641:065a:7a1a:642d/64 dev nx-br0

sudo ip netns add sx3 
sudo ip netns exec sx3 sysctl -w net.ipv6.conf.all.forwarding=1 
sudo ip link add nx-br0-eth0 type veth peer name nx-br0-eth0-br 

sudo ip link set nx-br0-eth0 netns sx3  
sudo ip link set nx-br0-eth0-br master nx-br0 
sudo ip link set dev nx-br0-eth0-br up 




sudo sysctl -w net.ipv6.conf.br0.proxy_ndp=1
sudo ip -6 neigh add proxy fe80::d091:3cff:fe25:6d96 dev br0
sudo ip -6 neigh add proxy fe80::d091:3cff:fe25:6d97 dev br0    

sudo ip link add sx1-eth0 type veth peer name sx1-eth0-br
sudo ip link add sx2-eth0 type veth peer name sx2-eth0-br

sudo ip link set sx1-eth0 netns sx1
sudo ip link set sx2-eth0 netns sx2


sudo ip link set sx1-eth0-br master br0
sudo ip link set sx2-eth0-br master br0

sudo ip link set br0 up
sudo ip link set sx1-eth0-br up
sudo ip link set sx2-eth0-br up

# assign ip addresses to the interfaces for Ipv4 layer 
sudo ip netns exec sx1 ip addr add 10.200.0.1/24 dev sx1-eth0
sudo ip netns exec sx2 ip addr add 10.200.0.2/24 dev sx2-eth0

# disable the autoconfiguration of the interfaces over ipv6 layer 
sudo ip netns exec sx1 sysctl -w net.ipv6.conf.sx1-eth0.autoconf=0
sudo ip netns exec sx2 sysctl -w net.ipv6.conf.sx2-eth0.autoconf=0

# log the ipv6 autoconfiguration of the interfaces in sysctl kernel config called via the kernel bridge on host 
sudo ip netns exec sx1 cat /proc/sys/net/ipv6/conf/sx1-eth0/autoconf 
sudo ip netns exec sx2 cat /proc/sys/net/ipv6/conf/sx1-eth0/autoconf 

sudo ip netns exec sx1 ip -6 addr add fe80::d091:3cff:fe25:6d96/64 dev sx1-eth0
sudo ip netns exec sx2 ip -6 addr add fe80::d091:3cff:fe25:6d97/64 dev sx2-eth0

# configure loopback interfaces
sudo ip netns exec sx1 ip link set lo up
sudo ip netns exec sx2 ip link set lo up

# configure interfaces for the veth pairs
sudo ip netns exec sx1 ip link set sx1-eth0 up
sudo ip netns exec sx2 ip link set sx2-eth0 up

sudo ip netns exec sx1 ip neigh show 
sudo ip netns exec sx2 ip neigh show

sudo ip netns exec sx1 arp 
sudo ip netns exec sx2 arp 


# fe80::d091:3cff:fe25:6d95/64
sudo sysctl -w  net.ipv6.conf.br0.autoconf=0
sudo ip addr add 10.200.0.0/24 dev br0
sudo ip -6 addr add fe80::d091:3cff:fe25:6d95/64 dev br0


# default route via the kernel host bridge as an interface on the host physcial bridge 
sudo ip netns exec sx1 ip route add 192.168.64.0/24 via 10.200.0.0
sudo ip netns exec sx2 ip route add 192.168.64.0/24 via 10.200.0.0