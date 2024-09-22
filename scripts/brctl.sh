sudo ip netns 


# sx1 used for egress redirection done via same bridge 

sudo iptables --policy FORWARD ACCEPT

sudo ip netns add sx1
sudo ip netns add sx2

# create a bridge
sudo ip link add br0 type bridge

sudo ip link add sx1-eth0 type veth peer name sx1-eth0-br
sudo ip link add sx2-eth0 type veth peer name sx2-eth0-br

sudo ip link set sx1-eth0 netns sx1
sudo ip link set sx2-eth0 netns sx2


sudo ip link set sx1-eth0-br master br0
sudo ip link set sx2-eth0-br master br0

sudo ip link set br0 up
sudo ip link set sx1-eth0-br up
sudo ip link set sx2-eth0-br up

# assign ip addresses to the interfaces
sudo ip netns exec sx1 ip addr add 10.200.0.1/24 dev sx1-eth0
sudo ip netns exec sx2 ip addr add 10.200.0.2/24 dev sx2-eth0

# configure loopback interfaces
sudo ip netns exec sx1 ip link set lo up
sudo ip netns exec sx2 ip link set lo up

# configure interfaces for the veth pairs
sudo ip netns exec sx1 ip link set sx1-eth0 up
sudo ip netns exec sx2 ip link set sx2-eth0 up

sudo ip netns exec sx1 ip neigh show 
sudo ip netns exec sx2 ip neigh show

suod ip netns exec sx1 arp 
suod ip netns exec sx2 arp 

sudo ip addr add 10.200.0.0/24 dev br0

sudo ip netns exec sx1 ip route add 192.168.64.0/24 via 10.200.0.0
sudo ip netns exec sx1 ip route add 192.168.64.0/24 via 10.200.0.0


