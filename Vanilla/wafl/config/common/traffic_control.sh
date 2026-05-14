# 0. Define the loss constant
LOSS_PERCENTAGE="0%"
P2P_PORT=10002
# 1. Detect the default interface
IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)
echo "Applying $LOSS_PERCENTAGE packet loss to interface: $IFACE on port $P2P_PORT"

# 2. Clear any existing tc rules to start fresh
sudo tc qdisc del dev $IFACE root 2>/dev/null

# 3. Create a priority queue with 4 bands
sudo tc qdisc add dev $IFACE root handle 1: prio bands 4

# 4. Attach the defined loss to the isolated 4th band
sudo tc qdisc add dev $IFACE parent 1:4 handle 40: netem loss $LOSS_PERCENTAGE

# 5. Filter TCP port $P2P_PORT into the lossy band
# 6. Filter UDP port $P2P_PORT into the lossy band
# IPv4 TCP
sudo tc filter add dev $IFACE protocol ip parent 1:0 flower \
  ip_proto tcp src_port $P2P_PORT flowid 1:4

# IPv4 UDP
sudo tc filter add dev $IFACE protocol ip parent 1:0 flower \
  ip_proto udp src_port $P2P_PORT flowid 1:4

# IPv6 TCP
sudo tc filter add dev $IFACE protocol ipv6 parent 1:0 flower \
  ip_proto tcp src_port $P2P_PORT flowid 1:4

# IPv6 UDP
sudo tc filter add dev $IFACE protocol ipv6 parent 1:0 flower \
  ip_proto udp src_port $P2P_PORT flowid 1:4
