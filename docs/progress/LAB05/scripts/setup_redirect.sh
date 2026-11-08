#!/usr/bin/env bash
set -e

echo "[*] Cleaning up old network namespaces and bridges..."
for ns in vic gw atk dst amp1 amp2 amp3 h1 h2; do
    ip netns del "$ns" 2>/dev/null || true
done
ip link del br0 2>/dev/null || true

echo "[*] Creating Linux Bridge br0 for LAN 10.0.0.0/24..."
ip link add name br0 type bridge
ip link set dev br0 up

# Function to connect a host to br0
add_lan_host() {
    local ns=$1
    local ip=$2
    echo "[*] Setting up LAN host $ns ($ip)..."
    
    ip netns add "$ns"
    ip link add "veth_${ns}" type veth peer name "${ns}0"
    ip link set "${ns}0" netns "$ns"
    ip link set "veth_${ns}" master br0
    ip link set "veth_${ns}" up
    
    ip netns exec "$ns" ip link set dev lo up
    ip netns exec "$ns" ip addr add "${ip}/24" brd 10.0.0.255 dev "${ns}0"
    ip netns exec "$ns" ip link set dev "${ns}0" up
}

# 1. Setup LAN hosts on br0
add_lan_host "vic" "10.0.0.2"
add_lan_host "gw"  "10.0.0.1"
add_lan_host "atk" "10.0.0.66"

# 2. Setup Point-to-Point link between gw and dst for 10.0.1.0/24
echo "[*] Setting up WAN/Destination network 10.0.1.0/24..."
ip netns add "dst"
ip netns exec dst ip link set dev lo up

ip link add "gw-d" type veth peer name "d-gw"
ip link set "gw-d" netns "gw"
ip link set "d-gw" netns "dst"

ip netns exec gw ip addr add 10.0.1.254/24 dev gw-d
ip netns exec gw ip link set dev gw-d up

ip netns exec dst ip addr add 10.0.1.5/24 dev d-gw
ip netns exec dst ip link set dev d-gw up

# 3. Configure routing
echo "[*] Configuring IP Forwarding and Routing..."
# gw acts as router
ip netns exec gw sysctl -w net.ipv4.ip_forward=1
ip netns exec gw sysctl -w net.ipv4.conf.all.send_redirects=0
ip netns exec gw sysctl -w net.ipv4.conf.default.send_redirects=0
ip netns exec gw sysctl -w net.ipv4.conf.gw0.send_redirects=0

# Default routes
ip netns exec vic ip route add default via 10.0.0.1 dev vic0
ip netns exec atk ip route add default via 10.0.0.1 dev atk0
ip netns exec dst ip route add default via 10.0.1.254 dev d-gw

# 4. Configure Victim to accept ICMP Redirects (Vulnerable State)
echo "[*] Configuring Victim (vic) to accept ICMP Redirects..."
for k in all default vic0; do
    ip netns exec vic sysctl -w net.ipv4.conf.$k.accept_redirects=1
    ip netns exec vic sysctl -w net.ipv4.conf.$k.secure_redirects=0
done

# 5. Warm up ARP caches
echo "[*] Warming up ARP caches across LAN..."
ip netns exec vic ping -c 1 -W 1 10.0.0.1 >/dev/null 2>&1 || true
ip netns exec vic ping -c 1 -W 1 10.0.0.66 >/dev/null 2>&1 || true
ip netns exec atk ping -c 1 -W 1 10.0.0.1 >/dev/null 2>&1 || true
ip netns exec atk ping -c 1 -W 1 10.0.0.2 >/dev/null 2>&1 || true
ip netns exec gw  ping -c 1 -W 1 10.0.1.5 >/dev/null 2>&1 || true

echo "[+] Lab 05 Topology Ready:"
echo "    - vic: 10.0.0.2  (via 10.0.0.1, accept_redirects=1)"
echo "    - gw:  10.0.0.1 (LAN) & 10.0.1.254 (WAN)"
echo "    - atk: 10.0.0.66 (LAN attacker)"
echo "    - dst: 10.0.1.5  (Target host behind gw)"

