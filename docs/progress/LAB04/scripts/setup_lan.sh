#!/usr/bin/env bash
set -e

echo "[*] Cleaning up old network namespaces and bridge if any..."
for ns in atk vic amp1 amp2 amp3 h1 h2; do
    ip netns del "$ns" 2>/dev/null || true
done
ip link del br0 2>/dev/null || true

echo "[*] Creating Linux Bridge br0..."
ip link add name br0 type bridge
ip link set dev br0 up

# Function to create and attach a namespace to br0
add_host() {
    local ns=$1
    local ip=$2
    echo "[*] Setting up host $ns ($ip)..."
    
    ip netns add "$ns"
    ip link add "veth_${ns}" type veth peer name "${ns}0"
    ip link set "${ns}0" netns "$ns"
    ip link set "veth_${ns}" master br0
    ip link set "veth_${ns}" up
    
    # Configure inside netns
    ip netns exec "$ns" ip link set dev lo up
    ip netns exec "$ns" ip addr add "${ip}/24" brd 10.0.0.255 dev "${ns}0"
    ip netns exec "$ns" ip link set dev "${ns}0" up
}

add_host "atk"  "10.0.0.100"
add_host "vic"  "10.0.0.200"
add_host "amp1" "10.0.0.11"
add_host "amp2" "10.0.0.12"
add_host "amp3" "10.0.0.13"

echo "[*] Configuring amplifiers to respond to broadcast ICMP (icmp_echo_ignore_broadcasts = 0)..."
for h in amp1 amp2 amp3; do
    ip netns exec "$h" sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0
done

echo "[*] Warming up ARP cache between hosts..."
for h in amp1 amp2 amp3; do
    ip netns exec vic ping -c 1 -W 1 "10.0.0.${h#amp}" >/dev/null 2>&1 || true
done

echo "[+] LAN Topology Ready on br0:"
echo "    - atk:  10.0.0.100"
echo "    - vic:  10.0.0.200"
echo "    - amp1: 10.0.0.11 (ignore_broadcasts = 0)"
echo "    - amp2: 10.0.0.12 (ignore_broadcasts = 0)"
echo "    - amp3: 10.0.0.13 (ignore_broadcasts = 0)"

