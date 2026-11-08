#!/bin/bash
# setup_pair.sh - Thiết lập topology 2 namespace h1 và h2 kết nối qua veth pair
set -e

echo "[*] Cleaning up existing namespaces and links if any..."
ip netns del h1 2>/dev/null || true
ip netns del h2 2>/dev/null || true
ip link del veth1 2>/dev/null || true
ip link del veth2 2>/dev/null || true

echo "[*] Creating namespaces h1 (attacker) and h2 (victim)..."
ip netns add h1
ip netns add h2

echo "[*] Creating veth pair (veth1 <-> veth2)..."
ip link add veth1 type veth peer name veth2
ip link set veth1 netns h1
ip link set veth2 netns h2

echo "[*] Configuring IP addresses..."
ip netns exec h1 ip addr add 10.0.0.1/24 dev veth1
ip netns exec h2 ip addr add 10.0.0.2/24 dev veth2

echo "[*] Bringing up interfaces..."
ip netns exec h1 ip link set veth1 up
ip netns exec h2 ip link set veth2 up
ip netns exec h1 ip link set lo up
ip netns exec h2 ip link set lo up

echo "[*] Dropping automatic TCP RST from kernel on h1 (allows Scapy full control)..."
ip netns exec h1 iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

echo "[*] Mapping spoofed IP 10.0.0.77 to veth1 MAC on h2 (simulating on-path LAN reception)..."
VETH1_MAC=$(ip netns exec h1 cat /sys/class/net/veth1/address)
ip netns exec h2 ip neigh replace 10.0.0.77 lladdr "$VETH1_MAC" dev veth2

echo "[+] Setup completed successfully. Verifying connectivity:"
ip netns exec h1 ping -c2 10.0.0.2
