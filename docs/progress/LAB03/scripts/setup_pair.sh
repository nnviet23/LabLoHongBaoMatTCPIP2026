#!/bin/bash
# setup_pair.sh - Thiết lập topology 2 namespace h1 (Client) và h2 (Server) phục vụ ICMP Tunneling
set -e

echo "[*] Cleaning up existing namespaces and links if any..."
ip netns del h1 2>/dev/null || true
ip netns del h2 2>/dev/null || true
ip link del veth1 2>/dev/null || true
ip link del veth2 2>/dev/null || true

echo "[*] Creating namespaces h1 (client) and h2 (server)..."
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

echo "[*] Disabling kernel auto-reply on h2 (delegating all ICMP handling to user-space Scapy server)..."
ip netns exec h2 sysctl -w net.ipv4.icmp_echo_ignore_all=1

echo "[+] Verifying baseline ping connectivity before disabling ignore_all for test:"
# Tạm thời để ping baseline kiểm tra cáp ảo
ip netns exec h2 sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null
ip netns exec h1 ping -c2 10.0.0.2
ip netns exec h2 sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null
echo "[+] Setup completed. Kernel icmp_echo_ignore_all set to 1 on h2."

