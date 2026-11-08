#!/bin/bash
# setup_pair.sh - Thiết lập topology 2 namespace h1 và h2 phục vụ kiểm thử IP Source Routing
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

echo "[*] Recreating vulnerable condition: accept_source_route=1, rp_filter=0, ip_forward=1..."
for k in all default lo veth2; do
  ip netns exec h2 sysctl -w net.ipv4.conf.$k.accept_source_route=1
  ip netns exec h2 sysctl -w net.ipv4.conf.$k.rp_filter=0
done
ip netns exec h2 sysctl -w net.ipv4.ip_forward=1

for k in all default lo veth1; do
  ip netns exec h1 sysctl -w net.ipv4.conf.$k.accept_source_route=1
  ip netns exec h1 sysctl -w net.ipv4.conf.$k.rp_filter=0
done
ip netns exec h1 sysctl -w net.ipv4.ip_forward=1

echo "[+] Setup completed successfully. Verifying connectivity:"
ip netns exec h1 ping -c2 10.0.0.2
