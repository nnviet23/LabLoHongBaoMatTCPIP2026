#!/usr/bin/env bash
set -e

echo "[*] Cleaning up old network namespaces and bridges..."
for ns in h1 h2 vic gw atk dst amp1 amp2 amp3; do
    ip netns del "$ns" 2>/dev/null || true
done
ip link del br0 2>/dev/null || true

echo "[*] Creating network namespaces h1 (Attacker) and h2 (Victim)..."
ip netns add h1
ip netns add h2

echo "[*] Creating veth pair (veth1 <-> veth2)..."
ip link add veth1 type veth peer name veth2
ip link set veth1 netns h1
ip link set veth2 netns h2

echo "[*] Configuring IP addresses and bringing up interfaces..."
ip netns exec h1 ip link set dev lo up
ip netns exec h1 ip addr add 10.0.0.1/24 dev veth1
ip netns exec h1 ip link set dev veth1 up

ip netns exec h2 ip link set dev lo up
ip netns exec h2 ip addr add 10.0.0.2/24 dev veth2
ip netns exec h2 ip link set dev veth2 up

echo "[+] Verifying baseline ping connectivity between h1 and h2:"
ip netns exec h1 ping -c 2 10.0.0.2

echo "[+] Setup completed successfully. Topology:"
echo "    - h1 (Attacker): 10.0.0.1/24 (veth1)"
echo "    - h2 (Victim)  : 10.0.0.2/24 (veth2)"

