#!/usr/bin/env bash
set -e

echo "[*] Killing old named and unbound processes if any..."
pkill -9 named 2>/dev/null || true
pkill -9 unbound 2>/dev/null || true

echo "[*] Cleaning up old network namespaces and bridge..."
for ns in dns-auth dns-res client rogue h1 h2 vic gw atk dst amp1 amp2 amp3; do
    ip netns del "$ns" 2>/dev/null || true
done
ip link del br0 2>/dev/null || true

echo "[*] Creating Linux Bridge br0..."
ip link add name br0 type bridge
ip link set dev br0 up

add_host() {
    local ns=$1
    local ip=$2
    echo "[*] Setting up DNS host $ns ($ip)..."
    
    ip netns add "$ns"
    ip link add "veth_${ns}" type veth peer name "${ns}0"
    ip link set "${ns}0" netns "$ns"
    ip link set "veth_${ns}" master br0
    ip link set "veth_${ns}" up
    
    ip netns exec "$ns" ip link set dev lo up
    ip netns exec "$ns" ip addr add "${ip}/24" brd 10.0.0.255 dev "${ns}0"
    ip netns exec "$ns" ip link set dev "${ns}0" up
}

add_host "dns-auth" "10.0.0.2"
add_host "dns-res"  "10.0.0.3"
add_host "client"   "10.0.0.4"
add_host "rogue"    "10.0.0.66"

echo "[*] Warming up ARP caches across LAN..."
for ip in 10.0.0.2 10.0.0.3 10.0.0.66; do
    ip netns exec client ping -c 1 -W 1 "$ip" >/dev/null 2>&1 || true
done

echo "[+] DNS Topology Ready on br0:"
echo "    - dns-auth: 10.0.0.2  (BIND9 DNSSEC Authoritative Server)"
echo "    - dns-res:  10.0.0.3  (Unbound Validating Resolver)"
echo "    - client:   10.0.0.4  (Client Query Node)"
echo "    - rogue:    10.0.0.66 (Rogue BIND9 Server - Unsigned)"

