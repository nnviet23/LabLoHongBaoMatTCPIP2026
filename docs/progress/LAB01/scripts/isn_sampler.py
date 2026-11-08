#!/usr/bin/env python3
# isn_sampler.py - Thu thập 30 ISN từ h2 qua port 9000 và tính độ chênh lệch delta
from scapy.all import IP, TCP, sr1, send, RandShort
import sys

target_ip = "10.0.0.2"
target_port = 9000
src_ip = "10.0.0.1"

isns = []
print(f"[*] Starting collection of 30 ISN samples from {target_ip}:{target_port}...")

for i in range(30):
    sport = int(RandShort())
    syn = IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=target_port, flags="S", seq=1000)
    ans = sr1(syn, timeout=1, verbose=0)
    if ans and ans.haslayer(TCP) and (ans[TCP].flags & 0x12) == 0x12:  # SYN+ACK
        isns.append(ans[TCP].seq)
        # Gửi RST đóng kết nối để giải phóng socket trên server
        send(IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=target_port, flags="R", seq=1001), verbose=0)
    else:
        print(f"[-] No SYN/ACK received on attempt {i+1}", file=sys.stderr)

print(f"\n[+] Total ISN collected: {len(isns)}")
print(f"{'Index':<6} {'Hex ISN':<14} {'Decimal ISN':<15}")
print("-" * 40)
for idx, x in enumerate(isns, 1):
    print(f"{idx:<6} {hex(x):<14} {x:<15}")

print("\n--- Chênh lệch (Delta) giữa các ISN liên tiếp (ISN[i+1] - ISN[i]) ---")
for idx, (a, b) in enumerate(zip(isns, isns[1:]), 1):
    diff = b - a
    print(f"Delta #{idx:<2} (ISN_{idx+1} - ISN_{idx}): {diff:+12d} (Mod 2^32 Hex: {hex(diff & 0xffffffff)})")

