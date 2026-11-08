#!/usr/bin/env python3
# icmp_server.py - Máy chủ ICMP Tunnel lắng nghe trên veth2 và giải mã payload
from scapy.all import sniff, IP, ICMP, send
import sys

def handle(p):
    if p.haslayer(ICMP) and p[ICMP].type == 8:  # Echo Request
        data = bytes(p[ICMP].payload)
        print(f"[server] nhan ({len(data)} bytes): {data}", flush=True)
        # Gửi Echo Reply mang tiền tố ACK kèm dữ liệu gốc (kênh 2 chiều)
        reply = IP(dst=p[IP].src) / ICMP(type=0, id=p[ICMP].id, seq=p[ICMP].seq) / (b"ACK:" + data)
        send(reply, verbose=0)

print("[server] dang lang nghe ICMP tren veth2 ...", flush=True)
sniff(iface="veth2", filter="icmp", prn=handle)

