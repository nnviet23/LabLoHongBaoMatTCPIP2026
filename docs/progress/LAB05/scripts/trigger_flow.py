#!/usr/bin/env python3
"""
Helper script running in victim namespace:
Generates an active outgoing UDP communication to target 10.0.1.5:80 from sport 12345.
This simulates active user traffic that triggers the kernel's routing lookup and socket state.
"""
import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 12345))
s.connect(("10.0.1.5", 80))
s.send(b"GET / HTTP/1.1\r\nHost: 10.0.1.5\r\n\r\n")
print("[+] Victim sent UDP traffic to 10.0.1.5:80 from sport 12345 (holding socket open for 2s)...")
time.sleep(2)
s.close()

