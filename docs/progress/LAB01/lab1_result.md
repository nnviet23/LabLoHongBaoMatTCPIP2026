# NHẬT KÝ THỰC NGHIỆM CHI TIẾT: LAB 01
## TCP Initial Sequence Number (ISN) Prediction & Blind Spoofing

- **Thời gian thực thi:** 2026-11-08 (Kali VM Local Time: 23:53 - 23:57)
- **Hệ điều hành kiểm thử:** Kali Linux 6.12.30-1kali1 (x86_64) trên VMware
- **Môi trường:** Linux Network Namespaces (`h1`, `h2`) kết nối qua liên kết ảo `veth1 <-> veth2`
- **Công cụ điều khiển:** Scapy 2.6.1, tcpdump 4.99.5, ncat 7.95

---

### 1. Kết Quả Khởi Tạo Topology & Kiểm Tra Kết Nối (Ping)

Lệnh thực thi:
```bash
echo Aa@123456 | sudo -S bash /tmp/lab01/setup_pair.sh
```

**Nguyên văn Terminal Output:**
```text
[*] Cleaning up existing namespaces and links if any...
[*] Creating namespaces h1 (attacker) and h2 (victim)...
[*] Creating veth pair (veth1 <-> veth2)...
[*] Configuring IP addresses...
[*] Bringing up interfaces...
[*] Dropping automatic TCP RST from kernel on h1 (allows Scapy full control)...
[*] Mapping spoofed IP 10.0.0.77 to veth1 MAC on h2 (simulating on-path LAN reception)...
[+] Setup completed successfully. Verifying connectivity:
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.164 ms
64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=0.037 ms

--- 10.0.0.2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1019ms
rtt min/avg/max/mdev = 0.037/0.100/0.164/0.063 ms
```

---

### 2. Dịch Vụ Nền Lắng Nghe Trên Victim (h2)

Lệnh thực thi:
```bash
ip netns exec h2 ncat -lk 10.0.0.2 9000 &
ip netns exec h2 ss -tlpn
```

**Nguyên văn Terminal Output:**
```text
State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
LISTEN 0      10          10.0.0.2:9000      0.0.0.0:*     users:(("ncat",pid=21704,fd=3))
```

---

### 3. Thu Thập & Đo Lường 30 Mẫu TCP ISN (RFC 6528 Evaluation)

Lệnh thực thi:
```bash
ip netns exec h1 python3 /tmp/lab01/isn_sampler.py
```

**Nguyên văn Terminal Output:**
```text
[*] Starting collection of 30 ISN samples from 10.0.0.2:9000...

[+] Total ISN collected: 30
Index  Hex ISN        Decimal ISN    
----------------------------------------
1      0xf618972e     4128806702     
2      0x19641717     425989911      
3      0x2612e25f     638771807      
4      0x4d172232     1293361714     
5      0x135d6c6      20305606       
6      0x25acca2f     632080943      
7      0x7554926      123029798      
8      0x212a5416     556422166      
9      0x4688a6a7     1183360679     
10     0xd4b625ce     3568707022     
11     0xec8ee643     3968788035     
12     0x9bcda448     2613945416     
13     0x6af43bc1     1794390977     
14     0x37b81426     934810662      
15     0xd2882b07     3532139271     
16     0xd65458b7     3595851959     
17     0x4b883a23     1267218979     
18     0x4095e6f2     1083565810     
19     0x8cd259c9     2362595785     
20     0x4e925bd      82388413       
21     0xe53fcecd     3846164173     
22     0x3d25b3a2     1025880994     
23     0xceda4dff     3470413311     
24     0x6d1b9c9f     1830526111     
25     0x65e21410     1709315088     
26     0x1e7cc6a6     511493798      
27     0x8f134bab     2400406443     
28     0x60f167c1     1626433473     
29     0x19c98bb3     432638899      
30     0x8487539f     2223461279     

--- Chênh lệch (Delta) giữa các ISN liên tiếp (ISN[i+1] - ISN[i]) ---
Delta #1  (ISN_2 - ISN_1):  -3702816791 (Mod 2^32 Hex: 0x234b7fe9)
Delta #2  (ISN_3 - ISN_2):   +212781896 (Mod 2^32 Hex: 0xcaecb48)
Delta #3  (ISN_4 - ISN_3):   +654589907 (Mod 2^32 Hex: 0x27043fd3)
Delta #4  (ISN_5 - ISN_4):  -1273056108 (Mod 2^32 Hex: 0xb41eb494)
Delta #5  (ISN_6 - ISN_5):   +611775337 (Mod 2^32 Hex: 0x2476f369)
Delta #6  (ISN_7 - ISN_6):   -509051145 (Mod 2^32 Hex: 0xe1a87ef7)
Delta #7  (ISN_8 - ISN_7):   +433392368 (Mod 2^32 Hex: 0x19d50af0)
Delta #8  (ISN_9 - ISN_8):   +626938513 (Mod 2^32 Hex: 0x255e5291)
Delta #9  (ISN_10 - ISN_9):  +2385346343 (Mod 2^32 Hex: 0x8e2d7f27)
Delta #10 (ISN_11 - ISN_10):   +400081013 (Mod 2^32 Hex: 0x17d8c075)
Delta #11 (ISN_12 - ISN_11):  -1354842619 (Mod 2^32 Hex: 0xaf3ebe05)
Delta #12 (ISN_13 - ISN_12):   -819554439 (Mod 2^32 Hex: 0xcf269779)
Delta #13 (ISN_14 - ISN_13):   -859580315 (Mod 2^32 Hex: 0xccc3d865)
Delta #14 (ISN_15 - ISN_14):  +2597328609 (Mod 2^32 Hex: 0x9ad016e1)
Delta #15 (ISN_16 - ISN_15):    +63712688 (Mod 2^32 Hex: 0x3cc2db0)
Delta #16 (ISN_17 - ISN_16):  -2328632980 (Mod 2^32 Hex: 0x7533e16c)
Delta #17 (ISN_18 - ISN_17):   -183653169 (Mod 2^32 Hex: 0xf50daccf)
Delta #18 (ISN_19 - ISN_18):  +1279029975 (Mod 2^32 Hex: 0x4c3c72d7)
Delta #19 (ISN_20 - ISN_19):  -2280207372 (Mod 2^32 Hex: 0x7816cbf4)
Delta #20 (ISN_21 - ISN_20):  +3763775760 (Mod 2^32 Hex: 0xe056a910)
Delta #21 (ISN_22 - ISN_21):  -2820283179 (Mod 2^32 Hex: 0x57e5e4d5)
Delta #22 (ISN_23 - ISN_22):  +2444532317 (Mod 2^32 Hex: 0x91b49a5d)
Delta #23 (ISN_24 - ISN_23):  -1639887200 (Mod 2^32 Hex: 0x9e414ea0)
Delta #24 (ISN_25 - ISN_24):   -121211023 (Mod 2^32 Hex: 0xf8c67771)
Delta #25 (ISN_26 - ISN_25):  -1197821290 (Mod 2^32 Hex: 0xb89ab296)
Delta #26 (ISN_27 - ISN_26):  +1888912645 (Mod 2^32 Hex: 0x70968505)
Delta #27 (ISN_28 - ISN_27):   -773972970 (Mod 2^32 Hex: 0xd1de1c16)
Delta #28 (ISN_29 - ISN_28):  -1193794574 (Mod 2^32 Hex: 0xb8d823f2)
Delta #29 (ISN_30 - ISN_29):  +1790822380 (Mod 2^32 Hex: 0x6abdc7ec)
```

---

### 4. Kết Quả Bắt Tay 3 Bước Giả Mạo Nguồn (Blind Spoofing Simulation)

Lệnh thực thi từ `h1`:
```bash
ip netns exec h1 python3 /tmp/lab01/spoof_sniff.py
```

**Nguyên văn Terminal Output từ Attacker:**
```text
[*] Target: 10.0.0.2:9000 | Spoofed IP: 10.0.0.77:62678
[*] Step 1: Sending SYN with SPOOFED source IP (10.0.0.77) to 10.0.0.2:9000...
[*] Step 2: Sniffing for SYN/ACK on interface veth1 (sport=62678)...
[+] Successfully captured SYN/ACK! Real Server ISN = 0xd8230272 (3626173042)
[*] Step 3: Sending ACK with ack = ISN + 1 (3626173043) to complete 3-way handshake...
[*] Step 4: Sending PSH+ACK payload data 'hello-from-spoofed-source'...
[+] Done! Successfully transmitted spoofed payload as 10.0.0.77 to 10.0.0.2:9000
```

---

### 5. Log Bắt Gói Tại Nạn Nhân (tcpdump trên h2)

Lệnh thực thi quan sát:
```bash
ip netns exec h2 timeout 8 tcpdump -i veth2 -nn -A tcp port 9000
```

**Nguyên văn Log Bắt Gói Tin `/tmp/lab01/tcpdump_h2.log`:**
```text
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on veth2, link-type EN10MB (Ethernet), snapshot length 262144 bytes
23:56:50.291658 IP 10.0.0.77.62678 > 10.0.0.2.9000: Flags [S], seq 1000, win 8192, length 0
E..(....@.f.
..M
.....#(........P. ._...
23:56:50.291688 IP 10.0.0.2.9000 > 10.0.0.77.62678: Flags [S.], seq 3626173042, ack 1001, win 64240, options [mss 1460], length 0
E..,..@.@.&~
...
..M#(...#.r....`....m......
23:56:51.303287 IP 10.0.0.2.9000 > 10.0.0.77.62678: Flags [S.], seq 3626173042, ack 1001, win 64240, options [mss 1460], length 0
E..,..@.@.&~
...
..M#(...#.r....`....m......
23:56:51.341853 IP 10.0.0.77.62678 > 10.0.0.2.9000: Flags [.], ack 1, win 8192, length 0
E..(....@.f.
..M
.....#(.....#.sP. .....
23:56:51.385155 IP 10.0.0.77.62678 > 10.0.0.2.9000: Flags [P.], seq 1:27, ack 1, win 8192, length 26
E..B....@.fg
..M
.....#(.....#.sP. .....hello-from-spoofed-source

23:56:51.385416 IP 10.0.0.2.9000 > 10.0.0.77.62678: Flags [.], ack 27, win 64214, length 0
E..(n.@.@...
...
..M#(...#.s....P....i..

6 packets captured
6 packets received by filter
0 packets dropped by kernel
```

---

### 6. Đánh Giá Kết Quả Thực Nghiệm

1. **Về tính ngẫu nhiên của ISN (Bước 3):**
   - Sự chênh lệch giữa các ISN liên tiếp hoàn toàn ngẫu nhiên và biến thiên cực lớn trên toàn bộ dải $2^{32}$.
   - Khẳng định nhân Linux kiểm thử (kernel 6.12) tuân thủ triệt để tiêu chuẩn **RFC 6528**, ngăn chặn hoàn toàn tấn công ngoại suy tuyến tính (Linear Prediction).
2. **Về khả năng chèn gói dữ liệu giả mạo (Bước 4 & 5):**
   - Nạn nhân `h2` hoàn toàn tiếp nhận bắt tay TCP 3 bước từ địa chỉ IP nguồn giả mạo `10.0.0.77`.
   - Gói tin mang cờ `[P.]` chứa dữ liệu `hello-from-spoofed-source` đã được máy chủ tiếp nhận thành công và phản hồi xác nhận `Flags [.], ack 27`.
   - Chứng minh thực nghiệm: TCP chỉ dựa vào Sequence & Acknowledgment Number để duy trì phiên. Nếu kẻ tấn công nắm được ISN (qua sniffing hoặc dự đoán), tầng TCP sẽ không có cơ chế phát hiện mạo danh địa chỉ IP.

