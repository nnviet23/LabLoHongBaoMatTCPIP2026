# BÁO CÁO KẾT QUẢ THỰC NGHIỆM: LAB 04
## Smurf Attack (ICMP Broadcast Amplification DoS) & Multi-layer Defense

- **Thời gian thực thi:** 2026-11-08 (Kali VM Local Time: 00:58 - 00:59)
- **Hệ điều hành kiểm thử:** Kali Linux (`7.1.5+kali-amd64`, x86_64) trên nền tảng VMware
- **Môi trường ảo hóa mạng:** Linux Bridge (`br0`) kết nối 5 Linux Network Namespaces độc lập qua veth pairs:
  - `atk` (`10.0.0.100/24`) - Host phát động kiểm thử
  - `vic` (`10.0.0.200/24`) - Host nạn nhân (bị giả mạo nguồn)
  - `amp1` (`10.0.0.11/24`) - Host khuếch đại 1
  - `amp2` (`10.0.0.12/24`) - Host khuếch đại 2
  - `amp3` (`10.0.0.13/24`) - Host khuếch đại 3
- **Công cụ:** Scapy 2.6.1, tcpdump 4.99.5, iproute2, sysctl

---

### 1. RAW TERMINAL OUTPUTS (Minh Chứng Thực Tế)

#### 1.1. Khởi tạo Topology LAN & Cấu hình sysctl dễ bị tấn công

Lệnh thực thi:
```bash
echo Aa@123456 | sudo -S bash /tmp/lab04/setup_lan.sh
```

Terminal Output:
```text
[*] Cleaning up old network namespaces and bridge if any...
[*] Creating Linux Bridge br0...
[*] Setting up host atk (10.0.0.100)...
[*] Setting up host vic (10.0.0.200)...
[*] Setting up host amp1 (10.0.0.11)...
[*] Setting up host amp2 (10.0.0.12)...
[*] Setting up host amp3 (10.0.0.13)...
[*] Configuring amplifiers to respond to broadcast ICMP (icmp_echo_ignore_broadcasts = 0)...
net.ipv4.icmp_echo_ignore_broadcasts = 0
net.ipv4.icmp_echo_ignore_broadcasts = 0
net.ipv4.icmp_echo_ignore_broadcasts = 0
[*] Warming up ARP cache between hosts...
[+] LAN Topology Ready on br0:
    - atk:  10.0.0.100
    - vic:  10.0.0.200
    - amp1: 10.0.0.11 (ignore_broadcasts = 0)
    - amp2: 10.0.0.12 (ignore_broadcasts = 0)
    - amp3: 10.0.0.13 (ignore_broadcasts = 0)
```

Xác minh ping cơ bản và cấu hình `sysctl`:
```text
PING 10.0.0.200 (10.0.0.200) 56(84) bytes of data.
64 bytes from 10.0.0.200: icmp_seq=1 ttl=64 time=0.164 ms
64 bytes from 10.0.0.200: icmp_seq=2 ttl=64 time=0.064 ms

--- 10.0.0.200 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1007ms
rtt min/avg/max/mdev = 0.064/0.114/0.164/0.050 ms
net.ipv4.icmp_echo_ignore_broadcasts = 0
net.ipv4.icmp_echo_ignore_broadcasts = 0
net.ipv4.icmp_echo_ignore_broadcasts = 0
```

---

#### 1.2. Phát động Kịch bản Khuếch đại & Nhật ký Bắt gói tại Nạn nhân (`vic`)

Lệnh thực thi:
```bash
# Bắt gói trên giao diện vic0
ip netns exec vic timeout 8 tcpdump -i vic0 -nn icmp > /tmp/lab04/tcpdump_vic_attack.log 2>&1 &

# Phát 10 gói tin từ atk tới directed broadcast 10.0.0.255 giả mạo src=10.0.0.200
ip netns exec atk python3 /tmp/lab04/smurf_attack.py
```

Output của script Scapy:
```text
[*] Starting Smurf Attack from Attacker...
    - Target Broadcast : 10.0.0.255
    - Spoofed Source IP: 10.0.0.200
    - Total Requests   : 10
[+] Successfully sent 10 ICMP Echo Requests to 10.0.0.255 with spoofed src=10.0.0.200
```

Raw Log `tcpdump` thu được tại `vic0` (`/tmp/lab04/tcpdump_vic_attack.log`):
```text
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on vic0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
00:58:17.392145 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:17.392149 IP 10.0.0.13 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.392151 IP 10.0.0.12 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.392152 IP 10.0.0.11 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.493944 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:17.494042 IP 10.0.0.13 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.494043 IP 10.0.0.12 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.494043 IP 10.0.0.11 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.595796 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:17.595852 IP 10.0.0.13 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.595852 IP 10.0.0.12 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.595853 IP 10.0.0.11 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.699385 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:17.699441 IP 10.0.0.13 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.699442 IP 10.0.0.12 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.699442 IP 10.0.0.11 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.800552 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:17.800653 IP 10.0.0.13 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.800654 IP 10.0.0.12 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.800654 IP 10.0.0.11 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.901745 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:17.901789 IP 10.0.0.13 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.901790 IP 10.0.0.12 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.901790 IP 10.0.0.11 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:18.005810 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:18.005871 IP 10.0.0.13 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:18.005872 IP 10.0.0.12 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:18.005872 IP 10.0.0.11 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:18.107999 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:18.108066 IP 10.0.0.13 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:18.108067 IP 10.0.0.12 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:18.108067 IP 10.0.0.11 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:18.209686 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:18.209748 IP 10.0.0.13 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:18.209749 IP 10.0.0.12 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:18.209749 IP 10.0.0.11 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:18.312239 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:18.312299 IP 10.0.0.13 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:18.312300 IP 10.0.0.12 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:18.312301 IP 10.0.0.11 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8

40 packets captured
40 packets received by filter
0 packets dropped by kernel
```

Số lượng phản hồi đếm được:
```bash
grep "echo reply" /tmp/lab04/tcpdump_vic_attack.log | wc -l
# Output: 30
```

---

#### 1.3. Kích hoạt Phòng thủ Tầng Kernel & Tái kiểm thử

Cấu hình phòng vệ trên các máy khuếch đại:
```bash
for h in amp1 amp2 amp3; do
    ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
done
```

Output:
```text
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
```

Thực thi lại đợt gửi gói và bắt gói `/tmp/lab04/tcpdump_vic_defended.log`:
```text
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on vic0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
00:58:50.494132 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:50.595223 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:50.697016 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:50.798171 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:50.899270 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:51.000634 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:51.102119 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:51.205498 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:51.307453 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:51.409696 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8

10 packets captured
10 packets received by filter
0 packets dropped by kernel
```

Số lượng phản hồi đếm được:
```bash
grep "echo reply" /tmp/lab04/tcpdump_vic_defended.log | wc -l
# Output: 0
```

---

### 2. BÓC TÁCH & PHÂN TÍCH CHUYÊN SÂU LOG TERMINAL

#### 2.1. Phân tích Cơ chế Khuếch đại (Amplification Mechanics)

Quan sát trực tiếp nhóm gói tin đầu tiên trong file log:
```text
00:58:17.392145 IP 10.0.0.200 > 10.0.0.255: ICMP echo request, id 4919, seq 0, length 8
00:58:17.392149 IP 10.0.0.13 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.392151 IP 10.0.0.12 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
00:58:17.392152 IP 10.0.0.11 > 10.0.0.200: ICMP echo reply, id 4919, seq 0, length 8
```

1. **Gói kích hoạt (Trigger Packet):**
   - Lúc `00:58:17.392145`, giao diện `vic0` nhận được 1 gói Broadcast ICMP Echo Request (`Type 8`) có địa chỉ đích `10.0.0.255` và `src = 10.0.0.200`. Gói này do attacker (`atk`) phát tán vào bridge `br0`. Do là gói directed broadcast, bridge chuyển tiếp gói tin tới mọi port kết nối (bao gồm cả `vic0`, `amp1_0`, `amp2_0`, `amp3_0`).
2. **Hiện tượng dội phản hồi đồng loạt (Simultaneous Echo Replies):**
   - Chỉ trong vòng **7 microsecond** (`.392145` $\rightarrow$ `.392152`), `vic0` nhận liên tiếp **3 gói ICMP Echo Reply (`Type 0`)**:
     - Gói 1 từ `10.0.0.13` (amp3) lúc `.392149`
     - Gói 2 từ `10.0.0.12` (amp2) lúc `.392151`
     - Gói 3 từ `10.0.0.11` (amp1) lúc `.392152`
   - Cả 3 gói phản hồi đều có cùng thông số `id 4919` (`0x1337`) và `seq 0`, khớp hoàn toàn với thông số của gói tin kích hoạt ban đầu.
3. **Tính chất bất đối xứng:**
   - Host `vic` (`10.0.0.200`) không chủ động phát đi bất kỳ gói tin nào, nhưng phải gánh chịu lưu lượng phản hồi dồn dập từ cả 3 máy trạm trên mạng.

#### 2.2. Phân tích Tác động Băng thông & Hệ số Khuếch đại

Hệ số khuếch đại gói tin ($K$) được xác định theo công thức:
$$K = \frac{N_{\text{replies}}}{N_{\text{requests\_sent}}} = N_{\text{amplifiers}}$$

Trong mô hình thực nghiệm:
- $N_{\text{requests\_sent}} = 10$
- $N_{\text{amplifiers}} = 3$ (`amp1`, `amp2`, `amp3`)
- $N_{\text{replies}} = 30$
$$\Rightarrow K = \frac{30}{10} = 3$$

**Đánh giá tác động ở quy mô mạng thực tế:**
- Giả sử trong một mạng doanh nghiệp subnet `/24` có 200 máy trạm đang hoạt động với cấu hình mặc định (chấp nhận ping broadcast).
- Kẻ tấn công chỉ cần một đường truyền băng thông nhỏ (ví dụ $10\text{ Mbps}$) liên tục bơm các gói directed broadcast với kích thước MTU đầy đủ ($1500\text{ bytes}$):
$$\text{Băng thông dội về nạn nhân} = 10\text{ Mbps} \times 200 = 2000\text{ Mbps} = 2\text{ Gbps}$$
- Lưu lượng $2\text{ Gbps}$ tập trung dội vào một card mạng máy tính cá nhân hoặc máy chủ nội bộ sẽ lập tức làm cạn kiệt hàng đợi phần cứng (ring buffer RX queue drops), làm tràn bảng ARP / State Table của switch và gây tê liệt hoàn toàn khả năng xử lý mạng của nạn nhân (Denial of Service).

#### 2.3. Đối chiếu Phòng thủ Đa lớp (Defense-in-Depth Comparison)

| Tầng Phòng Ngự | Cơ chế / Cấu hình | Vị trí Thực Thi | Hiệu quả & Phân tích |
| :--- | :--- | :--- | :--- |
| **Host Layer (Nội tại máy trạm)** | `sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1` | Trên từng máy trạm trong subnet | **Rất hiệu quả cho từng host:** Khi bật cờ này, nhân Linux drop gói ICMP echo request gửi tới broadcast ngay tại tầng IP của kernel, triệt tiêu $100\%$ các gói Echo Reply dội về nạn nhân (minh chứng: từ 30 gói về 0 gói trong log kiểm thử). Nhược điểm: Khó quản lý tập trung nếu có hàng ngàn thiết bị IoT/máy cũ không được chuẩn hóa cấu hình. |
| **Router Layer (Biên mạng LAN / WAN)** | `no ip directed-broadcast` (RFC 2644) | Trên Default Gateway / Core Router | **Chặn từ xa:** Ngăn chặn kẻ tấn công từ bên ngoài Internet gửi gói tin IP có địa chỉ đích là Directed Broadcast của mạng nội bộ (`x.y.z.255`). Router sẽ hủy gói tin thay vì chuyển đổi thành Ethernet broadcast trên LAN. Đây là tiêu chuẩn bắt buộc của các thiết bị mạng hiện đại. |
| **ISP / Carrier Layer (Nhà mạng)** | **BCP 38 / RFC 2827** (Ingress & Egress Filtering) | Thiết bị biên PE Router của ISP | **Triệt tiêu nguồn gốc giả mạo:** Bắt buộc ISP phải kiểm tra IP nguồn của gói tin đi ra từ khách hàng. Nếu gói tin có IP nguồn không thuộc dải địa chỉ được cấp phát cho đường truyền đó (`10.0.0.200`), router ISP sẽ lập tức drop gói (Unicast Reverse Path Forwarding - uRPF). Điều này khiến kẻ tấn công không thể gửi gói tin giả mạo ra mạng diện rộng. |

---

### 3. KẾT LUẬN

Bài thực hành LAB 04 đã tái hiện thành công bản chất tấn công khuếch đại Smurf Attack trên mô hình 5 máy ảo mạng LAN Linux Bridge, ghi nhận chính xác hệ số khuếch đại thực tế $K = \times 3$, và kiểm chứng tính hiệu quả tuyệt đối của tham số kernel `net.ipv4.icmp_echo_ignore_broadcasts=1` trong việc vô hiệu hóa vai trò của các trạm khuếch đại.

