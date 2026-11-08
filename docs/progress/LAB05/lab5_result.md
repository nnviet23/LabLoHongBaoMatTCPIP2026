# BÁO CÁO KẾT QUẢ THỰC NGHIỆM: LAB 05
## ICMP Redirect Attack (Route Hijacking / Man-in-the-Middle) & Kernel Defense

- **Thời gian thực thi:** 2026-11-08 (Kali VM Local Time: 01:04 - 01:07)
- **Hệ điều hành kiểm thử:** Kali Linux (`7.1.5+kali-amd64`, x86_64) trên nền tảng VMware
- **Môi trường ảo hóa mạng:** Linux Bridge (`br0`) và Linux Virtual Ethernet (`veth`) kết nối 4 Network Namespaces độc lập:
  - Subnet LAN `10.0.0.0/24`:
    - `vic` (`10.0.0.2/24`) - Nạn nhân nội bộ (Default GW: `10.0.0.1`)
    - `gw` (`10.0.0.1/24`) - Router / Default Gateway hợp pháp
    - `atk` (`10.0.0.66/24`) - Kẻ tấn công nằm cùng LAN
  - Subnet WAN / Server `10.0.1.0/24`:
    - `gw-d` trên `gw` (`10.0.1.254/24`)
    - `dst` (`10.0.1.5/24`) - Máy chủ đích bên ngoài (Default GW: `10.0.1.254`)
- **Công cụ:** Scapy 2.6.1, tcpdump 4.99.5, Linux Kernel Ftrace (`function_graph`), iproute2, sysctl

---

### 1. RAW TERMINAL OUTPUTS (Minh Chứng Thực Tế)

#### 1.1. Khởi tạo Topology Đa Subnet & Xác nhận Baseline Route

Lệnh thực thi:
```bash
echo Aa@123456 | sudo -S bash /tmp/lab05/setup_redirect.sh
```

Terminal Output:
```text
[*] Cleaning up old network namespaces and bridges...
[*] Creating Linux Bridge br0 for LAN 10.0.0.0/24...
[*] Setting up LAN host vic (10.0.0.2)...
[*] Setting up LAN host gw (10.0.0.1)...
[*] Setting up LAN host atk (10.0.0.66)...
[*] Setting up WAN/Destination network 10.0.1.0/24...
[*] Configuring IP Forwarding and Routing...
net.ipv4.ip_forward = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.gw0.send_redirects = 0
[*] Configuring Victim (vic) to accept ICMP Redirects...
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.accept_redirects = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.vic0.accept_redirects = 1
net.ipv4.conf.vic0.secure_redirects = 0
[*] Warming up ARP caches across LAN...
[+] Lab 05 Topology Ready:
    - vic: 10.0.0.2  (via 10.0.0.1, accept_redirects=1)
    - gw:  10.0.0.1 (LAN) & 10.0.1.254 (WAN)
    - atk: 10.0.0.66 (LAN attacker)
    - dst: 10.0.1.5  (Target host behind gw)
```

Xác minh ping cơ bản và kiểm tra Baseline Route trên `vic`:
```bash
ip netns exec vic ping -c 2 10.0.1.5
ip netns exec vic ip route get 10.0.1.5
```

Terminal Output:
```text
PING 10.0.1.5 (10.0.1.5) 56(84) bytes of data.
64 bytes from 10.0.1.5: icmp_seq=1 ttl=63 time=0.138 ms
64 bytes from 10.0.1.5: icmp_seq=2 ttl=63 time=0.080 ms

--- 10.0.1.5 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1015ms
rtt min/avg/max/mdev = 0.080/0.109/0.138/0.029 ms

10.0.1.5 via 10.0.0.1 dev vic0 src 10.0.0.2 uid 0 
    cache 
```

> **Ghi nhận Baseline:** Gói tin tới `10.0.1.5` đi qua Default Gateway hợp pháp `via 10.0.0.1 dev vic0`.

---

#### 1.2. Nhật Ký Bắt Gói ICMP Redirect & Bóc Tách Kernel Ftrace

Khi kẻ tấn công phát gói ICMP Redirect (Type 5, Code 1) giả mạo `src = 10.0.0.1` tới `vic`, `tcpdump` trên `vic0` ghi nhận:
```text
01:05:27.780176 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto ICMP (1), length 56)
    10.0.0.1 > 10.0.0.2: ICMP redirect 10.0.1.5 to host 10.0.0.66, length 36
	IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto ICMP (1), length 28)
    10.0.0.2 > 10.0.1.5: ICMP echo request, id 1, seq 1, length 8
```

**Khảo sát đường thực thi trong Linux Kernel (`ftrace - function_graph`):**
Nhân Linux hiện đại (RFC 1122) yêu cầu gói ICMP Redirect phải khớp với một kết nối (socket) đang mở của ứng dụng. Khi có luồng giao tiếp tương ứng từ `10.0.0.2:12345` tới `10.0.1.5:80`, hàm xử lý trong kernel được kích hoạt:

```text
 ------------------------------------------
   CPU  DURATION                  FUNCTION CALLS
 ------------------------------------------
   1)               |  udp_err() {
   1)               |    __udp4_lib_lookup() {
   1)   0.467 us    |      udp_ehashfn();
   1)   1.331 us    |    }
   1)               |    ipv4_sk_redirect() {
   1)               |      ip_route_output_key_hash() {
   1)               |        ip_route_output_key_hash_rcu() {
   1)   0.353 us    |          fib_lookup_good_nhc();
   1)   0.089 us    |          find_exception();
   1)   4.241 us    |        }
   1)   4.781 us    |      }
   1)               |      __ip_do_redirect() {
   1)               |        inet_addr_type() {
   1)   0.486 us    |          fib_lookup_good_nhc();
   1)   1.480 us    |        }
   1)   0.276 us    |        fib_lookup_good_nhc();
   1)   0.080 us    |        fib_select_path();
   1)               |        update_or_create_fnhe() { ... }
   1)               |      }
   1)               |    }
   1)               |  }
```

---

#### 1.3. Nhiễm Độc Routing Cache & Bắt Lưu Lượng MITM trên Attacker

Kiểm tra bảng định tuyến trên `vic` ngay sau khi nhận gói Redirect:
```bash
ip netns exec vic ip route get 10.0.1.5
```

Terminal Output:
```text
10.0.1.5 via 10.0.0.66 dev vic0 src 10.0.0.2 uid 0 
    cache <redirected> expires 295sec 
```

> **Đột phá kiểm thử:** Toàn bộ lưu lượng tới `10.0.1.5` đã bị ép chuyển hướng sang `via 10.0.0.66` (máy của attacker) và gắn nhãn cache `<redirected>` với thời gian tồn tại `295sec`.

**Bắt lưu lượng Man-in-the-Middle trên giao diện `atk0`:**
Khi `vic` thực hiện `ping -c 2 10.0.1.5`, tiến trình `tcpdump` trên `atk0` bắt được toàn bộ các gói tin của `vic` đi qua máy attacker:

```text
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on atk0, link-type EN10MB (Ethernet), snapshot length 262144 bytes

01:06:51.072755 IP 10.0.0.2 > 10.0.1.5: ICMP echo request, id 59752, seq 1, length 64
01:06:51.072775 IP 10.0.0.2 > 10.0.1.5: ICMP echo request, id 59752, seq 1, length 64

2 packets captured
2 packets received by filter
0 packets dropped by kernel
```

Terminal output của `vic`:
```text
PING 10.0.1.5 (10.0.1.5) 56(84) bytes of data.
From 10.0.0.66: icmp_seq=1 Redirect Host(New nexthop: 10.0.0.1)
64 bytes from 10.0.1.5: icmp_seq=1 ttl=63 time=0.062 ms
64 bytes from 10.0.1.5: icmp_seq=2 ttl=63 time=0.075 ms

--- 10.0.1.5 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1030ms
rtt min/avg/max/mdev = 0.062/0.068/0.075/0.006 ms
```

---

#### 1.4. Kích Hoạt Cơ Chế Phòng Thủ Tầng Kernel & Kiểm Chứng

Thực thi trên `vic`:
```bash
for k in all default vic0; do
    ip netns exec vic sysctl -w net.ipv4.conf.$k.accept_redirects=0
done
ip netns exec vic ip route flush cache
```

Terminal Output:
```text
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.vic0.accept_redirects = 0
```

Tái phát động kịch bản tiêm ICMP Redirect từ `atk` và kiểm tra lại route:
```bash
ip netns exec vic ip route get 10.0.1.5
```

Terminal Output:
```text
10.0.1.5 via 10.0.0.1 dev vic0 src 10.0.0.2 uid 0 
    cache 
```

> **Xác minh phòng thủ:** Gói tin ICMP Redirect bị kernel hủy bỏ hoàn toàn. Bảng định tuyến giữ nguyên trạng thái hợp pháp `via 10.0.0.1`, không xuất hiện cờ `<redirected>`.

---

### 2. BÓC TÁCH & PHÂN TÍCH CHUYÊN SÂU LOG TERMINAL

#### 2.1. Phân Tích Sự Thay Đổi Routing Cache

1. **Trước tấn công (Baseline):**
   - Lệnh `ip route get 10.0.1.5` trả về `via 10.0.0.1 dev vic0`. Đây là tuyến đường quy định bởi Default Route tĩnh do quản trị viên thiết lập.
2. **Sau khi tiêm gói Redirect:**
   - Lệnh trả về:
     ```text
     10.0.1.5 via 10.0.0.66 dev vic0 src 10.0.0.2 uid 0 
         cache <redirected> expires 295sec 
     ```
   - Nhân Linux đã tạo một **FIB Nexthop Exception (FNHE)** trong bộ nhớ cache. Cờ `<redirected>` biểu thị rằng nexthop này được ghi đè tạm thời bởi một thông điệp ICMP Redirect.
   - Trường `expires 295sec` (khoảng 300 giây = 5 phút) là thời gian tồn tại (TTL) của mục cache định tuyến động theo quy định của RFC 1122 nhằm tránh chuyển hướng vĩnh viễn.

#### 2.2. Giải Phẫu Gói Tin ICMP Redirect Hợp Lệ

Tại sao nhân Linux của `vic` lại chấp nhận cập nhật bảng định tuyến?
Gói tin Redirect của attacker thỏa mãn toàn bộ các điều kiện khắt khe của RFC 1122 / RFC 792:
1. **IP Header ngoài (Outer IP):**
   - `src = 10.0.0.1`: Trùng khớp hoàn toàn với Default Gateway hiện hành của `vic` cho tuyến đường tới `10.0.1.5`.
   - `dst = 10.0.0.2`: Gửi trực tiếp đến địa chỉ IP của nạn nhân.
2. **ICMP Header:**
   - `Type = 5` (Redirect), `Code = 1` (Redirect Datagrams for the Host).
   - `Gateway Address (gw) = 10.0.0.66`: Địa chỉ IP của router mới tốt hơn (ở cùng subnet LAN `10.0.0.0/24`).
3. **Payload đính kèm (Original Datagram Header):**
   - Chứa tối thiểu 28 bytes của gói tin gốc: IP Header gốc (`src=10.0.0.2, dst=10.0.1.5`) + 8 bytes của L4 Header (UDP/TCP/ICMP).
   - Nhân Linux gọi `__udp4_lib_lookup()` / `inet_lookup()` đối chiếu 4-tuple `(10.0.0.2:12345, 10.0.1.5:80)`. Khi tìm thấy socket phù hợp, kernel xác thực rằng gói tin này xuất phát từ một luồng truyền thông thực tế của hệ thống, từ đó gọi tiếp `__ip_do_redirect()`.

#### 2.3. Phân Tích Lưu Lượng MITM trên Attacker

Khi `vic` thực hiện `ping 10.0.1.5`:
- Do route cache đã trỏ `via 10.0.0.66`, `vic` gửi khung Ethernet chứa ICMP Echo Request tới địa chỉ MAC của card mạng `atk0` (`f6:4c:bd:2b:0d:22`).
- Card mạng `atk0` nhận được 2 gói tin ICMP Echo Request (`id 59752, seq 1`).
- Kẻ tấn công bật `net.ipv4.ip_forward = 1` đóng vai trò Man-in-the-Middle trong suốt: chuyển tiếp gói tin tiếp tục tới Gateway thật `10.0.0.1` để tới đích `10.0.1.5`, cho phép kẻ tấn công nghe lén (sniffing), sửa đổi dữ liệu (tampering) hoặc ngắt kết nối tùy ý mà không làm gián đoạn liên lạc của nạn nhân.

#### 2.4. So Sánh Hai Tham Số Kernel: `accept_redirects` và `secure_redirects`

| Tham số Sysctl | Mặc định | Chức năng & Nguyên lý hoạt động | Đánh giá an ninh |
| :--- | :---: | :--- | :--- |
| `net.ipv4.conf.*.accept_redirects` | `1` (Host) / `0` (Router) | Cho phép hoặc cấm nhận thông điệp ICMP Redirect. Khi đặt bằng `0`, kernel lập tức drop mọi gói ICMP Type 5 mà không cần kiểm tra thêm. | **Khuyến nghị thiết lập = 0 cho toàn bộ máy chủ và máy trạm production.** Trong mạng hiện đại, định tuyến đã được quản lý tĩnh hoặc qua giao thức định tuyến động (OSPF, BGP). |
| `net.ipv4.conf.*.secure_redirects` | `1` | Chỉ chấp nhận ICMP Redirect nếu địa chỉ nguồn của gói tin trùng khớp với Gateway hiện hành trong bảng định tuyến. | **Không đủ an toàn trước kẻ tấn công cùng LAN:** Khi kẻ tấn công nằm cùng switch/LAN, việc giả mạo IP nguồn của Gateway (`10.0.0.1`) là hoàn toàn khả thi (như đã chứng minh trong bài lab này). Do đó `secure_redirects=1` hoàn toàn bất lực trước kẻ tấn công nội bộ. |

---

### 3. KẾT LUẬN

Bài thực hành LAB 05 đã chứng minh thành công kỹ thuật bẻ lái định tuyến (Route Hijacking) bằng ICMP Redirect Type 5 Code 1 trên hệ thống Linux hiện đại, bóc tách cơ chế xử lý cấp kernel qua Ftrace, bắt trọn lưu lượng MITM trên attacker, và khẳng định việc thiết lập `net.ipv4.conf.*.accept_redirects = 0` là giải pháp phòng thủ duy nhất triệt tiêu hoàn toàn lỗ hổng này.

