# TÀI LIỆU KỸ THUẬT & KIẾN TRÚC THỰC THI: LAB 05
## ICMP Redirect Attack (Route Hijacking / MITM) & Defense Architecture

---

### 1. KIẾN TRÚC MÔ HÌNH THỰC NGHIỆM (TOPOLOGY ARCHITECTURE)

```
       +-------------------------------------------------------------+
       |                     LAN 10.0.0.0/24 (br0)                   |
       +--------------+-----------------------+----------------------+
                      |                       |                      |
                      v                       v                      v
                +-----------+           +-----------+          +-----------+
                |    vic    |           |    atk    |          |    gw     |
                | 10.0.0.2  |           | 10.0.0.66 |          | 10.0.0.1  |
                +-----------+           +-----------+          +-----+-----+
                  (Victim)               (Attacker)                  |
                                                          gw-d (10.0.1.254)
                                                                     |
                                                           WAN Link (veth)
                                                                     |
                                                          d-gw (10.0.1.5)
                                                                     v
                                                               +-----------+
                                                               |    dst    |
                                                               | 10.0.1.5  |
                                                               +-----------+
                                                              (Destination)
```

- **Môi trường ảo hóa:**
  - Subnet LAN `10.0.0.0/24`: Kết nối qua Linux Bridge `br0` chứa `vic` (`10.0.0.2`), `atk` (`10.0.0.66`), và cổng LAN của Router `gw` (`10.0.0.1`).
  - Subnet WAN `10.0.1.0/24`: Kết nối điểm-điểm giữa cổng `gw-d` (`10.0.1.254`) của router và máy chủ đích `dst` (`10.0.1.5`).
- **Chính sách định tuyến ban đầu:**
  - `vic`: Default gateway trỏ về `10.0.0.1`.
  - `dst`: Default gateway trỏ về `10.0.1.254`.
  - `gw`: Bật `net.ipv4.ip_forward = 1` để chuyển tiếp gói giữa hai subnet.

---

### 2. CẤU TRÚC GÓI TIN ICMP REDIRECT (RFC 792 & RFC 1122)

Gói tin ICMP Redirect có cấu trúc chuẩn như sau:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type (5)  |     Code (1)  |          Checksum             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Gateway Internet Address (gw)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      IP Header + first 64 bits of Original Datagram Data      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

1. **Type:** `5` (Redirect).
2. **Code:**
   - `0`: Redirect datagrams for the Network.
   - `1`: Redirect datagrams for the Host (sử dụng trong bài thực hành này để chuyển hướng đích cụ thể `10.0.1.5`).
   - `2`: Redirect datagrams for the Type of Service and Network.
   - `3`: Redirect datagrams for the Type of Service and Host.
3. **Gateway Internet Address:** Địa chỉ IP của router mới (nexthop mới) được khuyến nghị sử dụng (`10.0.0.66`).
4. **Original Datagram Header:**
   - Tiêu chuẩn RFC bắt buộc gói Redirect phải chứa toàn bộ IP Header của gói tin đã kích hoạt redirect cộng thêm tối thiểu 64 bits (8 bytes) đầu tiên của tầng L4.
   - **Mục đích an ninh:** Giúp hệ điều hành nạn nhân đối chiếu xem gói Redirect này có thực sự thuộc về một phiên truyền thông hợp lệ mà máy tính vừa khởi tạo hay không.

---

### 3. CƠ CHẾ XỬ LÝ NỘI TẠI CỦA LINUX KERNEL (FIB NEXTHOP EXCEPTION)

Khi một gói tin ICMP Redirect đến giao diện mạng của Linux:

1. **Kiểm tra sơ bộ (`icmp_redirect` trong `net/ipv4/icmp.c`):**
   - Kiểm tra `net.ipv4.ip_forward`: Nếu host đang cấu hình làm Router (`ip_forward = 1`), gói tin bị drop ngay lập tức (Router không bao giờ nhận Redirect).
   - Kiểm tra `net.ipv4.conf.<dev>.accept_redirects`: Nếu bằng `0`, gói tin bị drop.
   - Kiểm tra `net.ipv4.conf.<dev>.secure_redirects`: Nếu bằng `1`, `IP.src` của gói tin ngoài phải trùng với Gateway hiện hành của tuyến đường đó.
2. **Kiểm tra L4 Socket (`icmp_socket_deliver`):**
   - Trích xuất payload L4 từ gói tin gốc (`orig`).
   - Tìm kiếm socket đang mở (`__udp4_lib_lookup` hoặc `inet_lookup`).
   - Nếu tìm thấy socket, gọi tiếp `ipv4_sk_redirect()` $\rightarrow$ `__ip_do_redirect()`.
3. **Cập nhật Bảng Định Tuyến (FNHE):**
   - Hàm `update_or_create_fnhe()` tạo một bản ghi ngoại lệ (Next-Hop Exception) trong bảng routing cache của kernel:
     `10.0.1.5 via 10.0.0.66 dev vic0 src 10.0.0.2 cache <redirected> expires 300sec`
   - Khi bất kỳ tiến trình nào trên hệ thống (kể cả lệnh `ping`) phát gói tin tới `10.0.1.5`, kernel tra cứu FIB thấy có bản ghi exception hợp lệ $\rightarrow$ đẩy thẳng gói tin tới địa chỉ MAC của `10.0.0.66`.

---

### 4. SO SÁNH ICMP REDIRECT ATTACK VÀ ARP SPOOFING

| Tiêu Chí So Sánh | ICMP Redirect Attack (L3) | ARP Spoofing / Poisoning (L2) |
| :--- | :--- | :--- |
| **Tầng giao thức tác động** | Tầng Mạng (Network Layer - L3) | Tầng Liên kết dữ liệu (Data Link - L2) |
| **Bảng trạng thái bị nhiễm** | Kernel Routing Cache (FIB Nexthop Exception) | ARP Cache Table (`ip neigh`) |
| **Phạm vi chuyển hướng** | **Có tính chọn lọc cao:** Kẻ tấn công có thể chỉ chuyển hướng lưu lượng đi tới MỘT địa chỉ IP đích cụ thể (`10.0.1.5`), trong khi các lưu lượng khác vẫn đi qua Gateway bình thường. | **Toàn bộ lưu lượng:** Bẻ lái toàn bộ gói tin đi qua gateway (hoặc host) mà không phân biệt đích đến L3. |
| **Tần suất gửi gói** | **Rất thấp:** Chỉ cần gửi 1 hoặc vài gói ICMP Redirect khi có kết nối, route cache sẽ lưu nexthop mới trong 300 giây (5 phút). | **Liên tục:** Phải liên tục phát tán các gói ARP Reply giả mạo để duy trì trạng thái nhiễm độc và ghi đè ARP request hợp pháp. |
| **Khả năng bị phát hiện** | Khó bị phát hiện bởi các công cụ giám sát ARP (Arpwatch, Dynamic ARP Inspection - DAI). | Dễ dàng bị phát hiện và chặn bởi tính năng Dynamic ARP Inspection (DAI) trên managed switch. |
| **Cơ chế phòng vệ hữu hiệu** | Tắt `accept_redirects = 0` trên toàn bộ host. | Sử dụng Dynamic ARP Inspection (DAI) trên Switch, Static ARP mapping, hoặc 802.1X. |

---

### 5. GIẢI PHÁP PHÒNG THỦ TOÀN DIỆN (DEFENSIVE MITIGATION)

#### 5.1. Cấu hình Bắt buộc trên Máy chủ & Máy trạm (Host Layer)

Vô hiệu hóa việc nhận và xử lý ICMP Redirect trên toàn bộ giao diện mạng bằng cấu hình `sysctl`:

```bash
# Thêm vào file /etc/sysctl.conf hoặc /etc/sysctl.d/99-disable-redirects.conf
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Tương tự cho IPv6
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
```

Áp dụng ngay lập tức:
```bash
sysctl -p /etc/sysctl.d/99-disable-redirects.conf
```

#### 5.2. Cấu hình trên Bộ Định Tuyến (Router Layer)

Router mạng LAN nội bộ nên vô hiệu hóa tính năng gửi ICMP Redirect nếu mạng không có cấu hình đa router dự phòng bất đối xứng:

```bash
# Trên Linux Router
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
```

Trên thiết bị Cisco IOS:
```text
interface GigabitEthernet0/0
 no ip redirects
```

