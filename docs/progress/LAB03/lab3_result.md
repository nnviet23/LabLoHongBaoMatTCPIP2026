# NHẬT KÝ THỰC NGHIỆM CHI TIẾT: LAB 03
## ICMP Tunneling (Covert Channel & Data Exfiltration)

- **Thời gian thực thi:** 2026-11-08 (Kali VM Local Time: 00:41 - 00:43)
- **Hệ điều hành kiểm thử:** Kali Linux (Kernel: `7.1.5+kali-amd64`, x86_64) trên VMware
- **Môi trường ảo hóa:** Linux Network Namespaces (`h1` - Client nội bộ, `h2` - Server bên ngoài) kết nối qua `veth1 <-> veth2`
- **Công cụ sử dụng:** Scapy 2.6.1, tcpdump 4.99.5, iptables, netcat (nc)

---

### 1. RAW LOGS: Khởi Tạo Môi Trường & Cấu Hình Kernel

Lệnh thực thi:
```bash
echo Aa@123456 | sudo -S bash /tmp/lab03/setup_pair.sh
echo Aa@123456 | sudo -S ip netns exec h2 sysctl net.ipv4.icmp_echo_ignore_all
```

**Nguyên văn Terminal Output:**
```text
[*] Cleaning up existing namespaces and links if any...
[*] Creating namespaces h1 (client) and h2 (server)...
[*] Creating veth pair (veth1 <-> veth2)...
[*] Configuring IP addresses...
[*] Bringing up interfaces...
[*] Disabling kernel auto-reply on h2 (delegating all ICMP handling to user-space Scapy server)...
net.ipv4.icmp_echo_ignore_all = 1
[+] Verifying baseline ping connectivity before disabling ignore_all for test:
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=0.139 ms
64 bytes from 10.0.0.2: icmp_seq=2 ttl=64 time=0.054 ms

--- 10.0.0.2 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1015ms
rtt min/avg/max/mdev = 0.054/0.096/0.139/0.042 ms
[+] Setup completed. Kernel icmp_echo_ignore_all set to 1 on h2.
net.ipv4.icmp_echo_ignore_all = 1
```

---

### 2. RAW LOGS: Tiến Trình Tuồn Dữ Liệu & Nhật Ký Server

Lệnh thực thi:
```bash
# Khởi chạy server nền
ip netns exec h2 python3 /tmp/lab03/icmp_server.py > /tmp/lab03/server.log 2>&1 &
echo $! > /tmp/lab03/server.pid

# Chạy client tuồn dữ liệu
ip netns exec h1 python3 /tmp/lab03/icmp_client.py
```

**Nguyên văn Log Máy Khách (`icmp_client.py` stdout):**
```text
[*] Target Server: 10.0.0.2
[*] Exfiltrating data (7 bytes): b'tainbow'
[*] Sending chunk 1/1 (7 bytes): b'tainbow'...
[client] phan hoi tu server: b'ACK:tainbow'
[client] hoan tat gui du lieu qua ICMP
```

**Nguyên văn Log Máy Chủ (`/tmp/lab03/server.log`):**
```text
[server] dang lang nghe ICMP tren veth2 ...
[server] nhan (7 bytes): b'tainbow'
```

---

### 3. RAW LOGS: Bắt Gói Dữ Liệu ASCII Bằng tcpdump (`/tmp/lab03/tcpdump_payload.log`)

Lệnh thực thi:
```bash
ip netns exec h2 timeout 8 tcpdump -i veth2 -nn -A icmp
```

**Nguyên văn Log tcpdump:**
```text
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on veth2, link-type EN10MB (Ethernet), snapshot length 262144 bytes
00:41:15.551856 IP 10.0.0.1 > 10.0.0.2: ICMP echo request, id 4919, seq 0, length 15
E..#....@.f.
...
.....-..7..tainbow
00:41:15.611668 IP 10.0.0.2 > 10.0.0.1: ICMP echo reply, id 4919, seq 0, length 19
E..'....@.f.
...
........7..ACK:tainbow

2 packets captured
2 packets received by filter
0 packets dropped by kernel
```

---

### 4. RAW LOGS: Kiểm Chứng Vượt Tường Lửa Tầng 4 (Bypass L4 TCP Drop)

Lệnh thực thi:
```bash
# Thiết lập tường lửa chặn toàn bộ TCP trên h2
ip netns exec h2 iptables -A INPUT -p tcp -j DROP

# Kiểm tra kết nối TCP bằng netcat (nc)
ip netns exec h1 nc -w2 10.0.0.2 9000
echo "TCP exit code: $?"

# Gửi lại dữ liệu qua ICMP tunnel
ip netns exec h1 python3 /tmp/lab03/icmp_client.py
```

**Nguyên văn Output Kiểm Chứng:**
```text
TCP exit code: 1
[*] Target Server: 10.0.0.2
[*] Exfiltrating data (7 bytes): b'tainbow'
[*] Sending chunk 1/1 (7 bytes): b'tainbow'...
[client] phan hoi tu server: b'ACK:tainbow'
[client] hoan tat gui du lieu qua ICMP
```

**Nhật ký cập nhật tại Server sau 2 đợt gửi (`/tmp/lab03/server.log`):**
```text
[server] dang lang nghe ICMP tren veth2 ...
[server] nhan (7 bytes): b'tainbow'
[server] nhan (7 bytes): b'tainbow'
```

---

### 5. BÓC TÁCH & PHÂN TÍCH CHUYÊN SÂU LOG TERMINAL (BẮT BUỘC)

#### 5.1 Phân Tích Cơ Chế Payload Trong Giao Thức ICMP
Trích xuất từ dòng log tcpdump:
```text
00:41:15.551856 IP 10.0.0.1 > 10.0.0.2: ICMP echo request, id 4919, seq 0, length 15
E..#....@.f.
...
.....-..7..tainbow
```

- **Giải phẫu cấu trúc gói tin:**
  - `ICMP Echo Request`: `Type = 8`, `Code = 0`.
  - `id 4919`: Tương ứng giá trị thập lục phân `0x1337` do client ấn định làm nhãn định danh luồng tunnel.
  - `seq 0`: Số thứ tự của chunk dữ liệu đầu tiên.
  - `length 15`: 8 bytes tiêu đề ICMP cộng thêm **7 bytes tải trọng (payload)**.
  - Dòng dữ liệu ASCII: Chuỗi văn bản thuần túy `tainbow` (nội dung trích từ `/etc/hostname`) xuất hiện lộ thiên ngay trong phần đuôi của gói tin IP.
- **Tại sao TCP/IP lại cho phép chèn payload tùy ý?**
  - Tiêu chuẩn RFC 792 thiết kế giao thức ICMP Echo với mục tiêu ban đầu là kiểm tra khả năng tiếp cận và đo độ trễ RTT giữa hai nút mạng. RFC chỉ quy định trường Data có độ dài tùy biến để phục vụ việc chèn dữ liệu kiểm thử (như timestamp, chuỗi đệm padding), và bên nhận có nghĩa vụ trả về nguyên vẹn dữ liệu nhận được.
  - Tầng IP và ICMP hoàn toàn không có cơ chế xác thực ngữ nghĩa (Semantic Validation) đối với dữ liệu này. Kẻ tấn công lợi dụng đặc tính này để biến trường Data thành kênh mang tin độc hại (Data Carrier).

#### 5.2 Phân Tích Cơ Chế Phản Hồi Kênh 2 Chiều (Bidirectional Covert Channel)
Trích xuất từ dòng log phản hồi:
```text
00:41:15.611668 IP 10.0.0.2 > 10.0.0.1: ICMP echo reply, id 4919, seq 0, length 19
E..'....@.f.
...
........7..ACK:tainbow
```

- Ngay khi nhận được gói Echo Request, máy chủ Scapy ở user-space trích xuất payload, sau đó sinh gói `Echo Reply` (`Type = 0`) với cùng `id 4919` và `seq 0`, nhồi chuỗi `ACK:` vào đầu payload ban đầu thành `ACK:tainbow` ($4 + 7 = 11\text{ bytes}$ data, tổng ICMP length = 19 bytes).
- Gói phản hồi này chứng minh đường truyền ngầm hoàn toàn có thể hoạt động ở chế độ 2 chiều (Full-duplex / Bidirectional): Chiều đi (Outbound) dùng để tuồn dữ liệu mật ra ngoài, chiều về (Inbound) dùng để máy chủ C2 truyền mệnh lệnh điều khiển (Botnet Commands) ngược trở lại cho mã độc bên trong.

#### 5.3 Phân Tích Khả Năng Vượt Tường Lửa Tầng 4 (L4 Firewall Bypass)
- **So sánh kết quả thực nghiệm:**
  - Lệnh kiểm tra kết nối TCP `nc -w2 10.0.0.2 9000` thất bại với **exit code: 1** do quy tắc tường lửa `iptables -A INPUT -p tcp -j DROP` đã drop toàn bộ các gói tin TCP SYN.
  - Trong cùng điều kiện đó, script `icmp_client.py` truyền dữ liệu thành công $100\%$ và nhận đầy đủ phản hồi `b'ACK:tainbow'`.
- **Nguyên nhân cốt lõi:**
  - Tường lửa L4 chỉ giám sát các trường cổng mạng (`Source Port`, `Destination Port`) trong TCP Header (Protocol 6) và UDP Header (Protocol 17).
  - ICMP hoạt động ở Tầng Mạng (Layer 3 - Protocol 1) và **hoàn toàn không có khái niệm Port**. Do đó, mọi luật lọc theo cổng tầng 4 trở nên vô dụng trước các gói tin ICMP nếu quản trị viên cho phép lệnh ping đi qua firewall.

#### 5.4 Đánh Giá Phương Pháp Phát Hiện Bằng IDS/IPS (Suricata / Snort)
Để phát hiện kênh ngầm ICMP Tunneling, hệ thống giám sát an ninh mạng cần triển khai các chỉ dấu (Indicators) sau:
1. **Dị thường Kích thước Payload (Payload Size Anomaly):** Kích thước payload chuẩn của Linux là $56\text{ bytes}$ (tổng gói IP = $84\text{ bytes}$) và Windows là $32\text{ bytes}$ (tổng gói IP = $60\text{ bytes}$). Các gói ICMP có payload nhỏ bất thường (như 7 bytes trong lab) hoặc lớn bất thường ($> 100\text{ bytes}$) phải bị gắn cờ cảnh báo.
2. **Phân tích Entropy Dữ liệu (Payload Entropy Analysis):** Lưu lượng ping thông thường có entropy rất thấp do payload chứa chuỗi lặp (như bảng chữ cái). Khi dữ liệu bị tuồn ra ngoài dưới dạng nhị phân, mã hóa hoặc nén, chỉ số Entropy của trường dữ liệu ICMP sẽ tăng vọt tiệm cận $8.0\text{ bits/byte}$.
3. **Mật độ & Tần suất Phiên Bất thường (Volume & Beaconing Frequency):** Lệnh ping người dùng thường chỉ phát vài gói rồi dừng lại. Kênh tunnel thường duy trì lưu lượng liên tục kéo dài nhiều giờ với khoảng cách giữa các gói có tính chu kỳ (Beaconing) để duy trì kết nối C2.

