# WORKFLOW EXECUTION: LAB 02 - IP SOURCE ROUTING (LSRR/SSRR) VULNERABILITY

Bạn hãy đóng vai trò là một **Senior Network Security Analyst, Packet Crafting Specialist và Linux Kernel Engineer**.

## 1. MỤC TIÊU & BỐI CẢNH KỸ THUẬT
- **Mục tiêu:** Thực thi và kiểm chứng lỗ hổng IP Source Routing (Strict Source and Record Route - SSRR) trong môi trường Linux Network Namespace cục bộ trên máy ảo Kali Linux thông qua tool `kali-vm:ssh_execute`.
- **Cơ chế cốt lõi:** Chứng minh cách kẻ tấn công giả mạo IP nguồn (spoofed IP `10.0.0.77`) nhưng vẫn nhận được phản hồi hai chiều nhờ ép kernel của nạn nhân đảo ngược lộ trình SSRR quay về chính mình (`10.0.0.1`).
- **Mục tiêu phòng thủ:** Kiểm chứng cơ chế bảo vệ của Linux kernel hiện đại (`net.ipv4.conf.*.accept_source_route = 0`) và phương pháp lọc gói tin có IP Options tại biên mạng dựa vào trường độ dài tiêu đề IP Header Length (IHL > 5).

---

## 2. QUY TRÌNH THỰC THI CHI TIẾT (5 GIAI ĐOẠN)

### GIAI ĐOẠN 1: Chuẩn bị Script Cục bộ & Khởi tạo Topology
1. Tạo thư mục `docs/progress/LAB02/scripts/` trên workspace host.
2. Tạo script `setup_pair.sh`:
   - Dọn dẹp sạch các namespace cũ (`h1`, `h2`) và link (`veth1`, `veth2`) nếu còn tồn tại.
   - Tạo 2 namespace: `h1` (`10.0.0.1/24`) đóng vai Attacker, `h2` (`10.0.0.2/24`) đóng vai Victim.
   - **Tái tạo điều kiện dễ bị tấn công:** Bật `accept_source_route = 1` và tắt `rp_filter = 0` trên cả 2 namespace (cho các interface `all`, `veth1`, `veth2`).
   - Kiểm tra kết nối ping baseline giữa `h1` và `h2`.
3. Tạo script Scapy tấn công `ssrr.py`:
   - Tạo gói tin:
     ```python
     IP(src="10.0.0.77", dst="10.0.0.2", options=[IPOption_SSRR(routers=["10.0.0.1", "10.0.0.2"])]) / ICMP(id=0x4242) / b"src-routed-probe"
     ```
   - Gửi gói tin qua hàm `send()`.

### GIAI ĐOẠN 2: Triển khai lên Kali VM & Kiểm tra Môi trường
1. Dùng `ssh_execute` tạo thư mục `/tmp/lab02` trên Kali VM.
2. Đẩy file script lên Kali VM và phân quyền thực thi `chmod +x /tmp/lab02/setup_pair.sh`.
3. Chạy setup và ghi nhận kết quả ping, kiểm tra trạng thái sysctl trên `h1` và `h2` qua lệnh:
   ```bash
   ip netns exec h1 sysctl net.ipv4.conf.veth1.accept_source_route net.ipv4.conf.veth1.rp_filter
   ip netns exec h2 sysctl net.ipv4.conf.veth2.accept_source_route net.ipv4.conf.veth2.rp_filter
   ```

### GIAI ĐOẠN 3: Phát động Tấn công SSRR (Bi-directional Spoofing)
1. Mở tiến trình `tcpdump` trên `h1` để bắt gói tin ICMP phản hồi dội về chính mình (chạy timeout 6 giây ghi log ra `/tmp/lab02/tcpdump_h1_attack.log`):
   ```bash
   ip netns exec h1 timeout 6 tcpdump -i veth1 -nn -v icmp > /tmp/lab02/tcpdump_h1_attack.log 2>&1 &
   ```
2. Thực thi script `ssrr.py` từ namespace `h1`:
   ```bash
   ip netns exec h1 python3 /tmp/lab02/ssrr.py
   ```
3. Đọc log `/tmp/lab02/tcpdump_h1_attack.log` để xác nhận: Gói Echo Request gửi đi từ `10.0.0.77`, nhưng gói Echo Reply từ `10.0.0.2` lại dội ngược về đúng `10.0.0.1`.

### GIAI ĐOẠN 4: Kiểm chứng Phòng thủ & Phát hiện Gói tin IP Option
1. **Kiểm tra bộ lọc IHL:** Mở `tcpdump` trên `h2` lọc các gói có IP options (IHL > 5 tương ứng biểu thức bit `ip[0] & 0x0f > 5`):
   ```bash
   ip netns exec h2 timeout 6 tcpdump -i veth2 -nn -v "ip[0] & 0x0f > 5" > /tmp/lab02/tcpdump_h2_ihl.log 2>&1 &
   ```
2. Gửi lại script `ssrr.py` để ghi nhận gói tin bị bộ lọc nhận diện.
3. **Bật cơ chế phòng vệ:** Đặt lại `accept_source_route = 0` trên `h2`:
   ```bash
   for k in all veth2; do
       ip netns exec h2 sysctl -w net.ipv4.conf.$k.accept_source_route=0
   done
   ```
4. Mở lại `tcpdump` trên `h1`, gửi lại `ssrr.py` và chứng minh: Victim hủy bỏ gói tin, không còn bất kỳ gói Echo Reply nào dội về `h1`.

### GIAI ĐOẠN 5: Báo cáo Thực nghiệm & Dọn dẹp Môi trường
1. Tạo tệp `docs/progress/LAB02/IMPLEMENTATION.md`:
   - Mô tả mục đích từng bước thực hiện và phân tích chi tiết mã nguồn Scapy `IPOption_SSRR`.
   - Giải thích vai trò của các tham số kernel `accept_source_route` và `rp_filter`.
2. Tạo tệp `docs/progress/LAB02/lab2_result.md` với định dạng bắt buộc ở Mục 3 bên dưới.
3. Dọn dẹp môi trường: Xóa 2 namespace `h1`, `h2` và thư mục `/tmp/lab02`.
4. Cập nhật trạng thái `[x]` cho Lab 02 trong `PLAN.md`.

---

## 3. YÊU CẦU CẤU TRÚC BÁO CÁO docs/progress/LAB02/lab2_result.md
Tệp kết quả phải bao gồm:
- **Metadata:** Thời gian chạy, Kernel version, Công cụ sử dụng.
- **Terminal Outputs thô (Raw Logs):** Toàn bộ stdout/stderr của từng giai đoạn (setup, ping, sysctl, tcpdump).
- **BÓC TÁCH & PHÂN TÍCH CHUYÊN SÂU LOG TERMINAL (BẮT BUỘC):**
  - **Phân tích Log Bước 3 (SSRR Attack):** Trích xuất từng dòng log tcpdump; giải thích vì sao gói gửi đi có IP nguồn là `10.0.0.77` nhưng gói Reply lại gửi về `10.0.0.1`. Chỉ ra địa chỉ IP nào nằm trong trường SSRR list và cơ chế Kernel đảo ngược danh sách này như thế nào.
  - **Phân tích Log Bước 4 (IHL Filter & Defense):** Giải thích tại sao cờ proto ICMP (1), length ... và options (SSRR ...) làm kích thước tiêu đề IP vượt quá 20 bytes thông thường (IHL = 5 * 4 = 20 bytes), dẫn đến điều kiện `ip[0] & 0x0f > 5` bắt được gói.
  - **Đánh giá hiệu quả phòng thủ:** So sánh trạng thái trước và sau khi kích hoạt `accept_source_route=0`.

---

## 4. STRICT RULES
- Mọi thao tác trên Kali Linux BẮT BUỘC gọi qua `kali-vm:ssh_execute`.
- TUYỆT ĐỐI KHÔNG để các lệnh tcpdump chạy vô hạn; luôn bọc bằng lệnh `timeout 6` và redirect ra file log tạm.
- Tuyệt đối không giả lập log; 100% dữ liệu trong `lab2_result.md` phải là log thực tế trích từ Kali VM.
