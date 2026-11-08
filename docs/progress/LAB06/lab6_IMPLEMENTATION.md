# HƯỚNG DẪN TRIỂN KHAI & PHÂN TÍCH KỸ THUẬT: LAB 06
## Teardrop Attack (IP Fragmentation Overlap)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG

#### 1.1 Mục Tiêu & Cơ Sở Lý Thuyết
- **Bản chất cơ chế phân mảnh IP (RFC 791):** Khi gói tin IP có kích thước lớn hơn đơn vị truyền dẫn tối đa (MTU) của liên kết, IP Header sử dụng 3 trường để phân chia và tái hợp mảnh:
  - `Identification (16 bit)`: Định danh chung cho tất cả các mảnh của cùng một gói gốc.
  - `Flags (3 bit)`: Cờ `MF` (More Fragments, $1$ nếu còn mảnh sau, $0$ nếu là mảnh cuối).
  - `Fragment Offset (13 bit)`: Vị trí byte bắt đầu của mảnh trong gói gốc, tính theo **đơn vị khối 8 byte (8-octet blocks)**.
- **Lỗ hổng Teardrop lịch sử (CVE-1999-0015):** Xuất hiện vào năm 1997, khai thác lỗi số học con trỏ trong mã nguồn tái hợp mảnh (IP Reassembly) của hệ điều hành thế hệ cũ (Linux trước 2.0.32, Windows 95/NT). Khi nhận các mảnh có dải byte chồng lấn (overlapping) hoặc dải offset bất thường, phép trừ tính toán độ dài dữ liệu mới bị tràn số dưới (Integer Underflow), sinh ra số nguyên âm. Khi truyền vào hàm `memcpy()`, số này bị ép kiểu thành số nguyên không dấu khổng lồ ($\approx 4\text{ GB}$), dẫn tới ghi đè bộ nhớ nhân và làm sập hệ thống (Kernel Panic / Blue Screen of Death).
- **Cơ chế xử lý an toàn của Linux Kernel hiện đại (RFC 1858 / RFC 3128):** Nhân Linux hiện đại đã thiết kế lại thuật toán tái hợp mảnh (`ip_frag_reasm` trong `net/ipv4/ip_fragment.c`):
  1. Kiểm tra biên chặt chẽ cho từng mảnh trong danh sách liên kết `ipq`.
  2. Phát hiện các mảnh có offset bất thường hoặc chồng lấn không thể dung hòa, kernel sẽ hủy toàn bộ hàng đợi mảnh mà không bao giờ gây lỗi bộ nhớ.
  3. Ghi nhận lỗi vào bộ đếm thống kê mạng chuẩn MIB-II tại `/proc/net/snmp` (cụ thể là biến `ReasmFails`).
- **Mục tiêu thực nghiệm trong Lab 06:**
  1. Sử dụng Scapy chế tạo 2 mảnh IP Teardrop có dải byte chồng lấn 16 bytes:
     - Mảnh 1: `offset = 0`, `MF = 1`, dài 24 bytes (chiếm byte $0 \rightarrow 23$).
     - Mảnh 2: `offset = 1` (byte $1 \times 8 = 8$), `MF = 0`, dài 24 bytes (chiếm byte $8 \rightarrow 31$).
  2. Bắt gói tin trên card mạng của nạn nhân để phân tích chi tiết trường `offset` và cờ `MF`.
  3. Kiểm chứng sức sống của nạn nhân (100% gói ping thông suốt, không crash) và kiểm tra log hạt nhân `dmesg`.
  4. Đọc biến đếm `/proc/net/snmp` để chứng minh `ReasmReqds = 2` và `ReasmFails = 1`.

#### 1.2 Topology Mạng & Quy Ước Thực Thi
- **Mô hình kết nối:** Cặp Network Namespaces nối qua `veth1` $\leftrightarrow$ `veth2`:
  - `[ATTACKER - h1]`: `10.0.0.1/24` trên `veth1`.
  - `[VICTIM - h2]`: `10.0.0.2/24` trên `veth2`.

> 💡 **Quy ước thực thi lệnh:**
> - `[VICTIM - h2]`: Lệnh chạy trong namespace nạn nhân (tiền tố `ip netns exec h2`).
> - `[ATTACKER - h1]`: Lệnh chạy trong namespace kẻ tấn công (tiền tố `ip netns exec h1`).
> - `[HOST / CHUNG]`: Lệnh chạy trực tiếp trên máy ảo Kali.

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC SCRIPT

Trong bước này, ta chuẩn bị 2 tệp kịch bản tại `/tmp/lab06`:

#### 2.1 Kịch Bản `setup_pair.sh` (Point-to-Point Network Setup)
- **Tại sao lại đặt tên như vậy?** Đặt tên là `setup_pair` vì kịch bản này thiết lập cặp host mạng đối đầu `h1` và `h2` kết nối điểm-điểm.
- **Ý nghĩa của script:** Khởi tạo môi trường mạng ảo hóa cô lập cho phép kiểm tra chi tiết các chỉ số thống kê SNMP của nhân kernel mà không bị ảnh hưởng bởi lưu lượng bên ngoài máy host.
- **Ý chính của script làm gì?**
  1. Tạo 2 namespace `h1` và `h2`.
  2. Tạo cặp card mạng ảo `veth1` $\leftrightarrow$ `veth2`, gán IP `10.0.0.1/24` và `10.0.0.2/24`.
  3. Kiểm tra ping cơ bản để kích hoạt trạng thái UP của giao diện.
- **Móc nối lý thuyết (Theory Hook):**
  - Môi trường namespace tách biệt đảm bảo biến đếm `/proc/net/snmp` của `h2` phản ánh chính xác 100% từng gói tin do kẻ tấn công `h1` gửi đến.

#### 2.2 Kịch Bản `teardrop.py` (Overlapping Fragment Generator)
- **Tại sao lại đặt tên như vậy?** Đặt tên theo cuộc tấn công **Teardrop** kinh điển trong lịch sử an toàn thông tin.
- **Ý nghĩa của script:** Chế tạo thủ công các mảnh phân đoạn IP mang cấu trúc hình học chồng lấn.
- **Ý chính của script làm gì?**
  1. Gán chung mã định danh: `ipid = 1234` và giao thức UDP (`proto = 17`).
  2. **Mảnh 1:** `flags = "MF"`, `frag = 0`, tải trọng 24 bytes `b"A" * 24` (byte $0 \rightarrow 23$).
  3. **Mảnh 2:** `flags = 0` (mảnh cuối), `frag = 1` (tương ứng offset $1 \times 8 = 8$), tải trọng 24 bytes `b"B" * 24` (byte $8 \rightarrow 31$).
  4. Gửi đồng thời danh sách `[f1, f2]` tới IP đích `10.0.0.2`.
- **Móc nối lý thuyết (Theory Hook):**
  - Móc nối với quy tắc tính toán offset trong **RFC 791**: Trường `frag` trong Scapy đại diện cho giá trị của trường Fragment Offset trong IP Header (tính theo đơn vị 8 byte). Khi đặt `frag = 1`, vị trí bắt đầu là byte số 8. Vì Mảnh 1 trải dài từ byte 0 đến byte 23, vùng nhớ từ byte $8 \rightarrow 23$ bị đè lên nhau đúng 16 bytes.

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG & GHI NHẬN BASELINE SNMP

Thực thi kịch bản và ghi lại trạng thái ban đầu của hệ điều hành:

```bash
# 1. [HOST / CHUNG] Chạy setup mạng
sudo bash /tmp/lab06/setup_pair.sh

# 2. [VICTIM - h2] Ghi nhận thống kê tái hợp mảnh IP trước khi tấn công
sudo ip netns exec h2 sh -c "cat /proc/net/snmp | grep -A1 '^Ip:'"
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `cat /proc/net/snmp | grep -A1 '^Ip:'`:
   - `/proc/net/snmp`: Tệp ảo do nhân Linux cung cấp, phản ánh trực tiếp các bộ đếm mạng MIB-II (Management Information Base) theo chuẩn RFC 1213.
   - `grep -A1 '^Ip:'`: Trích xuất dòng tiêu đề các cột của giao thức IP và đúng 1 dòng dữ liệu số liệu thống kê đi kèm ngay sau nó (`-A1` = After 1 line).
2. **Các cột chỉ số tái hợp mảnh quan trọng cần lưu ý:**
   - `ReasmReqds`: Số lượng mảnh IP được đưa vào hàng đợi tái hợp (Reassembly Requests).
   - `ReasmOKs`: Số lượng gói IP được tái hợp thành công hoàn chỉnh.
   - `ReasmFails`: Số lần tái hợp thất bại (do hết hạn thời gian chờ timeout hoặc do mảnh bị hỏng/chồng lấn bất thường).
   - **Baseline ban đầu:** Tất cả các chỉ số trên đều bằng `0`.

---

### 4. BƯỚC 3: PHÁT ĐỘNG TẤN CÔNG & GIÁM SÁT SỨC SỐNG

Khởi chạy hệ thống giám sát và phát động tấn công:

```bash
# 1. [VICTIM - h2] Mở tcpdump trên h2 để bắt các mảnh IP đến
sudo ip netns exec h2 tcpdump -i veth2 -nn -v ip > /tmp/lab06/tcpdump_frag.log 2>&1 &
sleep 1

# 2. [VICTIM - h2] Mở luồng ping kiểm tra sức sống liên tục từ h2 về h1
sudo ip netns exec h2 ping -i 0.3 -c 10 10.0.0.1 > /tmp/lab06/ping_health.log 2>&1 &
sleep 1

# 3. [ATTACKER - h1] Phát động gửi các mảnh Teardrop từ h1
sudo ip netns exec h1 python3 /tmp/lab06/teardrop.py
sleep 3
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `tcpdump -i veth2 -nn -v ip`:
   - `-v`: Bắt buộc phải có để hiển thị các cờ phân mảnh (`flags [+]` cho MF=1) và trường `offset`.
   - `ip`: Bộ lọc tầng 3, bắt toàn bộ các gói tin IPv4.
2. `ping -i 0.3 -c 10 10.0.0.1`:
   - `-i 0.3` (Interval): Gửi gói ping với tần suất dày đặc hơn mặc định (0.3 giây/gói thay vì 1 giây/gói).
   - `-c 10` (Count): Gửi đúng 10 gói tin.
   - **Ý nghĩa kỹ thuật:** Đây là phép đo "nhịp tim" (Heartbeat / Health Check) của hệ thống. Nếu kernel bị treo hoặc crash do lỗi xử lý bộ nhớ của Teardrop, luồng ping này sẽ bị ngắt quãng hoặc báo packet loss ngay lập tức.

---

### 5. BƯỚC 4: KIỂM CHỨNG KẾT QUẢ

Thực hiện kiểm chứng đa chiều: Phân tích gói tin $\rightarrow$ Kiểm tra sức sống $\rightarrow$ Đối chiếu SNMP $\rightarrow$ Kiểm tra Kernel Panic:

```bash
# 1. [HOST / CHUNG] Kiểm tra log bắt gói tcpdump
cat /tmp/lab06/tcpdump_frag.log | grep "id 1234"

# 2. [HOST / CHUNG] Kiểm tra sức sống của nạn nhân
cat /tmp/lab06/ping_health.log | tail -n 3

# 3. [VICTIM - h2] Kiểm tra biến đếm SNMP sau tấn công
sudo ip netns exec h2 sh -c "cat /proc/net/snmp | grep -A1 '^Ip:'"

# 4. [HOST / CHUNG] Kiểm tra nhật ký nhân Linux
dmesg | tail -n 10
```

#### Phân Tích Kết Quả Thực Nghiệm:
1. **Phân tích gói tin (`tcpdump_frag.log`):**
   ```text
   IP (tos 0x0, ttl 64, id 1234, offset 0, flags [+], proto UDP (17), length 44)
       10.0.0.1 > 10.0.0.2: udp
   IP (tos 0x0, ttl 64, id 1234, offset 8, flags [none], proto UDP (17), length 44)
       10.0.0.1 > 10.0.0.2: udp
   ```
   - Mảnh 1: `id 1234`, `offset 0`, `flags [+]` ($MF=1$), payload $44 - 20 = 24$ bytes.
   - Mảnh 2: `id 1234`, `offset 8`, `flags [none]` ($MF=0$), payload 24 bytes.
   - Khẳng định 2 mảnh Teardrop chồng lấn đã tới đích thành công.
2. **Kiểm tra sức sống (`ping_health.log`):**
   ```text
   10 packets transmitted, 10 received, 0% packet loss, time 2704ms
   rtt min/avg/max/mdev = 0.045/0.062/0.098/0.015 ms
   ```
   Nạn nhân phản hồi đầy đủ 10/10 gói ping với độ trễ cực thấp, hệ thống hoàn toàn bình an vô sự.
3. **Phân tích biến đếm SNMP:**
   - `ReasmReqds`: Tăng từ $0 \rightarrow \mathbf{2}$ (kernel đã tiếp nhận đúng 2 mảnh rời rạc có ID 1234).
   - `ReasmOKs`: Vẫn giữ nguyên là $\mathbf{0}$ (không có gói tin nào được tái hợp).
   - `ReasmFails`: Tăng từ $0 \rightarrow \mathbf{1}$ (thuật toán kiểm tra biên phát hiện chồng lấn bất thường và drop an toàn).
4. **Nhật ký kernel (`dmesg`):**
   - Hoàn toàn sạch sẽ, không có bất kỳ thông báo "Kernel Panic", "Oops" hay "Out of Bounds Memory Access" nào. Điều này chứng minh nhân Linux hiện đại đã giải quyết triệt để lỗ hổng CVE-1999-0015 ở cấp độ kiến trúc.

---

### 6. BƯỚC 5: DỌN DẸP MÔI TRƯỜNG

Khôi phục hệ thống:

```bash
# [HOST / CHUNG] Tắt tiến trình nền và xóa namespaces
sudo pkill -f tcpdump 2>/dev/null || true
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo rm -rf /tmp/lab06
```

- Tắt tiến trình `tcpdump`, xóa hai namespace `h1`, `h2` và xóa thư mục `/tmp/lab06`.

