# HƯỚNG DẪN TRIỂN KHAI & PHÂN TÍCH KỸ THUẬT: LAB 02
## IP Source Routing Vulnerability (SSRR / LSRR)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG

#### 1.1 Mục Tiêu & Cơ Sở Lý Thuyết
- **Bản chất giao thức IP (RFC 791):** Giao thức IPv4 cung cấp trường IP Options nằm sau 20 byte header cơ bản. Hai tùy chọn Loose Source and Record Route (LSRR - Type 131, `0x83`) và Strict Source and Record Route (SSRR - Type 137, `0x89`) cho phép bên gửi can thiệp vào lộ trình gói tin bằng cách gắn sẵn danh sách các địa chỉ IP của các router trung gian.
- **Lỗ hổng Đảo Tuyến Đường (Route Reversal - RFC 1122):** Theo chuẩn RFC 1122 (mục 3.2.2.4), khi một máy trạm nhận được gói tin có tùy chọn Source Route, khi phản hồi (ví dụ ICMP Echo Reply hoặc TCP SYN/ACK), nó bắt buộc phải đảo ngược lộ trình ghi trong Option và gắn vào gói trả lời.
- **Mối đe dọa 2-Chiều Giả Mạo Nguồn (Two-Way Spoofing):** Lợi dụng cơ chế trên, kẻ tấn công ($10.0.0.1$) có thể gửi gói tin mang IP nguồn giả mạo của một thực thể tin cậy ($10.0.0.77$) nhưng lại đặt danh sách router SSRR trỏ về chính mình ($[10.0.0.1, 10.0.0.2]$). Nạn nhân khi xử lý sẽ đảo ngược lộ trình và gửi phản hồi quay về $10.0.0.1$.
- **Mục tiêu thực nghiệm trong Lab 02:**
  1. Tái tạo môi trường kernel dễ bị tổn thương trên máy nạn nhân bằng cách bật tham số `accept_source_route = 1`.
  2. Dùng Scapy chế tạo gói tin ICMP mang tùy chọn SSRR và IP nguồn giả mạo `10.0.0.77`.
  3. Bắt gói phản hồi tại máy kẻ tấn công và phân tích cấu trúc IHL ($> 5$) bằng bộ lọc BPF (`ip[0] & 0x0f > 5`).
  4. Kích hoạt cơ chế phòng thủ `accept_source_route = 0` theo RFC 7126 và chứng minh gói tin bị drop tức thì.

#### 1.2 Topology Mạng & Quy Ước Thực Thi
- **Mô hình kết nối:** Cặp Network Namespaces nối qua `veth1` $\leftrightarrow$ `veth2`:
  - `[ATTACKER - h1]`: `10.0.0.1/24` trên giao diện `veth1`.
  - `[VICTIM - h2]`: `10.0.0.2/24` trên giao diện `veth2`.
  - Địa chỉ IP mạo danh: `10.0.0.77`.

> 💡 **Quy ước thực thi lệnh:**
> - `[VICTIM - h2]`: Lệnh chạy trong namespace nạn nhân (tiền tố `ip netns exec h2`).
> - `[ATTACKER - h1]`: Lệnh chạy trong namespace kẻ tấn công (tiền tố `ip netns exec h1`).
> - `[HOST / CHUNG]`: Lệnh chạy trực tiếp trên máy ảo Kali.

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC SCRIPT

Trong bước này, ta chuẩn bị 2 tệp kịch bản tại `/tmp/lab02`:

#### 2.1 Kịch Bản `setup_pair.sh` (Vulnerable Network Configuration)
- **Tại sao lại đặt tên như vậy?** Đặt tên là `setup_pair` vì kịch bản này thiết lập cặp máy ảo đối đầu `h1` $\leftrightarrow$ `h2` kết nối qua veth pair.
- **Ý nghĩa của script:** Khởi tạo môi trường mạng ảo hóa cô lập và chủ động cấu hình hạ tầng hạt nhân của máy nạn nhân vào trạng thái có lỗ hổng (vulnerable state) để phục vụ kiểm thử.
- **Ý chính của script làm gì?**
  1. Tạo namespace `h1`, `h2` và cặp card mạng ảo `veth1`, `veth2` với IP `10.0.0.1/24` và `10.0.0.2/24`.
  2. Ghi đè bảng ARP tĩnh trên `h2` cho IP `10.0.0.77` trỏ về MAC của `veth1`.
  3. Can thiệp các biến nhân kernel trên `h2` để chấp nhận Source Route:
     - `net.ipv4.conf.<dev>.accept_source_route = 1`
     - `net.ipv4.conf.<dev>.rp_filter = 0` (Tắt Reverse Path Filtering để kernel không drop gói tin có IP nguồn lạ).
     - `net.ipv4.ip_forward = 1` (Cho phép chuyển tiếp gói tin theo lộ trình chỉ định).
- **Móc nối lý thuyết (Theory Hook):**
  - Móc nối với **RFC 1122**: Mặc định các nhân Linux hiện đại đã vô hiệu hóa `accept_source_route = 0` vì lý do bảo mật. Để tái hiện cuộc tấn công cổ điển lịch sử (từng làm rung chuyển hệ thống mạng Internet giai đoạn thập niên 1990 theo khuyến cáo CERT CA-1995-01), ta bắt buộc phải bật cờ này lên trên máy nạn nhân.

#### 2.2 Kịch Bản `ssrr.py` (Strict Source Routing Packet Crafting)
- **Tại sao lại đặt tên như vậy?** Tên gọi `ssrr` viết tắt trực tiếp từ kỹ thuật **Strict Source and Record Route**.
- **Ý nghĩa của script:** Đóng vai trò là công cụ chế tạo gói tin cấp thấp (Packet Crafter) mang tùy chọn IP Options đặc biệt.
- **Ý chính của script làm gì?**
  1. Sử dụng lớp `IPOption_SSRR(routers=['10.0.0.1', '10.0.0.2'])` trong Scapy để tạo phần mở rộng IP Header.
  2. Gán địa chỉ IP nguồn giả mạo `src = '10.0.0.77'` và đích đến `dst = '10.0.0.2'`.
  3. Lồng gói tin `ICMP(id=0x4242)` mang tải trọng nhận dạng `src-routed-probe` và bắn ra giao diện `veth1`.
- **Móc nối lý thuyết (Theory Hook):**
  - Móc nối với cấu trúc tiêu đề IPv4 trong **RFC 791**: Header chuẩn không có Options dài đúng 20 bytes (trường `IHL = 5`). Khi nhúng `IPOption_SSRR`, tùy chọn gồm: Code (1 byte, `0x89`), Length (1 byte), Pointer (1 byte) và danh sách địa chỉ IPv4 ($2 \times 4 = 8$ bytes) cộng byte padding tròn từ 32-bit $\implies$ Header phình to thành 32 bytes (trường `IHL = 8`), kích hoạt việc đảo lộ trình trên Victim.

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG

Thực thi kịch bản thiết lập:

```bash
# [HOST / CHUNG] Thiết lập topology h1 <-> h2
sudo bash /tmp/lab02/setup_pair.sh
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `sysctl -w net.ipv4.conf.$dev.accept_source_route=1`:
   - `sysctl -w`: Ghi trực tiếp giá trị vào cây cấu hình kernel động (`/proc/sys/`).
   - `accept_source_route`: Tham số quy định kernel có xử lý tùy chọn LSRR/SSRR hay hủy bỏ gói tin. Thiết lập `= 1` cho phép host đóng vai trò xử lý chặng theo tùy chọn định tuyến do nguồn.
2. `sysctl -w net.ipv4.conf.$dev.rp_filter=0`:
   - `rp_filter` (Reverse Path Filtering - RFC 3704): Cơ chế chống giả mạo nguồn. Khi `= 1` (Strict Mode) hoặc `= 2` (Loose Mode), kernel sẽ tra cứu bảng định tuyến xem gói tin có thể đi ngược về IP nguồn qua chính card mạng vừa nhận hay không; nếu không khớp, kernel sẽ drop ngay. Cần tắt về `= 0` để kernel chấp nhận gói tin giả mạo `10.0.0.77` trên giao diện `veth2`.
3. `sysctl -w net.ipv4.ip_forward=1`:
   - Cho phép kernel đóng vai trò router chuyển tiếp các gói tin giữa các chặng trong lộ trình SSRR.

---

### 4. BƯỚC 3: PHÁT ĐỘNG TẤN CÔNG & BẮT GÓI PHẢN HỒI

Quy trình phát động và bắt gói song song:

```bash
# 1. [ATTACKER - h1] Mở tcpdump đón bắt phản hồi dội về kẻ tấn công
sudo ip netns exec h1 tcpdump -i veth1 -nn -v icmp > /tmp/lab02/tcpdump_h1.log 2>&1 &
sleep 1

# 2. [VICTIM - h2] Mở tcpdump với bộ lọc BPF kiểm tra IP Options
sudo ip netns exec h2 tcpdump -i veth2 -nn "ip[0] & 0x0f > 5" > /tmp/lab02/tcpdump_h2_options.log 2>&1 &
sleep 1

# 3. [ATTACKER - h1] Chạy script gửi gói tin SSRR từ h1
sudo ip netns exec h1 python3 /tmp/lab02/ssrr.py
sleep 2
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `tcpdump -i veth1 -nn -v icmp`:
   - `-v`: Cờ Verbose (hiển thị chi tiết). Khi có `-v`, tcpdump sẽ in toàn bộ các trường trong tiêu đề IP, bao gồm TTL, IP ID, cờ DF/MF, và đặc biệt là danh sách chi tiết của trường **IP Options (SSRR)**.
   - `icmp`: Bộ lọc chỉ bắt các gói tin thuộc giao thức ICMP (bỏ qua ARP, STP, v.v.).
2. `"ip[0] & 0x0f > 5"` (Bộ Lọc BPF Nhận Diện IP Options):
   - Đây là biểu thức Byte-level Slicing cực kỳ mạnh mẽ của Berkeley Packet Filter:
     - `ip[0]`: Trích xuất byte đầu tiên (Byte 0) của tiêu đề IP. Theo chuẩn RFC 791, byte 0 gồm 4 bit đầu là trường `Version` (thường là 4 đối với IPv4) và 4 bit sau là trường `IHL` (Internet Header Length).
     - `& 0x0f`: Phép toán AND bitwise với mặt nạ `00001111` để loại bỏ 4 bit Version, chỉ giữ lại nguyên vẹn 4 bit của `IHL`.
     - `> 5`: Bình thường, IP Header không có Option có độ dài 20 bytes, tức $20 / 4 = 5$ từ (IHL = 5). Khi có bất kỳ tùy chọn nào được thêm vào, độ dài phải lớn hơn 20 bytes $\implies \text{IHL} > 5$.
     - Biểu thức này lọc chuẩn xác 100% tất cả các gói tin IPv4 có mang Options trên đường truyền mà không cần quan tâm đến loại option cụ thể nào.

---

### 5. BƯỚC 4: KIỂM CHỨNG KẾT QUẢ

Kiểm tra kết quả thực nghiệm tại hai đầu kết nối:

```bash
# 1. [ATTACKER - h1] Kiểm tra gói tin phản hồi tại máy kẻ tấn công
cat /tmp/lab02/tcpdump_h1.log

# 2. [VICTIM - h2] Kiểm tra kết quả bắt gói của bộ lọc BPF
cat /tmp/lab02/tcpdump_h2_options.log
```

#### Phân Tích Chi Tiết Dữ Liệu Bắt Gói:
1. **Tại Kẻ tấn công (`tcpdump_h1.log`):**
   ```text
   1. IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto ICMP (1), length 52, options (SSRR 10.0.0.1,10.0.0.2))
      10.0.0.77 > 10.0.0.2: ICMP echo request, id 16962, seq 0, length 24
   2. IP (tos 0x0, ttl 64, id 13421, offset 0, flags [none], proto ICMP (1), length 52, options (SSRR 10.0.0.2))
      10.0.0.2 > 10.0.0.77: ICMP echo reply, id 16962, seq 0, length 24
   ```
   - **Gói 1 (Echo Request):** Đi từ `10.0.0.77 > 10.0.0.2` mang tùy chọn `SSRR 10.0.0.1,10.0.0.2`.
   - **Gói 2 (Echo Reply):** Dù địa chỉ đích logic là `10.0.0.77`, nhưng gói tin vật lý lại xuất hiện trên card mạng `veth1` của `10.0.0.1` nhờ kernel của Victim tự động đảo ngược danh sách router trong tùy chọn SSRR. Kẻ tấn công nhận trọn vẹn gói Echo Reply mã định danh `id 16962`. Cuộc tấn công giả mạo 2 chiều thành công!
2. **Tại Nạn nhân (`tcpdump_h2_options.log`):**
   - Bộ lọc `ip[0] & 0x0f > 5` bắt chính xác gói tin vì `length 52` (chứa 32 bytes IP Header, tức $\text{IHL} = 8 > 5$ thay vì 20 bytes chuẩn).

---

### 6. BƯỚC 5: KÍCH HOẠT PHÒNG THỦ & KIỂM CHỨNG LẠI

Tiến hành kích hoạt chính sách an ninh theo khuyến cáo của **RFC 7126**:

```bash
# 1. [VICTIM - h2] Tắt chấp nhận Source Route trên toàn bộ các giao diện của Victim
for dev in all default lo veth2; do
    sudo ip netns exec h2 sysctl -w net.ipv4.conf.$dev.accept_source_route=0
done

# 2. [ATTACKER - h1] Mở lại tcpdump và phát lại gói tin SSRR
sudo ip netns exec h1 tcpdump -i veth1 -nn icmp > /tmp/lab02/tcpdump_defended.log 2>&1 &
sleep 1
sudo ip netns exec h1 python3 /tmp/lab02/ssrr.py
sleep 2

# 3. [ATTACKER - h1] Đọc nhật ký kiểm tra kết quả phòng thủ
cat /tmp/lab02/tcpdump_defended.log
```

#### Phân Tích Cơ Chế Phòng Thủ:
- Khi cấu hình `accept_source_route = 0`, hàm xử lý gói tin tầng IP trong kernel Linux (`ip_rcv_options()` trong file nguồn `net/ipv4/ip_options.c`) sẽ kiểm tra loại tùy chọn:
  - Nếu gặp mã tùy chọn SSRR (`IPOPT_SSRR`) hoặc LSRR (`IPOPT_LSRR`), kernel sẽ lập tức từ chối và giải phóng bộ đệm gói tin (`kfree_skb`).
- **Kết quả trên `tcpdump_defended.log`:**
  ```text
  11:32:01.123456 IP 10.0.0.77 > 10.0.0.2: ICMP echo request, id 16962, seq 0, length 24
  ```
  Chỉ có duy nhất 1 gói Echo Request phát đi từ kẻ tấn công, **hoàn toàn có 0 gói phản hồi nào quay trở lại**. Hệ thống nạn nhân đã miễn nhiễm tuyệt đối trước thủ đoạn giả mạo nguồn qua Source Routing.

---

### 7. BƯỚC 6: DỌN DẸP MÔI TRƯỜNG

Khôi phục trạng thái máy chủ:

```bash
# [HOST / CHUNG] Tắt tiến trình nền và xóa namespaces
sudo pkill -f tcpdump 2>/dev/null || true
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo rm -rf /tmp/lab02
```

- Lệnh `pkill -f tcpdump` kết thúc các tiến trình lắng nghe ngầm, tránh tình trạng chiếm giữ file log hoặc giữ socket thô (packet socket).
- Lệnh `ip netns del` xóa hai namespace và giải phóng toàn bộ cấu hình `sysctl` tạm thời trong namespace đó mà không ảnh hưởng tới kernel chính của máy host.

