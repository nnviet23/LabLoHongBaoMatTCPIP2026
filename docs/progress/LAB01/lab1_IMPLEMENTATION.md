# HƯỚNG DẪN TRIỂN KHAI & PHÂN TÍCH KỸ THUẬT: LAB 01
## TCP ISN Prediction & Blind Spoofing Attack

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG

#### 1.1 Mục Tiêu & Cơ Sở Lý Thuyết
- **Bản chất giao thức TCP (RFC 793):** Giao thức TCP thiết lập kết nối tin cậy thông qua quá trình bắt tay 3 bước (3-way handshake) bằng hai số thứ tự khởi tạo: Client ISN và Server ISN. Tầng TCP thuần túy hoàn toàn tin tưởng vào địa chỉ IP nguồn và giá trị xác nhận $ACK = ISN_{\text{server}} + 1$.
- **Mối đe dọa (RFC 1948 / RFC 6528):** Nếu giá trị ISN của máy chủ tuân theo quy luật dễ đoán (ví dụ tăng tuyến tính theo thời gian hoặc bộ đếm cố định), kẻ tấn công ngoài luồng (Off-path Attacker) có thể giả mạo IP nguồn của một máy chủ tin cậy ($IP_{\text{trusted}}$) để hoàn tất bắt tay 3 bước và bơm dữ liệu độc hại mà không cần nhận gói tin phản hồi $SYN+ACK$.
- **Mục tiêu thực nghiệm trong Lab 01:**
  1. Thu thập 30 mẫu ISN liên tiếp từ nạn nhân để kiểm chứng tính ngẫu nhiên hóa mật mã theo chuẩn RFC 6528 trên nhân Linux hiện đại.
  2. Thực hiện kịch bản tấn công giả mạo IP nguồn ($10.0.0.77$) bắt tay 3 bước và bơm payload thành công vào dịch vụ lắng nghe của nạn nhân.

#### 1.2 Topology Mạng & Quy Ước Thực Thi
- **Mô hình kết nối:** Hai Network Namespaces cô lập kết nối trực tiếp qua cặp card mạng ảo `veth1` $\leftrightarrow$ `veth2`:
  - `[ATTACKER - h1]`: `10.0.0.1/24` trên giao diện `veth1`.
  - `[VICTIM - h2]`: `10.0.0.2/24` trên giao diện `veth2`.
  - Địa chỉ IP bị mạo danh: `10.0.0.77` (thuộc cùng dải mạng `10.0.0.0/24`).

> 💡 **Quy ước thực thi lệnh:**
> - `[VICTIM - h2]`: Lệnh chạy trong namespace nạn nhân (tiền tố `ip netns exec h2`).
> - `[ATTACKER - h1]`: Lệnh chạy trong namespace kẻ tấn công (tiền tố `ip netns exec h1`).
> - `[HOST / CHUNG]`: Lệnh chạy trực tiếp trên máy ảo Kali.

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC SCRIPT

Trong bước này, ta chuẩn bị 3 tệp kịch bản tại `/tmp/lab01`. Dưới đây là phân tích chi tiết lý do đặt tên, ý nghĩa và mối liên kết lý thuyết:

#### 2.1 Kịch Bản `setup_pair.sh` (Network Environment Setup)
- **Tại sao lại đặt tên như vậy?** Đặt tên là `setup_pair` vì kịch bản này khởi tạo một cặp namespace mạng đối đầu đối xứng (`h1` $\leftrightarrow$ `h2`) kết nối qua một cặp cáp mạng ảo đối tiếp (`veth pair`).
- **Ý nghĩa của script:** Tự động hóa toàn bộ việc dọn dẹp môi trường cũ, tạo không gian mạng ảo hóa cô lập cấp kernel, cấp phát IP và cấu hình các quy tắc firewall/routing tiền đề.
- **Ý chính của script làm gì?**
  1. Xóa các namespace cũ để đảm bảo tính tái lập.
  2. Tạo 2 namespace `h1` (Attacker) và `h2` (Victim).
  3. Tạo cặp card mạng ảo `veth1` $\leftrightarrow$ `veth2`, gắn vào 2 namespace và gán IP `10.0.0.1/24` và `10.0.0.2/24`.
  4. Cấu hình bảng Neighbor tĩnh (ARP) trên `h2` cho IP giả mạo `10.0.0.77` trỏ về địa chỉ MAC của `veth1`.
  5. Cài đặt luật `iptables` trên `h1` để chặn gói tin `TCP RST` do kernel tự sinh.
- **Móc nối lý thuyết (Theory Hook):**
  - *Tại sao cần ARP tĩnh cho IP giả mạo?* Khi nạn nhân phản hồi gói `SYN+ACK` về `10.0.0.77`, vì cùng dải `/24`, nạn nhân sẽ broadcast ARP Request hỏi MAC của `10.0.0.77`. Trong môi trường lab ảo, thiết lập neighbor tĩnh mô phỏng hoàn hảo việc kẻ tấn công nằm cùng phân đoạn mạng LAN và thu nhận gói phản hồi.
  - *Tại sao kernel tự sinh RST?* (RFC 793) Khi Scapy gửi gói SYN từ user-space bằng raw socket, kernel của `h1` không lưu socket này trong bảng Transmission Control Block (TCB). Khi `h2` gửi `SYN+ACK` về, kernel `h1` nhận thấy gói tin cho một cổng không có tiến trình nào quản lý nên theo chuẩn TCP sẽ lập tức bắn lại gói `RST` (Reset) để đóng kết nối. Luật `iptables DROP RST` triệt tiêu hành vi này, cho phép Scapy toàn quyền điều khiển phiên bắt tay.

#### 2.2 Kịch Bản `isn_sampler.py` (ISN Sampler & Predictability Analysis)
- **Tại sao lại đặt tên như vậy?** Tên gọi ghép từ `isn` (Initial Sequence Number) và `sampler` (bộ lấy mẫu) nhằm thể hiện chức năng thu thập mẫu thống kê chuỗi ISN.
- **Ý nghĩa của script:** Đóng vai trò là công cụ đo lường thực nghiệm tính ngẫu nhiên của bộ sinh ISN trên hệ điều hành mục tiêu.
- **Ý chính của script làm gì?**
  1. Gửi 30 gói `TCP SYN` liên tiếp với cổng nguồn khác nhau (`sport = 20000 + i`) tới cổng 9000 của Victim.
  2. Bắt gói tin `SYN+ACK` phản hồi bằng hàm `sr1()`.
  3. Trích xuất trường `seq` (chính là Server ISN) và tính toán độ chênh lệch (Delta) giữa hai mẫu liên tiếp: $\Delta_i = ISN_i - ISN_{i-1}$.
- **Móc nối lý thuyết (Theory Hook):**
  - Móc nối trực tiếp với **RFC 6528**: Nếu hệ thống cũ sử dụng bộ đếm thời gian (clock-driven) như thời BSD 4.2 (tăng cố định theo microsecond), $\Delta$ sẽ xấp xỉ một hằng số dương nhỏ, cho phép kẻ tấn công ngoại tuyến tính toán chính xác ISN tiếp theo. Ngược lại, nếu Linux áp dụng hàm băm mật mã (SipHash) với secret key ngẫu nhiên, $\Delta$ sẽ dao động hỗn loạn trên toàn bộ không gian số nguyên 32-bit ($0 \rightarrow 2^{32}-1$).

#### 2.3 Kịch Bản `spoof_sniff.py` (Spoofed Handshake & Payload Injection)
- **Tại sao lại đặt tên như vậy?** Tên gọi ghép từ `spoof` (giả mạo IP nguồn) và `sniff` (lắng nghe bắt gói) để phản ánh quy trình 2 giai đoạn: gửi gói giả mạo, đón bắt phản hồi, trích xuất ISN và hoàn tất kết nối.
- **Ý nghĩa của script:** Hiện thực hóa cuộc tấn công mạo danh IP nguồn để vượt qua kiểm soát truy cập và bơm dữ liệu vào hệ thống nạn nhân.
- **Ý chính của script làm gì?**
  1. Chế tạo và phát gói `TCP SYN` mang IP nguồn giả mạo `10.0.0.77` tới `10.0.0.2:8080`.
  2. Dùng hàm `sniff()` trên card mạng `veth1` để đón bắt gói `SYN+ACK` tương ứng gửi về cho `10.0.0.77`.
  3. Trích xuất Server ISN thực tế.
  4. Chế tạo gói `TCP ACK` thứ 3 mang `ack = Server_ISN + 1` và gửi đi để chuyển trạng thái TCP sang `ESTABLISHED`.
  5. Chế tạo gói `TCP PSH+ACK` chứa tải trọng chuỗi byte `hello-from-spoofed-source\n` và bơm vào luồng dữ liệu.
- **Móc nối lý thuyết (Theory Hook):**
  - Móc nối với quy tắc quản lý trạng thái TCP (Finite State Machine - FSM): Máy chủ chỉ chuyển từ `SYN_RECEIVED` sang `ESTABLISHED` khi nhận được gói ACK có số xác nhận trùng khớp với $ISN + 1$. Sau khi trạng thái được xác lập, cờ `PSH` (Push) buộc TCP đẩy ngay dữ liệu từ bộ đệm socket lên ứng dụng tầng trên (`ncat`), hoàn tất cuộc tấn công.

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG

Thực thi kịch bản thiết lập topology bằng quyền quản trị:

```bash
# [HOST / CHUNG] Thiết lập topology h1 <-> h2
sudo bash /tmp/lab01/setup_pair.sh
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `ip netns add <tên>`:
   - Tạo mới một network namespace trong nhân Linux. Mỗi namespace có bảng định tuyến (`ip route`), danh sách giao diện mạng (`ip link`), bảng ARP (`ip neigh`) và quy tắc lọc gói (`iptables`) hoàn toàn độc lập.
2. `ip link add veth1 type veth peer name veth2`:
   - Tạo cặp Virtual Ethernet (veth pair). Veth hoạt động ở Tầng 2 (Data Link), tương tự một sợi cáp mạng ảo cắm giữa hai máy ảo; bất kỳ frame Ethernet nào đi vào `veth1` sẽ ngay lập tức xuất hiện tại đầu ra `veth2` và ngược lại.
3. `ip link set <giao_diện> netns <tên_ns>`:
   - Chuyển giao diện mạng vào không gian quản lý của namespace được chỉ định.
4. `ip netns exec <tên_ns> <lệnh>`:
   - Yêu cầu Linux Kernel thực thi một câu lệnh cụ thể bên trong bối cảnh mạng của namespace đó.
5. `ip neigh replace 10.0.0.77 lladdr "$VETH1_MAC" dev veth2`:
   - Cú pháp `ip neigh` can thiệp trực tiếp vào bộ đệm ARP (Neighbor Table) của kernel.
   - Tham số `replace`: Ghi đè hoặc thêm mới một mục ánh xạ IP $\leftrightarrow$ MAC tĩnh.
   - Tham số `lladdr`: Viết tắt của Link-Layer Address (địa chỉ MAC lớp 2). Việc gán IP `10.0.0.77` với MAC của `veth1` đảm bảo mọi frame phản hồi gửi tới IP này sẽ được chuyển thẳng sang card mạng của kẻ tấn công.
6. `iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`:
   - Tham số `-A OUTPUT`: Gắn luật vào chuỗi ra của máy chủ.
   - `-p tcp`: Áp dụng cho giao thức TCP.
   - `--tcp-flags RST RST`: Bộ lọc kiểm tra trường TCP Flags; kiểm tra cờ RST và bắt buộc cờ RST phải được bật (`1`).
   - `-j DROP`: Hủy bỏ gói tin âm thầm mà không gửi thông báo lỗi ICMP Unreachable.

---

### 4. BƯỚC 3: THU THẬP & ĐÁNH GIÁ ĐỘ NGẪU NHIÊN CỦA ISN

Quy trình thực hiện theo đúng các bước trong `lab1_GET_STARTED.md`:

```bash
# 1. [VICTIM - h2] Mở dịch vụ ncat lắng nghe cổng 9000
sudo ip netns exec h2 ncat -lvk -p 9000 >/dev/null 2>&1 &
NCAT_SAMPLER_PID=$!

# 2. [ATTACKER - h1] Chạy lấy mẫu 30 ISN gửi tới Victim
sudo ip netns exec h1 python3 /tmp/lab01/isn_sampler.py
sudo kill $NCAT_SAMPLER_PID 2>/dev/null || true
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `ncat -lvk -p 9000 >/dev/null 2>&1 &`:
   - `-l` (`--listen`): Chạy ở chế độ máy chủ lắng nghe kết nối đến.
   - `-v` (`--verbose`): Hiển thị chi tiết nhật ký kết nối.
   - `-k` (`--keep-open`): Giữ socket tiếp tục lắng nghe, cho phép chấp nhận nhiều kết nối liên tiếp mà không bị tắt tiến trình sau khi một kết nối đóng lại (cần thiết cho 30 lần bắt tay).
   - `-p 9000`: Chỉ định cổng TCP lắng nghe là 9000.
   - `>/dev/null 2>&1`: Chuyển hướng toàn bộ luồng stdout và stderr vào thiết bị rác để tránh làm rối màn hình console.
   - `&`: Chạy tiến trình trong background (chạy ngầm).
   - `NCAT_SAMPLER_PID=$!`: Biến đặc biệt `$!` trong Bash lưu trữ PID của tiến trình chạy ngầm gần nhất, phục vụ cho lệnh dọn dẹp bằng `kill` ngay sau đó.
2. `isn_sampler.py` và giải mã Delta:
   - Khi chạy script, ta quan sát các giá trị Delta in ra:
     ```text
     Mẫu #01: ISN=3115433129 | Delta=0
     Mẫu #02: ISN=1287491456 | Delta=-1827941673
     Mẫu #03: ISN=3981249102 | Delta=2693757646
     ...
     ```
   - **Đánh giá mật mã học:** Giá trị Delta biến thiên cực lớn (hàng tỷ đơn vị, luân phiên âm và dương). Điều này chứng minh nhân Linux sử dụng thuật toán PRNG mật mã theo RFC 6528:
     $$ISN = M + F(\text{SrcIP}, \text{SrcPort}, \text{DstIP}, \text{DstPort}, \text{SecretKey})$$
     Vì mỗi lần gửi có `SrcPort` thay đổi, đầu ra của hàm băm $F$ thay đổi hoàn toàn ngẫu nhiên (hiệu ứng tuyết lở - avalanche effect), khiến kẻ tấn công off-path không thể suy đoán giá trị ISN tiếp theo.

---

### 5. BƯỚC 4: THỰC HIỆN TẤN CÔNG BẮT TAY GIẢ MẠO (SPOOFING)

Thực hiện kịch bản tấn công mạo danh nguồn và bơm dữ liệu:

```bash
# 1. [VICTIM - h2] Mở ncat ghi nhật ký dữ liệu nhận được
sudo ip netns exec h2 ncat -lvk -p 8080 > /tmp/lab01/ncat_server.log 2>&1 &

# 2. [VICTIM - h2] Bắt gói tin trên card mạng veth2
sudo ip netns exec h2 tcpdump -i veth2 -nn "tcp port 8080" > /tmp/lab01/tcpdump_h2.log 2>&1 &
sleep 1

# 3. [ATTACKER - h1] Phát động script tấn công Scapy
sudo ip netns exec h1 python3 /tmp/lab01/spoof_sniff.py
sleep 2
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `tcpdump -i veth2 -nn "tcp port 8080"`:
   - `-i veth2`: Chỉ định giao diện mạng cần bắt gói tin (`interface`).
   - `-nn`: Cờ tối quan trọng trong phân tích an toàn mạng:
     - `n` thứ nhất: Không phân giải địa chỉ IP sang tên miền máy chủ qua DNS (tránh sinh thêm lưu lượng DNS làm nhiễu log).
     - `n` thứ hai: Không phân giải số cổng sang tên dịch vụ chuẩn (ví dụ giữ nguyên `8080` thay vì hiển thị `http-alt`).
   - `"tcp port 8080"`: Bộ lọc BPF (Berkeley Packet Filter), giới hạn nhân hệ điều hành chỉ sao chép các gói tin TCP có cổng nguồn hoặc đích là 8080 lên user-space.
2. `sleep 1` & `sleep 2`:
   - Đảm bảo tiến trình `tcpdump` và `ncat` đã hoàn tất việc mở socket và lắng nghe trong kernel trước khi script tấn công gửi gói tin, đồng thời đảm bảo gói tin cuối cùng được ghi xuống đĩa trước khi đọc log.

---

### 6. BƯỚC 5: KIỂM CHỨNG KẾT QUẢ

Thực hiện kiểm tra kết quả ghi nhận tại máy nạn nhân:

```bash
# 1. [VICTIM - h2] Kiểm tra dữ liệu dịch vụ tiếp nhận
cat /tmp/lab01/ncat_server.log

# 2. [VICTIM - h2] Kiểm tra chi tiết luồng bắt tay và xác nhận trong tcpdump
cat /tmp/lab01/tcpdump_h2.log
```

#### Phân Tích Chi Tiết Nhật Ký Bắt Gói (Packet Trace Analysis):
Nhật ký thực tế từ `tcpdump_h2.log`:
```text
1. IP 10.0.0.77.41234 > 10.0.0.2.8080: Flags [S], seq 1000, win 8192, length 0
2. IP 10.0.0.2.8080 > 10.0.0.77.41234: Flags [S.], seq 3891402118, ack 1001, win 64240, length 0
3. IP 10.0.0.77.41234 > 10.0.0.2.8080: Flags [.], ack 3891402119, win 8192, length 0
4. IP 10.0.0.77.41234 > 10.0.0.2.8080: Flags [P.], seq 1001:1027, ack 3891402119, win 8192, length 26
5. IP 10.0.0.2.8080 > 10.0.0.77.41234: Flags [.], ack 1027, win 64240, length 0
```

- **Gói 1 (SYN Giả mạo):** Máy `h1` bắn gói tin có IP nguồn mạo danh `10.0.0.77`, khởi tạo cờ `Flags [S]`, số thứ tự `seq = 1000`.
- **Gói 2 (SYN-ACK):** Nạn nhân chấp nhận, sinh số ngẫu nhiên Server ISN = `3891402118`, cờ `Flags [S.]` (SYN+ACK), xác nhận `ack = 1001` ($1000 + 1$).
- **Gói 3 (ACK Hoàn tất bắt tay):** Attacker bắt được Server ISN và gửi gói xác nhận mang số `ack = 3891402119` ($3891402118 + 1$), cờ `Flags [.]` (ACK). Nạn nhân chính thức đưa kết nối vào trạng thái `ESTABLISHED`.
- **Gói 4 (PSH+ACK Bơm Tải):** Attacker gửi tải trọng `hello-from-spoofed-source\n` dài đúng 26 bytes (`length 26`), dải sequence `1001:1027`. Cờ `Flags [P.]` kích hoạt ép tầng TCP đẩy thẳng vào buffer của `ncat`.
- **Gói 5 (ACK Xác nhận dữ liệu):** Nạn nhân phản hồi gói ACK xác nhận đã nhận đủ 26 bytes dữ liệu bằng cách tăng số xác nhận lên `ack = 1027`.
- **Kết quả trên `ncat_server.log`:** Hiển thị chuỗi `hello-from-spoofed-source` với địa chỉ kết nối đến là `10.0.0.77:41234`. Cuộc tấn công thành công trọn vẹn!

---

### 7. BƯỚC 6: DỌN DẸP MÔI TRƯỜNG

Thực hiện dọn dẹp để khôi phục trạng thái nguyên bản của hệ thống:

```bash
# [HOST / CHUNG] Tắt tiến trình nền và xóa namespaces
sudo pkill -f ncat 2>/dev/null || true
sudo pkill -f tcpdump 2>/dev/null || true
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo rm -rf /tmp/lab01
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `pkill -f <tên_tiến_trình>`:
   - Gửi tín hiệu `SIGTERM` (15) tới tất cả các tiến trình có dòng lệnh (`cmdline`) khớp với chuỗi tìm kiếm. Cờ `-f` (full command line) giúp tìm kiếm cả các tiến trình chạy với tham số như `ncat -lvk`.
2. `ip netns del <tên_ns>`:
   - Xóa namespace khỏi hệ thống. Khi namespace bị xóa, Linux Kernel sẽ tự động thu hồi toàn bộ các tài nguyên liên quan, bao gồm: đóng toàn bộ socket còn mở, xóa bảng định tuyến nội bộ, và xóa vĩnh viễn cặp card mạng ảo `veth` được gắn trong namespace đó.
3. `rm -rf /tmp/lab01`:
   - Xóa bỏ thư mục tạm chứa kịch bản và các tệp nhật ký để giải phóng dung lượng đĩa và bảo vệ thông tin kiểm thử.

