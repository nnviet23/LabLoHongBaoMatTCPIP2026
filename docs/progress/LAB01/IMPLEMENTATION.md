# HƯỚNG DẪN TRIỂN KHAI & PHÂN TÍCH KỸ THUẬT: LAB 01
## Phân Tích Cơ Chế TCP Initial Sequence Number (ISN) & Blind Spoofing

---

### 1. Kiến Trúc Mạng & Mục Đích Từng Câu Lệnh Cấu Hình

Topology được xây dựng gồm hai máy ảo cô lập bằng Linux Network Namespaces (`h1` - Attacker, `h2` - Victim) kết nối qua cặp card mạng ảo `veth1` $\leftrightarrow$ `veth2`.

```
[ Namespace h1 (Attacker) ]                     [ Namespace h2 (Victim) ]
+------------------------+                     +------------------------+
| IP: 10.0.0.1/24        |                     | IP: 10.0.0.2/24        |
| Interface: veth1       | <=== (veth link) => | Interface: veth2       |
| iptables DROP RST      |                     | Listen: TCP Port 9000  |
+------------------------+                     +------------------------+
```

#### Phân Tích Lệnh Cấu Hình Trong `setup_pair.sh`:
- `ip netns add h1` & `ip netns add h2`: Khởi tạo hai không gian mạng cô lập, mỗi namespace sở hữu bảng định tuyến, bảng socket và cấu hình firewall riêng biệt.
- `ip link add veth1 type veth peer name veth2`: Tạo một cặp Virtual Ethernet (veth pair) đóng vai trò như một sợi cáp mạng ảo nối trực tiếp hai máy.
- `ip link set veth1 netns h1` & `ip link set veth2 netns h2`: Gắn mỗi đầu cáp vào một namespace tương ứng.
- `ip netns exec h1 ip addr add 10.0.0.1/24 dev veth1`: Gán địa chỉ IP cho giao diện mạng của máy Attacker.
- `ip netns exec h2 ip addr add 10.0.0.2/24 dev veth2`: Gán địa chỉ IP cho giao diện mạng của máy Victim.
- `iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP` (trên `h1`): **Đây là bước cấu hình then chốt:**
  - *Tại sao phải chặn gói RST của kernel?* Khi Scapy (chạy ở tầng người dùng - user space) tự gửi gói tin TCP SYN bằng raw socket, kernel của Linux ở máy gửi không lưu trữ thông tin socket này trong bảng TCB (Transmission Control Block).
  - Khi Victim gửi phản hồi SYN/ACK về máy gửi, kernel của máy gửi nhận thấy gói tin phản hồi cho một socket không hề tồn tại trong quản lý của nó. Theo chuẩn RFC 793, kernel sẽ tự động sinh ngay một gói `TCP RST` (Reset) gửi ngược lại Victim để hủy kết nối.
  - Gói RST tự động này sẽ lập tức đóng phiên kết nối trước khi kịch bản Scapy kịp gửi gói ACK thứ 3. Do đó, quy tắc `iptables DROP RST` là điều kiện bắt buộc để Scapy toàn quyền điều khiển tiến trình bắt tay.
- `ip netns exec h2 ip neigh replace 10.0.0.77 lladdr "$VETH1_MAC" dev veth2`:
  - Trong kịch bản tấn công trên phân đoạn mạng LAN cục bộ, khi máy Victim nhận gói tin mang IP nguồn giả mạo `10.0.0.77`, nó cần gửi phản hồi SYN/ACK về IP đó.
  - Vì `10.0.0.77` nằm trong cùng dải mạng `10.0.0.0/24`, kernel Victim sẽ gửi yêu cầu ARP Request hỏi địa chỉ MAC của `10.0.0.77`.
  - Cấu hình neighbor tĩnh này mô phỏng điều kiện môi trường thực tế nơi Attacker nằm cùng broadcast domain và thực hiện bắt gói on-path, chuyển tiếp gói tin về đúng giao diện `veth1` để Scapy thu thập.

---

### 2. Ý Nghĩa Kỹ Thuật Các Tham Số Trong Script Scapy

#### 2.1 Trong `isn_sampler.py` (Lấy mẫu & Đánh giá ISN)
- `sport = int(RandShort())`: Sinh cổng nguồn ngẫu nhiên (16-bit) cho mỗi lần thử. Điều này đảm bảo mỗi lần gửi SYN đều tạo thành một bộ tứ kết nối (Socket Quadruple: `src_ip, sport, dst_ip, dport`) hoàn toàn mới, kích hoạt hàm băm sinh ISN của server.
- `syn = IP(src=src_ip, dst=target_ip)/TCP(sport=sport, dport=target_port, flags="S", seq=1000)`:
  - `flags="S"`: Thiết lập cờ SYN để khởi tạo phiên TCP mới.
  - `seq=1000`: Giá trị sequence number ban đầu của client.
- `ans = sr1(syn, timeout=1, verbose=0)`:
  - Hàm `sr1` (Send and Receive 1 packet): Gửi gói tin ở Layer 3 và chỉ chờ nhận 1 gói tin phản hồi đầu tiên.
  - `timeout=1`: Giới hạn thời gian chờ tối đa 1 giây để tránh tắc nghẽn script nếu gói tin bị drop.
- `(ans[TCP].flags & 0x12) == 0x12`: Kiểm tra xem gói phản hồi có chứa đồng thời cả hai cờ `SYN` (`0x02`) và `ACK` (`0x10`) hay không ($0x02 | 0x10 = 0x12$).
- `send(IP(...)/TCP(..., flags="R", seq=1001), verbose=0)`:
  - Gửi gói RST để đóng kết nối ngay lập tức sau khi lấy được ISN, giúp giải phóng socket trên server, tránh làm đầy hàng đợi SYN backlog của victim.
- `diff = b - a`: Tính độ biến thiên giữa hai ISN liên tiếp. Trên các hệ điều hành tuân thủ RFC 6528, giá trị này dao động ngẫu nhiên qua toàn bộ không gian số nguyên 32-bit.

#### 2.2 Trong `spoof_sniff.py` (Bắt tay giả mạo & Chèn Payload)
- `sport = int(RandShort())`: Sử dụng cổng nguồn ngẫu nhiên tránh rơi vào trạng thái `TIME_WAIT` của socket cũ.
- `send(IP(src=spoof, dst=victim)/TCP(sport=sport, dport=dport, flags="S", seq=1000))`:
  - Gửi gói SYN với `src="10.0.0.77"` (địa chỉ IP hoàn toàn bị giả mạo).
- `sa = sniff(iface="veth1", timeout=3, count=1, lfilter=lambda p: ...)`:
  - Lắng nghe thụ động trên giao diện `veth1`.
  - Bộ lọc `lfilter`: Chỉ bắt các gói tin TCP có cổng đích trùng với `sport` của phiên và mang cờ `SYN+ACK`.
- `isn = sa[0][TCP].seq`: Trích xuất số thứ tự ban đầu thực tế (ISN) của Server.
- `send(IP(src=spoof, dst=victim)/TCP(..., flags="A", seq=1001, ack=isn + 1))`:
  - **Gói ACK hoàn tất bắt tay:** Đặt `ack = isn + 1`. Đây là điều kiện tiên quyết mà máy chủ kiểm tra để chuyển trạng thái từ `SYN_RECEIVED` sang `ESTABLISHED`.
- `send(IP(src=spoof, dst=victim)/TCP(..., flags="PA", seq=1001, ack=isn + 1)/b"hello-from-spoofed-source\n")`:
  - `flags="PA"`: Bật đồng thời cờ `PSH` (Push) và `ACK` để yêu cầu tầng TCP của máy chủ đẩy ngay dữ liệu lên ứng dụng mà không cần chờ đầy bộ đệm.
  - Payload dữ liệu: Chuỗi byte `hello-from-spoofed-source\n`.

---

### 3. Phân Tích Tiến Trình Bắt Gói Tại Nạn Nhân (tcpdump Verification)

Dòng log bắt gói thực tế tại nạn nhân (`h2`):

```text
1. 23:56:50.291658 IP 10.0.0.77.62678 > 10.0.0.2.9000: Flags [S], seq 1000
2. 23:56:50.291688 IP 10.0.0.2.9000 > 10.0.0.77.62678: Flags [S.], seq 3626173042, ack 1001
3. 23:56:51.341853 IP 10.0.0.77.62678 > 10.0.0.2.9000: Flags [.], ack 1
4. 23:56:51.385155 IP 10.0.0.77.62678 > 10.0.0.2.9000: Flags [P.], seq 1:27, ack 1, length 26: hello-from-spoofed-source
5. 23:56:51.385416 IP 10.0.0.2.9000 > 10.0.0.77.62678: Flags [.], ack 27
```

**Nhận xét quy trình:**
1. **Gói 1:** Nạn nhân nhận yêu cầu kết nối từ IP giả mạo `10.0.0.77`.
2. **Gói 2:** Nạn nhân đồng ý và sinh ISN là `3626173042` (`0xd8230272`), phản hồi lại địa chỉ `10.0.0.77`.
3. **Gói 3:** Attacker gửi gói ACK với số thứ tự xác nhận đúng bằng `ISN + 1`. Nạn nhân coi như phiên bắt tay đã hoàn tất thành công.
4. **Gói 4:** Attacker gửi dữ liệu dưới danh nghĩa `10.0.0.77`.
5. **Gói 5:** Nạn nhân xác nhận đã tiếp nhận toàn bộ 26 bytes dữ liệu (`ack 27`). Phiên truyền dữ liệu giả mạo thành công hoàn hảo.

---

### 4. Kết Luận Phòng Thủ & Khuyến Nghị

1. **Ngẫu nhiên hóa ISN bằng Mật mã (RFC 6528):**
   - Nhân Linux hiện đại đã triệt tiêu hoàn toàn khả năng đoán ISN của kẻ tấn công ngoài luồng (Off-path Blind Attacker). Mọi hệ điều hành cần đảm bảo sử dụng hàm băm mật mã với khóa bí mật định kỳ để sinh ISN.
2. **Chặn Giả Mạo Nguồn Tại Biên Mạng (BCP 38 / RFC 2827):**
   - Cuộc tấn công chỉ có thể khởi phát nếu kẻ tấn công gửi được các gói tin mang địa chỉ IP nguồn không thuộc dải IP của mình. Triển khai Ingress Filtering tại các bộ định tuyến biên là phòng tuyến vật lý hữu hiệu nhất.
3. **Mã Hóa & Xác Thực Tầng Ứng Dụng (End-to-End Encryption):**
   - Thí nghiệm đã chứng minh: **Tầng TCP thuần túy không có khả năng tự bảo vệ trước việc mạo danh IP nếu kẻ tấn công nằm trên đường truyền (On-path Sniffer).**
   - Mọi dịch vụ mạng nhạy cảm bắt buộc phải triển khai mã hóa và xác thực chữ ký số tầng trên (TLS 1.3, SSHv2, IPsec). Khi đó, dù kẻ tấn công có hoàn tất bắt tay TCP 3 bước giả mạo, chúng cũng không thể vượt qua bước trao đổi khóa mật mã.

