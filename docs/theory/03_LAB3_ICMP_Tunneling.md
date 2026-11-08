# BÁO CÁO LÝ THUYẾT & PHÂN TÍCH CHUYÊN SÂU: LAB 03
## Kỹ Thuật Tấn Công Kênh Ngầm ICMP Tunneling (Covert Channel & Data Exfiltration)

---

### 1. Mục Tiêu & Chuẩn RFC Liên Quan

#### 1.1 Mục Tiêu Bài Học (Trích xuất từ tài liệu đề bài)
- Nắm vững nguyên lý và phương pháp chèn (nhồi) dữ liệu tùy ý vào trường tải trọng (Data Payload) của các gói tin ICMP Echo Request (Type 8) và Echo Reply (Type 0) nhằm thiết lập một kênh truyền thông bí mật (Covert Channel).
- Tự tay phát triển chương trình máy khách (Client) và máy chủ (Server) phục vụ ICMP Tunneling bằng thư viện Scapy để thực hiện hành vi rò rỉ dữ liệu (Data Exfiltration).
- Kiểm chứng thực nghiệm khả năng xuyên thủng tường lửa: Kênh ngầm ICMP hoạt động trơn tru ngay cả khi chính sách an ninh mạng đã khóa hoàn toàn tất cả các cổng giao vận TCP/UDP.
- Nhận diện các đặc trưng mạng bất thường và xây dựng phương thức giám sát, phát hiện lưu lượng ICMP độc hại.

#### 1.2 Các Chuẩn RFC và Tài Liệu Học Thuật Tham Chiếu
- **RFC 792 (Internet Control Message Protocol - 1981):** Tiêu chuẩn cốt lõi quy định cấu trúc gói ICMP. Tiêu chuẩn này quy định trường dữ liệu (Data Field) của gói Echo/Echo Reply có độ dài linh hoạt và nội dung dữ liệu nhận được trong Echo Request bắt buộc phải được trả về nguyên vẹn trong Echo Reply.
- **Dự án Loki (Loki2 / Phrack Magazine #49 năm 1996 & #51 năm 1997):** Chuyên khảo nổi tiếng của Daemon9 mô tả kỹ thuật sử dụng ICMP để qua mặt các hệ thống tường lửa thế hệ đầu, khởi nguyên cho khái niệm "ICMP Covert Channel".
- **Các công cụ triển khai thực tế:** `ptunnel` (Ping Tunnel), `icmptunnel`, `Hans` — những công cụ cho phép đóng gói toàn bộ luồng lưu lượng IP hoặc TCP/SSH qua các gói tin ICMP Echo.

---

### 2. Nguyên Lý Tấn Công & Điểm Yếu Giao Thức

#### 2.1 Bản Chất Của Giao Thức ICMP Echo
Theo RFC 792, mục đích ban đầu của cặp thông điệp ICMP Echo Request / Echo Reply là kiểm tra khả năng tiếp cận (reachability) và đo độ trễ (RTT) giữa hai nút mạng:
- **Cấu trúc gói tin:**
  - `Type (8 bit)`: Type 8 (Request), Type 0 (Reply).
  - `Code (8 bit)`: Thường là 0 đối với Echo.
  - `Checksum (16 bit)`: Kiểm tra tính toàn vẹn của tiêu đề và dữ liệu ICMP.
  - `Identifier (16 bit)` & `Sequence Number (16 bit)`: Phục vụ ghép cặp giữa yêu cầu và phản hồi.
  - `Data Payload (Độ dài tùy ý)`: Chuẩn RFC không giới hạn nội dung payload và quy định máy nhận phải gửi lại nguyên xi payload đó.
- **Lỗ hổng khái niệm (Architectural Weakness):** RFC không có bất kỳ cơ chế kiểm tra tính hợp lệ về mặt ngữ nghĩa (semantic validation) đối với payload. Các hệ điều hành thường điền các chuỗi ký tự mặc định (như bảng chữ cái `abcdef...` trên Windows hoặc timestamp trên Linux). Kẻ tấn công có thể thay thế toàn bộ chuỗi đệm này bằng tài liệu mật, thông tin định danh hoặc mã lệnh shell.

#### 2.2 Cơ Chế Tạo Kênh Ngầm & Vượt Tường Lửa Tầng 4
- **Tại sao vượt qua tường lửa:**
  Hầu hết các bộ định tuyến và tường lửa mạng tầng 4 (Stateful Packet Inspection - L4 Firewall) lọc gói tin dựa trên bộ thông số: `IP nguồn, IP đích, Giao thức (TCP/UDP), Cổng nguồn, Cổng đích`.
  - ICMP hoạt động ở tầng Network (cùng tầng với IP, không có khái niệm Port như TCP/UDP).
  - Quản trị viên mạng thường mở cho phép lệnh `ping` (ICMP Type 8) ra ngoài Internet để phục vụ chẩn đoán sự cố mạng của nhân viên.
  - Tường lửa chặn cổng TCP (ví dụ chặn port 22, 80, 443, 9000) nhưng cho phép ICMP đi qua. Kẻ tấn công đóng gói dữ liệu cần đánh cắp vào payload của gói ping, biến ICMP thành giao thức mang tin (carrier protocol) để đưa dữ liệu trót lọt ra ngoài Internet.
- **Kênh truyền thông 2 chiều (Bidirectional Channel):**
  - Chiều đi (Outbound / Exfiltration): Client gửi ICMP Echo Request chứa dữ liệu đánh cắp trong payload.
  - Chiều về (Inbound / C2 Commands): Server phản hồi ICMP Echo Reply chứa mệnh lệnh thực thi tiếp theo cho mã độc.

#### 2.3 Phân Tích Kỹ Thuật (Senior Protocol Researcher Perspective)
Tại sao cần tắt tính năng kernel auto-reply trên Server bằng lệnh:
```bash
sysctl -w net.ipv4.icmp_echo_ignore_all=1
```
- Khi một máy Linux nhận được gói ICMP Echo Request, theo mặc định mã kernel trong hệ điều hành sẽ tự động tạo và gửi ngay một gói ICMP Echo Reply tương ứng về người gửi.
- Nếu kịch bản Scapy server (`icmp_server.py`) của kẻ tấn công đang chạy ở tầng user-space cũng lắng nghe và gửi gói Reply chứa thông điệp ACK/Command, client sẽ nhận được **hai** phản hồi: một từ kernel (chứa payload nguyên bản) và một từ Scapy server (chứa ACK payload).
- Việc tắt auto-reply của kernel giúp ứng dụng tấn công chiếm quyền độc quyền kiểm soát hoàn toàn kênh ICMP.

---

### 3. Cơ Chế Phòng Thủ (Mitigation)

#### 3.1 Kiểm Soát Biên Mạng (Edge Egress Filtering)
- **Hạn chế tối đa ICMP ra ngoài Internet:** Trong môi trường mạng nội bộ doanh nghiệp có độ nhạy cảm cao, áp dụng chính sách Default-Deny đối với lưu lượng ICMP đi ra Internet (Egress Drop). Việc chẩn đoán mạng có thể giới hạn trên các cổng quản trị chuyên dụng hoặc thông qua proxy.
- **Giới hạn tỷ lệ (Rate Limiting):** Sử dụng iptables hoặc router để bóp băng thông ICMP nhằm ngăn chặn việc truyền tải các file kích thước lớn:
  ```bash
  iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT
  iptables -A FORWARD -p icmp --icmp-type echo-request -j DROP
  ```

#### 3.2 Phát Hiện Bằng Hệ Thống Giám Sát Xâm Nhập (IDS/IPS - Snort/Suricata)
Cấu hình các signature kiểm tra dị thường gói tin ICMP:
1. **Kiểm tra độ dài payload (Length Anomalies):**
   Gói ping hợp lệ của Linux tiêu chuẩn có payload 56 bytes (tổng gói IP = 84 bytes), Windows có payload 32 bytes (tổng gói IP = 60 bytes). Các gói ICMP có độ dài bất thường (vài trăm byte hoặc nhiều kilobyte) phải kích hoạt cảnh báo:
   ```text
   alert icmp any any -> any any (msg:"ICMP Large Payload Tunnel Detected"; dsize:>100; sid:1000001; rev:1;)
   ```
2. **Kiểm tra nội dung mẫu (Pattern & Signature Matching):**
   Kiểm tra payload xem có chứa các định dạng nhị phân, header file bí mật (như `PK`, `MZ`, `ELF`, chuỗi ASCII văn bản) hoặc các chữ ký của công cụ đường hầm thông dụng (`ptunnel`, `icmptunnel`).

#### 3.3 Phân Tích Dị Thường Thống Kê & Entropy (Statistical & Entropy Analysis)
- **Phân tích Entropy:** Dữ liệu thông thường (như bảng chữ cái ping chuẩn) có độ hỗn loạn (entropy) rất thấp. Nếu dữ liệu trong payload bị mã hóa hoặc nén để giấu nội dung, độ hỗn loạn thông tin sẽ xấp xỉ mức tối đa ($\approx 8\text{ bits/byte}$). Hệ thống phân tích lưu lượng (Network Traffic Analysis - NTA) dựa vào sự gia tăng đột biến của entropy trên giao thức ICMP để cô lập host nghi vấn.
- **Tỉ lệ Request/Reply bất đối xứng (Ratio Mismatch):** Nếu xuất hiện lưu lượng Echo Request gửi đi ồ ạt liên tục nhưng tỷ lệ phản hồi thấp hoặc kích thước payload giữa hai chiều có sự chênh lệch bất thường.
- **Phân tích Hành Vi Người Dùng & Thực Thể (UEBA):** Cảnh báo khi một máy trạm nội bộ gửi lưu lượng ping liên tục nhiều giờ liền tới một địa chỉ IP công cộng không xác định ở nước ngoài.

---

### 4. Giải Đáp Chi Tiết Câu Hỏi Ôn Tập (Review Questions)

#### Câu 1: Vì sao payload ICMP lại là nơi lý tưởng để giấu dữ liệu? Ping hợp lệ thường có payload bao nhiêu byte?
- **Vì sao là nơi lý tưởng để giấu dữ liệu:**
  - Chuẩn RFC 792 không bắt buộc bất kỳ định dạng cố định nào cho phần dữ liệu đi kèm sau ICMP Header.
  - Mục đích giao thức yêu cầu máy nhận phải giữ nguyên vẹn dữ liệu trong gói trả về, tạo thành một kênh truyền tin tự nhiên và hoàn chỉnh cả hai chiều (Half-duplex / Full-duplex).
  - Lưu lượng ICMP ping thường được các nhà quản trị mạng coi là lưu lượng "vô hại", phục vụ chẩn đoán hạ tầng, nên ít khi bị áp dụng các cơ chế Deep Packet Inspection (DPI) khắt khe như HTTP/HTTPS.
- **Kích thước payload của ping hợp lệ:**
  - Trên hệ điều hành **Linux / Unix**: Lệnh ping mặc định gửi **56 bytes** payload dữ liệu (cộng 8 bytes ICMP header và 20 bytes IP header $\rightarrow$ tổng cộng gói tin IP là **84 bytes**).
  - Trên hệ điều hành **Windows**: Lệnh ping mặc định gửi **32 bytes** payload dữ liệu (chứa chuỗi ký tự cố định `abcdefghijklmnopqrstuvwabcdefghi`, tổng cộng gói tin IP là **60 bytes**).

#### Câu 2: Trong Bước 2.4, tại sao tường lửa lọc theo cổng (port) không chặn được tunnel? Cần bổ sung biện pháp gì?
- **Tại sao tường lửa theo cổng không chặn được:**
  - Tường lửa lọc theo cổng hoạt động ở Tầng Giao Vận (Layer 4 - Transport Layer), sử dụng thông tin trong TCP Header hoặc UDP Header (cụ thể là `Source Port` và `Destination Port`) để quyết định cho phép (`ACCEPT`) hay từ chối (`DROP`).
  - Giao thức ICMP là giao thức hỗ trợ hoạt động ở Tầng Mạng (Layer 3 - Network Layer), được đóng gói trực tiếp vào IPv4 với trường Protocol bằng $1$. ICMP hoàn toàn **không có khái niệm Port**.
  - Quy tắc tường lửa `iptables -A INPUT -p tcp -j DROP` chỉ so khớp các gói tin có IP Protocol = 6 (TCP), do đó mọi gói tin ICMP (Protocol = 1) đều không bị khớp luật này và được phép đi qua bình thường.
- **Các biện pháp bổ sung cần thiết:**
  - Bổ sung quy tắc lọc tại Tầng Mạng: Chặn toàn bộ hoặc giới hạn nghiêm ngặt lưu lượng ICMP từ các máy trạm đi ra ngoài Internet.
  - Sử dụng Tường lửa thế hệ mới (Next-Generation Firewall - NGFW) và hệ thống IPS/DPI có khả năng kiểm tra sâu nội dung payload của gói ICMP thay vì chỉ nhìn vào header cổng.
  - Áp dụng các chính sách giới hạn băng thông và số lượng gói ICMP trên mỗi giây (Rate Limiting).

#### Câu 3: Liệt kê 3 đặc trưng giúp IDS phát hiện ICMP tunnel.
1. **Dị thường về kích thước và định dạng Payload (Payload Size & Pattern Anomaly):** Kích thước payload liên tục biến động hoặc vượt xa kích thước chuẩn (ví dụ $> 64$ bytes), hoặc payload chứa chuỗi ký tự ASCII có thể đọc được (như nội dung file văn bản, token bí mật) thay vì chuỗi nhị phân đệm tiêu chuẩn của hệ điều hành.
2. **Tần suất và mật độ gói tin cao bất thường (Abnormal Packet Frequency & Volume):** Các phiên ping thông thường chỉ gửi 1 gói/giây trong thời gian ngắn (khoảng 4 đến 5 gói). Khi thực hiện truyền file hoặc duy trì kênh C2 qua ICMP tunnel, các gói tin được gửi liên tục với tốc độ cao, kéo dài liên tục nhiều giờ liền và tổng dung lượng truyền tải lên tới nhiều Megabytes.
3. **Chỉ số Entropy của Payload cao (High Payload Entropy):** Dữ liệu truyền trong tunnel (đặc biệt khi được mã hóa AES hoặc nén zip/gzip) có độ ngẫu nhiên thông tin cực cao (tiệm cận 8.0), khác biệt hoàn toàn với payload lặp đi lặp lại có entropy rất thấp của lệnh ping tiêu chuẩn.

#### Câu 4: Nếu dữ liệu được mã hóa trước khi nhồi vào ICMP, những phương pháp phát hiện nào vẫn còn hiệu lực?
Khi kẻ tấn công mã hóa dữ liệu (ví dụ dùng AES hoặc ChaCha20), các phương pháp so khớp chuỗi văn bản (Pattern Matching / Signature-based) sẽ mất tác dụng. Tuy nhiên, các phương pháp phân tích nâng cao sau đây **vẫn còn nguyên hiệu lực**:
1. **Phân tích Entropy (Shannon Entropy Analysis):** Mã hóa làm cho dữ liệu có tính chất ngẫu nhiên đồng đều. Trình phát hiện dị thường chỉ cần tính toán entropy của payload ICMP; nếu giá trị đạt từ 7.5 đến 8.0 bits/byte thì độ tin cậy kết luận đây là kênh truyền ngầm mã hóa là cực kỳ cao.
2. **Phân tích Thống kê Kích thước & Lưu lượng (Flow Volume & Packet Sizing):** Việc gửi đi khối lượng byte lớn bất thường qua ICMP và các gói tin liên tục có kích thước MTU tối đa (ví dụ 1000 - 1500 bytes) là dấu hiệu không thể che giấu được dù dữ liệu bên trong có mã hóa hay không.
3. **Phân tích Hành vi & Tương quan Mạng (Network Behavioral Analysis & Beaconing Detection):** Các kênh C2 mã hóa thường có đặc trưng phát tín hiệu định kỳ (Beaconing) theo chu kỳ thời gian nhất định (khoảng cách giữa các gói tin có độ lệch thời gian nhỏ) để duy trì kết nối với máy chủ điều khiển. Hệ thống AI/ML và UEBA dễ dàng phát hiện mô hình truyền thông tuần hoàn này.

