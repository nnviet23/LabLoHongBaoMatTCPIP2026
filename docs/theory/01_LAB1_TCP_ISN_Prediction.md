# BÁO CÁO LÝ THUYẾT & PHÂN TÍCH CHUYÊN SÂU: LAB 01
## Kỹ Thuật Tấn Công Dự Đoán TCP Sequence Number (TCP ISN Prediction & Blind Spoofing)

---

### 1. Mục Tiêu & Chuẩn RFC Liên Quan

#### 1.1 Mục Tiêu Bài Học (Trích xuất từ tài liệu đề bài)
- Hiểu rõ vai trò của trường Sequence Number (SEQ) và Acknowledgment Number (ACK) trong quá trình thiết lập phiên truyền thông TCP 3 bước (3-way handshake).
- Nắm bắt cơ chế và lý do vì sao giá trị Initial Sequence Number (ISN) có thể đoán trước (predictable) lại mở đường cho kỹ thuật tấn công mạo danh mù (Blind IP Spoofing) và chiếm đoạt phiên (TCP Session Hijacking).
- Tiến hành thu thập mẫu và phân tích chuỗi ISN trên hệ điều hành Linux hiện đại để chứng minh tính ngẫu nhiên hóa mật mã.
- Sử dụng Scapy để mô phỏng hoàn tất quá trình bắt tay TCP 3 bước với địa chỉ IP nguồn bị giả mạo.

#### 1.2 Các Chuẩn RFC và Tài Liệu Học Thuật Tham Chiếu
- **RFC 793 (Transmission Control Protocol - 1981):** Tiêu chuẩn nền tảng xác định cấu trúc TCP header, cơ chế bắt tay 3 bước và quy tắc quản lý Sequence Number. Ban đầu RFC 793 đề xuất ISN dựa trên bộ đếm thời gian (clock-driven), tăng 1 đơn vị mỗi 4 micro giây.
- **RFC 1948 (Defending Against Sequence Number Attacks - Bellovin, 1996):** Đề xuất giải pháp bảo mật đầu tiên sử dụng hàm băm mật mã (MD5) kết hợp khóa bí mật ngẫu nhiên của kernel để sinh ISN duy nhất cho mỗi socket pair.
- **RFC 6528 (Defending Against Sequence Number Attacks - 2012, thay thế RFC 1948):** Chuẩn hóa thuật toán sinh ISN hiện đại:
  $$\text{ISN} = M + F(\text{LocalIP}, \text{LocalPort}, \text{RemoteIP}, \text{RemotePort}, \text{SecretKey})$$
  Trong đó $M$ là bộ đếm tăng đơn điệu theo thời gian thực và $F$ là hàm băm một chiều an toàn mật mã (SipHash/MD5).
- **Robert Morris (1985):** *"A Weakness in the 4.2BSD Unix TCP/IP Software"* — bài báo kinh điển vạch trần điểm yếu ISN tăng tuyến tính.
- **Kevin Mitnick & Tsutomu Shimomura (1994):** Cuộc tấn công nổi tiếng lịch sử khai thác dự đoán ISN để vượt qua cơ chế xác thực rsh/rlogin dựa trên địa chỉ IP tin cậy.

---

### 2. Nguyên Lý Tấn Công & Điểm Yếu Giao Thức

#### 2.1 Điểm Yếu Cốt Lõi Của Giao Thức TCP Truyền Thống
Giao thức TCP được thiết kế với mục tiêu bảo đảm độ tin cậy của luồng dữ liệu (reliability) chứ không tích hợp sẵn tính toàn vẹn hoặc xác thực nguồn gốc mật mã tại tầng giao vận.
- **Cơ chế bắt tay 3 bước (3-Way Handshake):**
  1. Client $\rightarrow$ Server: `SYN (seq = client_isn)`
  2. Server $\rightarrow$ Client: `SYN+ACK (seq = server_isn, ack = client_isn + 1)`
  3. Client $\rightarrow$ Server: `ACK (seq = client_isn + 1, ack = server_isn + 1)`
- **Điểm nghẽn xác thực:** Server tin tưởng tuyệt đối rằng host nào gửi lại gói `ACK` mang đúng giá trị `ack = server_isn + 1` chính là chủ sở hữu hợp pháp của địa chỉ IP nguồn trong gói `SYN` ban đầu.

#### 2.2 Tấn Công Off-Path Blind Spoofing Diễn Ra Như Thế Nào?
Kẻ tấn công "ngoài luồng" (off-path attacker) không nằm trên tuyến định tuyến trung gian, do đó không thể bắt lén (sniff) được gói `SYN+ACK` mà nạn nhân (server) gửi về địa chỉ IP bị mạo danh.
- **Nếu ISN có thể đoán trước (như trong các stack mạng cũ):**
  1. Attacker gửi gói `SYN` mang IP nguồn giả mạo $IP_{\text{trusted}}$ tới Server.
  2. Server gửi `SYN+ACK` về $IP_{\text{trusted}}$ (attacker hoàn toàn mù, không nhận được).
  3. Attacker dựa vào thuật toán hoặc thời gian để đoán chính xác giá trị `server_isn`.
  4. Attacker gửi gói `ACK` thứ 3 với `ack = predicted_isn + 1` và IP nguồn $IP_{\text{trusted}}$.
  5. Server chấp nhận bắt tay thành công và chuyển trạng thái kết nối sang `ESTABLISHED`.
  6. Attacker tiếp tục gửi gói `PSH+ACK` chứa lệnh thực thi nguy hiểm (ví dụ chèn lệnh vào rlogin, echo ssh key vào `authorized_keys`).

#### 2.3 Phân Tích Kỹ Thuật (Senior Protocol Researcher Perspective)
Tại sao trong bài thực hành môi trường namespace cục bộ lại thực hiện on-path sniffing?
- Trong thực tế hiện đại, việc đoán ISN trên Linux là bất khả thi do RFC 6528. Do đó, Lab 01 chia làm hai phần minh chứng rõ ràng:
  1. *Phần 1 (Đo lường & Phân tích):* Gửi 30 gói `SYN` liên tiếp và tính toán delta giữa các ISN trả về. Kết quả cho thấy khoảng cách giữa các số $2^{32}$ biến thiên giả ngẫu nhiên cực lớn, không có quy luật cố định $+C$.
  2. *Phần 2 (Mô phỏng bắt tay giả mạo):* Để chứng minh cơ chế TCP chấp nhận kết nối giả mạo nguồn một khi có được ISN, kịch bản dùng Scapy lắng nghe gói `SYN+ACK` trên giao diện veth1 (on-path capture), trích xuất ISN thực tế và gửi gói `ACK` + `Data` hoàn tất phiên. Điều này chứng minh rằng: **Nếu không có mã hóa/xác thực tầng trên, bảo mật TCP hoàn toàn phụ thuộc vào việc kẻ tấn công có biết được ISN hay không.**

---

### 3. Cơ Chế Phòng Thủ (Mitigation)

#### 3.1 Ngẫu Nhiên Hóa ISN Bằng Mật Mã (RFC 6528)
- Nhân Linux và Windows hiện đại sử dụng hàm băm giả ngẫu nhiên an toàn kết hợp khóa bí mật sinh ra tại thời điểm boot hệ thống (`random_secret_seed`). Khóa này được làm mới định kỳ.
- Kẻ tấn công off-path dù gửi hàng triệu gói thăm dò cũng không thể tái dựng được hàm băm nội bộ hay suy đoán ISN cho một socket pair cụ thể.

#### 3.2 Lọc Gói Tin Tại Biên Mạng (BCP 38 / RFC 2827 - Ingress & Egress Filtering)
- Tấn công Blind Spoofing bắt buộc kẻ tấn công phải phát các gói tin mang địa chỉ IP nguồn không thuộc dải mạng mình quản lý.
- Router và tường lửa biên phải kích hoạt bộ lọc Egress/Ingress Filtering: loại bỏ ngay lập tức bất kỳ gói tin nào đi ra khỏi mạng nội bộ nếu IP nguồn không nằm trong subnet hợp lệ được cấp phát của mạng đó.

#### 3.3 Thiết Lập Kernel Sysctl & Tường Lửa Cục Bộ
- **Chặn RST không mong muốn khi kiểm thử Scapy:**
  ```bash
  iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
  ```
  *Ý nghĩa:* Khi Scapy gửi gói SYN từ user-space, kernel của máy gửi không lưu trữ TCB (Transmission Control Block) trong bảng socket. Khi Server phản hồi SYN/ACK, kernel của máy gửi sẽ coi đây là gói tin bất thường của một kết nối không tồn tại và lập tức tự động bắn lại gói TCP RST để hủy kết nối. Việc dùng `iptables` chặn RST giúp Scapy duy trì quyền kiểm soát toàn diện đối với kết nối.
- **Kích hoạt TCP SYN Cookies (`net.ipv4.tcp_syncookies = 1`):** Ngăn chặn cạn kiệt hàng đợi SYN khi bị tấn công làm ngập kết nối giả mạo.
- **TCP Timestamps (`net.ipv4.tcp_timestamps = 1` - RFC 7323):** Thêm trường giá trị thời gian giúp loại bỏ các gói tin trễ hoặc gói giả mạo không khớp phạm vi PAWS (Protection Against Wrapped Sequence Numbers).

#### 3.4 Bảo Mật Tầng Ứng Dụng (Application Layer Security)
- Loại bỏ tuyệt đối các giao thức tin cậy dựa trên địa chỉ IP thuần túy (như R-services: `rsh`, `rlogin`, `rcp`).
- Sử dụng các giao thức mã hóa và xác thực 2 chiều ở tầng ứng dụng hoặc tầng transport như TLS 1.3, SSHv2, IPsec. Cho dù attacker có bắt tay TCP giả mạo thành công, họ vẫn không thể vượt qua bước trao đổi khóa mã hóa mật mã (Cryptographic Handshake).

---

### 4. Giải Đáp Chi Tiết Câu Hỏi Ôn Tập (Review Questions)

#### Câu 1: Giải thích vai trò của SEQ và ACK trong bắt tay 3 bước. Vì sao bên tấn công off-path phải đoán đúng ISN?
- **Vai trò của SEQ và ACK:**
  - `Sequence Number (SEQ)` định danh vị trí byte dữ liệu đầu tiên trong dòng truyền thông TCP và bảo đảm việc tái sắp xếp dữ liệu đúng thứ tự tại phía nhận.
  - `Acknowledgment Number (ACK)` mang ý nghĩa báo cho đối phương biết số thứ tự của byte tiếp theo mà bên nhận đang kỳ vọng.
  - Trong quá trình bắt tay: Gói `SYN` khởi tạo ISN của bên gửi; gói `SYN+ACK` phản hồi `ACK = Client_ISN + 1` và khởi tạo `Server_ISN`; gói `ACK` cuối cùng xác nhận `ACK = Server_ISN + 1`.
- **Vì sao attacker off-path phải đoán đúng ISN:**
  - Vì kẻ tấn công nằm ngoài luồng truyền tải dữ liệu (off-path), gói `SYN+ACK` do máy chủ gửi về địa chỉ nguồn bị mạo danh sẽ không đi qua attacker. Attacker bị "mù" thông tin `Server_ISN`.
  - Muốn máy chủ chấp nhận gói `ACK` thứ 3 để chuyển kết nối sang trạng thái `ESTABLISHED` và chấp nhận dữ liệu (payload), trường `ACK Number` của attacker gửi đi bắt buộc phải khớp chính xác với `Server_ISN + 1`. Nếu sai lệch dù chỉ 1 đơn vị, máy chủ sẽ loại bỏ gói hoặc phản hồi gói RST hủy kết nối.

#### Câu 2: Từ dữ liệu ở Bước 2.2, cho biết các ISN có theo quy luật không? Giá trị chênh lệch nói lên điều gì về cơ chế sinh ISN?
- **Quy luật:** Các giá trị ISN thu được phân bố rải rác trên toàn bộ không gian số nguyên 32-bit ($0 \rightarrow 2^{32}-1$). Không tồn tại bất kỳ chuỗi tăng tuần tự hay quy luật chu kỳ nào.
- **Ý nghĩa giá trị chênh lệch (Delta):**
  - Giá trị hiệu số giữa hai lần lấy mẫu liên tiếp ($\Delta = \text{ISN}_{k+1} - \text{ISN}_k$) có độ lớn ngẫu nhiên cực đại (hàng triệu, hàng tỷ đơn vị), mang cả dấu âm và dương trên không gian vòng tròn module $2^{32}$.
  - Điều này chứng minh nhân Linux hiện đại đang áp dụng đúng tiêu chuẩn RFC 6528: sử dụng hàm băm mật mã một chiều với khóa bí mật ngẫu nhiên của kernel kết hợp với bộ 4 thông số socket `(src_ip, src_port, dst_ip, dst_port)` và đồng hồ thời gian. Thuật toán này triệt tiêu hoàn toàn khả năng ngoại suy tuyến tính của kẻ tấn công.

#### Câu 3: Trong Bước 2.3, nếu attacker ở ngoài đoạn mạng (không sniff được SYN/ACK) thì phải làm gì để hoàn tất bắt tay? Điều này liên hệ thế nào với 'dự đoán ISN'?
- **Hành động cần làm:** Nếu không thể bắt gói (sniff) trên dây, attacker bắt buộc phải đoán mò (brute-force hoặc ngoại suy mô hình toán học) giá trị `Server_ISN`. Cụ thể, sau khi gửi gói `SYN` giả mạo, attacker phải bắn hàng loạt gói `ACK` với các giá trị phỏng đoán `ack = guessed_isn + 1` trong dải số hy vọng trúng cửa sổ nhận (Receive Window) của server.
- **Liên hệ với "Dự đoán ISN":** Đây chính là bản chất của kỹ thuật tấn công TCP ISN Prediction trong lịch sử (Morris/Mitnick). Khi thuật toán sinh ISN còn thô sơ (tăng cố định theo mili giây), attacker chỉ cần đo trễ (RTT) và tốc độ tăng của bộ đếm là có thể tính toán chính xác ISN trong vài lần thử. Tuy nhiên, với không gian $2^{32}$ ngẫu nhiên hiện nay, xác suất đoán trúng một kết nối là xấp xỉ $\frac{1}{2^{32}} \approx 2.3 \times 10^{-10}$, khiến tấn công mù trong thực tế bị vô hiệu hóa.

#### Câu 4: BCP 38 ngăn chặn thành phần nào của cuộc tấn công? Vì sao chỉ ngẫu nhiên hóa ISN là chưa đủ?
- **Thành phần bị BCP 38 ngăn chặn:** BCP 38 (Network Ingress Filtering) ngăn chặn trực tiếp hành vi **IP Spoofing** ngay từ bước đầu tiên. Bộ định tuyến biên sẽ kiểm tra nếu gói tin rời khỏi mạng nội bộ có địa chỉ IP nguồn không khớp với dải địa chỉ được định tuyến của mạng đó thì sẽ lập tức bị hủy bỏ (drop). Do đó, gói `SYN` giả mạo nguồn `10.0.0.77` không bao giờ rời khỏi được phân đoạn mạng của attacker.
- **Vì sao chỉ ngẫu nhiên hóa ISN là chưa đủ:**
  - Ngẫu nhiên hóa ISN chỉ chống lại kẻ tấn công **off-path** (kẻ không thấy được gói tin).
  - Nó hoàn toàn **bất lực** trước kẻ tấn công **on-path** (nằm trên đường truyền, cùng phân đoạn mạng LAN bị nhiễm độc ARP, hoặc kiểm soát được router trung gian). Kẻ tấn công on-path chỉ việc đọc trường SEQ trong gói `SYN+ACK` bay qua card mạng mà không cần đoán. Do đó, cần kết hợp cả BCP 38 (chống spoofing), ngẫu nhiên hóa ISN (chống đoán mò) và mã hóa xác thực như TLS/IPsec (chống nghe lén on-path).

#### Câu 5: Dùng lệnh nào để quan sát ISN do chính kernel của bạn sinh ra cho một kết nối thật? (gợi ý: tcpdump bắt gói SYN đi ra).
- Để quan sát giá trị ISN thực tế (dạng số thô tuyệt đối, không bị Wireshark/tcpdump hiển thị tương đối `relative sequence number`), ta sử dụng tùy chọn `-S` của lệnh `tcpdump`:
  ```bash
  tcpdump -i any -nn -S "tcp[tcpflags] & tcp-syn != 0"
  ```
- **Giải thích tham số:**
  - `-i any`: Lắng nghe trên mọi giao diện mạng.
  - `-nn`: Không phân giải tên miền và tên cổng dịch vụ (hiển thị IP và Port số thuần).
  - `-S`: In số thứ tự TCP tuyệt đối (Absolute TCP Sequence Numbers) thay vì số thứ tự tương đối bắt đầu từ 0.
  - `tcp[tcpflags] & tcp-syn != 0`: Bộ lọc BPF chỉ bắt các gói tin TCP có bật cờ `SYN`.

