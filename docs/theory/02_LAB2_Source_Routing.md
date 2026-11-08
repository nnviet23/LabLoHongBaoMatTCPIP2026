# BÁO CÁO LÝ THUYẾT & PHÂN TÍCH CHUYÊN SÂU: LAB 02
## Lỗ Hổng Bảo Mật Loại IP Source Routing (LSRR/SSRR Vulnerability)

---

### 1. Mục Tiêu & Chuẩn RFC Liên Quan

#### 1.1 Mục Tiêu Bài Học (Trích xuất từ tài liệu đề bài)
- Hiểu rõ cơ chế hoạt động và cấu trúc của tùy chọn IP Source Routing (LSRR - Loose Source and Record Route, SSRR - Strict Source and Record Route) trong tiêu đề IP.
- Nhận thức mối nguy hiểm an ninh nghiêm trọng: Kẻ tấn công có thể giả mạo địa chỉ IP nguồn tùy ý nhưng vẫn nhận được toàn bộ gói tin phản hồi của nạn nhân thông qua việc ép lộ trình quay ngược.
- Thực hành tái tạo điều kiện dễ bị tấn công trên nhân Linux bằng tham số kernel `accept_source_route=1`, quan sát hành vi đảo ngược tuyến đường, sau đó cấu hình phòng thủ và kiểm chứng kết quả.

#### 1.2 Các Chuẩn RFC và Tài Liệu Học Thuật Tham Chiếu
- **RFC 791 (Internet Protocol - 1981):** Định nghĩa giao thức IP và trường IP Options trong header. Trong đó chỉ định rõ tùy chọn SSRR (Type = 137, `0x89`) và LSRR (Type = 131, `0x83`) nhằm mục đích ban đầu là chẩn đoán đường truyền mạng và gỡ lỗi định tuyến.
- **RFC 1122 (Requirements for Internet Hosts - Communication Layers - 1989):** Yêu cầu một hệ thống host khi nhận được gói tin có tùy chọn Source Routing bắt buộc phải đảo ngược danh sách các chặng (route reverse) khi sinh gói tin trả lời (chẳng hạn như ICMP Echo Reply hay TCP SYN/ACK).
- **RFC 7126 (Filtering of IP-Optioned Packets - 2014):** Khuyến nghị tiêu chuẩn của IETF về việc bộ định tuyến biên mạng (edge router) nên loại bỏ (drop) toàn bộ các gói tin IPv4 chứa tùy chọn Source Routing do rủi ro an ninh áp đảo giá trị vận hành thực tế.
- **CERT Advisory CA-1995-01 / IP Spoofing via Source Routing:** Cảnh báo an ninh mạng toàn cầu đầu tiên về các cuộc tấn công chiếm quyền điều khiển phiên thông qua khai thác LSRR/SSRR.

---

### 2. Nguyên Lý Tấn Công & Điểm Yếu Giao Thức

#### 2.1 Điểm Yếu Cốt Lõi Của Kiến Trúc Định Tuyến Do Nguồn (Source Routing)
Trong mô hình mạng IP chuẩn tắc (Hop-by-Hop Destination-based Routing), quyết định chuyển tiếp gói tin thuộc về các router trung gian dựa trên địa chỉ IP đích (`Destination IP`).
- **Nguyên lý Source Routing:** Người gửi (Sender) được phép can thiệp trực tiếp vào quyết định chuyển tiếp bằng cách đóng gói danh sách các nút trung gian (IP list) ngay trong phần Option của IP Header:
  - **Loose Source Routing (LSRR):** Gói tin bắt buộc phải đi qua các router được liệt kê trong danh sách, nhưng giữa các chặng đó có thể đi qua nhiều router trung gian khác.
  - **Strict Source Routing (SSRR):** Gói tin bắt buộc phải đi chính xác theo từng bước kế tiếp nhau trong danh sách mà không được phép rẽ qua bất kỳ router nào ngoài danh sách.
- **Cơ chế Đảo Lược Lộ Trình (Route Reversal Vulnerability):**
  Theo RFC 1122, máy nhận khi trả lời gói tin source-routed sẽ tạo một gói tin mới, lấy danh sách IP trong option của gói nhận được, đảo ngược thứ tự và gán vào gói trả lời. 
  Điều này tạo ra lỗ hổng chí mạng: **Attacker có thể giả mạo IP nguồn của một máy chủ đáng tin cậy (ví dụ Firewall Admin / Trusted Host), nhưng trong tùy chọn SSRR lại ghi danh sách các nút quay về IP thực tế của Attacker.** Nạn nhân khi xử lý xong sẽ gửi phản hồi ngược lại đúng IP của Attacker!

#### 2.2 Tấn Công 2-Chiều Giả Mạo Nguồn (Two-Way Spoofing via SSRR)
1. Attacker ($10.0.0.1$) muốn nói chuyện với Victim ($10.0.0.2$) dưới danh nghĩa IP tin cậy ($10.0.0.77$).
2. Nếu gửi IP Spoofing thông thường: Victim sẽ gửi phản hồi về máy $10.0.0.77$, Attacker không nhận được gì (Blind).
3. Attacker đóng gói tùy chọn `IPOption_SSRR(routers=["10.0.0.1", "10.0.0.2"])` vào gói tin gửi đi với $IP_{\text{src}} = 10.0.0.77$ và $IP_{\text{dst}} = 10.0.0.2$.
4. Khi Victim nhận được gói, kiểm tra thấy $IP_{\text{dst}}$ là chính mình. Victim xử lý gói ICMP Echo Request.
5. Khi phản hồi, kernel Victim đảo ngược lộ trình SSRR: gói Echo Reply sẽ có đích đến là $10.0.0.77$, nhưng đường dẫn trung gian (Next Hop) lại bị ép đi qua $10.0.0.1$ (Attacker).
6. Kết quả: Attacker nhận được toàn bộ gói trả lời từ Victim dù gói tin đó chính thức có $IP_{\text{dst}} = 10.0.0.77$.

#### 2.3 Phân Tích Kỹ Thuật (Senior Protocol Researcher Perspective)
Tại sao trường `IHL` (Internet Header Length) lại bị thay đổi?
- Header IPv4 chuẩn không có options có độ dài 20 bytes. Do đơn vị tính của trường IHL (4-bit) là các từ 32-bit (4 bytes), giá trị của IHL ở trạng thái bình thường là $\frac{20}{4} = 5$ (tương ứng `0101` nhị phân).
- Khi có thêm tùy chọn SSRR/LSRR, mỗi địa chỉ IP bổ sung tiêu tốn 4 bytes, kèm theo 3 bytes header của option (Code, Length, Pointer) và các byte đệm (padding) để chia hết cho 4.
- Vì vậy, độ dài tiêu đề IP lúc này chắc chắn lớn hơn 20 bytes, dẫn tới giá trị $\text{IHL} > 5$. Đây là dấu hiệu nhận diện bất thường cốt lõi cho phép bộ lọc mạng (Packet Filter) và firewall phát hiện tức thì bằng biểu thức lọc:
  `ip[0] & 0x0f > 5`

---

### 3. Cơ Chế Phòng Thủ (Mitigation)

#### 3.1 Cấu Hình Nhân Linux (Kernel Sysctl)
Nhân Linux hiện đại được bảo vệ mặc định thông qua các tham số hạt nhân kiểm soát tiếp nhận và chuyển tiếp gói source-routed:
```bash
# Vô hiệu hóa tiếp nhận source routing trên mọi interface
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0

# Kích hoạt Reverse Path Filtering chế độ nghiêm ngặt (Strict Mode)
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
```
- Khi `accept_source_route = 0`: Kernel sẽ tự động hủy bỏ (drop) mọi gói tin có chứa trường Option SSRR/LSRR ngay tại tầng IP, không chuyển tiếp và không sinh gói trả lời.
- `rp_filter = 1` (RFC 3704): Yêu cầu kernel kiểm tra xem nếu gửi gói tin trả lời về địa chỉ IP nguồn thì cổng mạng đi ra có trùng khớp với cổng mạng đã nhận gói tin vào hay không.

#### 3.2 Cấu Hình Tường Lửa & Router Chuyên Dụng (Cisco / Iptables)
- **Trên Router Cisco:**
  ```text
  Router(config)# no ip source-route
  ```
- **Trên Linux Netfilter / iptables:**
  ```bash
  # Loại bỏ gói tin chứa tùy chọn IP source route
  iptables -A INPUT -m ipv4options --flags lsrr,ssrr -j DROP
  iptables -A FORWARD -m ipv4options --flags lsrr,ssrr -j DROP
  ```

#### 3.3 Khuyến Nghị Lọc Gói Tin Tại Biên Mạng (RFC 7126)
- Bộ định tuyến biên (Edge Router / Border Gateway) của các nhà cung cấp dịch vụ mạng (ISP) và doanh nghiệp là chốt chặn quan trọng nhất. Nếu gói tin có options bị drop ngay tại cổng biên, lưu lượng tấn công không bao giờ có thể tiếp cận hạ tầng nội bộ.

---

### 4. Giải Đáp Chi Tiết Câu Hỏi Ôn Tập (Review Questions)

#### Câu 1: Phân biệt Loose (LSRR) và Strict (SSRR) source routing. Trường IHL thay đổi thế nào khi có tùy chọn này?
- **Phân biệt LSRR và SSRR:**
  - `Loose Source and Record Route (LSRR - Option 131 / 0x83):` Cho phép người gửi chỉ định một danh sách các "cột mốc" router mà gói tin bắt buộc phải đi qua. Tuy nhiên, giữa hai cột mốc liên tiếp, gói tin có thể đi qua bất kỳ số lượng router trung gian nào khác tùy theo bảng định tuyến thông thường của mạng.
  - `Strict Source and Record Route (SSRR - Option 137 / 0x89):` Yêu cầu gói tin phải đi **chính xác từng chặng** theo danh sách IP quy định trong option. Địa chỉ IP của chặng kế tiếp phải là router kết nối trực tiếp trên cùng liên kết vật lý/liên kết trực tiếp; nếu router hiện tại không thể chuyển tiếp trực tiếp đến địa chỉ tiếp theo trong danh sách, một thông điệp lỗi `ICMP Source Route Failed` (Type 3, Code 5) sẽ được sinh ra và gói tin bị hủy.
- **Sự thay đổi của trường IHL:**
  - Tiêu đề IPv4 tiêu chuẩn (không có tùy chọn) dài 20 bytes, trường IHL (Internet Header Length) có giá trị bằng $5$ (vì $5 \times 4 = 20\text{ bytes}$).
  - Khi thêm tùy chọn LSRR hoặc SSRR, kích thước phần Option tối thiểu tăng thêm từ vài byte đến hàng chục byte (gồm 1 byte Type, 1 byte Length, 1 byte Pointer, cộng thêm $4 \times N$ bytes cho $N$ địa chỉ IP, và padding để làm tròn bội số của 4).
  - Do đó, tổng độ dài header IP sẽ từ 24 đến tối đa 60 bytes, dẫn tới **giá trị của trường IHL sẽ luôn luôn lớn hơn 5** ($\text{IHL} \in [6, 15]$).

#### Câu 2: Vì sao source routing phá vỡ hiệu quả của reverse-path filtering trong việc chống giả mạo nguồn?
- **Cơ chế thông thường của Reverse Path Filtering (RPF / RFC 3704):**
  RPF hoạt động bằng cách lấy địa chỉ IP nguồn ($IP_{\text{src}}$) của gói tin đến tra cứu ngược vào bảng định tuyến FIB (Forwarding Information Base). Nếu cổng mạng dẫn đến $IP_{\text{src}}$ đó không trùng khớp với cổng mạng vừa tiếp nhận gói tin, router/host kết luận gói tin bị giả mạo nguồn và lập tức loại bỏ.
- **Vì sao Source Routing phá vỡ RPF:**
  Khi gói tin sử dụng tùy chọn Source Routing, quyết định chuyển tiếp gói tin không dựa trên bảng định tuyến thông thường nữa mà bị ghi đè bởi danh sách IP trong trường Option. Khi host đích phản hồi, nó không tra cứu đường đi về $IP_{\text{src}}$ qua cổng thông thường mà đảo ngược tuyến đường trong Option và đẩy gói tin quay trở lại router trung gian mà kẻ tấn công đã cài cắm. Hơn nữa, trên các hệ thống cũ chưa được vá lỗi, kiểm tra RPF bị bỏ qua hoặc bị đánh lừa vì gói tin đi vào từ chính router được chỉ định hợp lệ trong danh sách chặng kế tiếp, làm mất hoàn toàn tác dụng phòng vệ của RPF.

#### Câu 3: Trong Bước 2.1, nếu không có SSRR, phản hồi của victim sẽ đi về đâu? Vì sao attacker không nhận được?
- **Hướng đi của phản hồi nếu không có SSRR:**
  Nếu không có tùy chọn SSRR, gói tin gửi đi chỉ là một gói IP thông thường với $IP_{\text{src}} = 10.0.0.77$ và $IP_{\text{dst}} = 10.0.0.2$. Khi máy chủ nạn nhân ($10.0.0.2$) sinh gói ICMP Echo Reply, nó sẽ gửi gói tin trực tiếp về địa chỉ IP đích $10.0.0.77$ theo bảng định tuyến chuẩn.
- **Vì sao attacker không nhận được:**
  - Địa chỉ $10.0.0.77$ là một địa chỉ không tồn tại (hoặc thuộc về một nút mạng khác, không phải của attacker tại $10.0.0.1$).
  - Gói phản hồi sẽ được định tuyến về máy $10.0.0.77$ (hoặc bị router drop / broadcast ARP tìm không thấy).
  - Vì attacker ($10.0.0.1$) nằm ngoài tuyến đường dẫn đến $10.0.0.77$, card mạng của attacker hoàn toàn không thể nhận hay nhìn thấy gói phản hồi này (trở thành tấn công mù một chiều - One-way Blind Spoofing).

#### Câu 4: Nêu hai nơi nên lọc gói source-routed và giải thích vì sao lọc ở biên mạng (edge) là quan trọng nhất.
- **Hai nơi nên lọc gói source-routed:**
  1. **Tại các Host đầu cuối (End Hosts / Servers):** Cấu hình trực tiếp trên hệ điều hành (`sysctl net.ipv4.conf.all.accept_source_route = 0` trên Linux, hoặc thiết lập Registry trên Windows) để từ chối xử lý và không đảo ngược lộ trình.
  2. **Tại Bộ định tuyến biên mạng (Edge Routers / Firewalls):** Cấu hình `no ip source-route` hoặc iptables rules để hủy bỏ toàn bộ gói tin có cờ options ngay tại ranh giới mạng giữa vùng mạng nội bộ và Internet.
- **Vì sao lọc ở biên mạng (Edge) là quan trọng nhất:**
  - **Bảo vệ toàn diện theo chiều sâu (Defense-in-Breadth):** Trong một mạng nội bộ doanh nghiệp lớn, có hàng nghìn thiết bị khác nhau (servers, máy trạm, thiết bị IoT, máy in, thiết bị di động). Quản trị viên không thể đảm bảo 100% mọi host nội bộ đều được cấu hình đúng tham số hạt nhân chống source-route. Lọc tại biên tạo thành chiếc ô bảo vệ tập trung cho toàn bộ hạ tầng bên trong.
  - **Tiết kiệm tài nguyên xử lý:** Việc loại bỏ gói độc hại ngay tại cửa ngõ giúp ngăn chặn lưu lượng rác thâm nhập sâu vào mạng lõi, tránh gây quá tải đường truyền nội bộ và giảm tải CPU cho các hệ thống máy chủ nội bộ.
  - **Triệt tiêu nguy cơ trinh sát mạng (Topology Mapping):** Source routing thường được kẻ tấn công sử dụng để thăm dò cấu trúc mạng nội bộ phía sau tường lửa (bằng cách ép gói tin đi sâu vào các IP private bên trong rồi dội ra ngoài). Chặn ở biên sẽ bẻ gãy hoàn toàn kỹ thuật trinh sát này.

