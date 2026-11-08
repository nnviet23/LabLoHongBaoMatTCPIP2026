# BÁO CÁO LÝ THUYẾT & PHÂN TÍCH CHUYÊN SÂU: LAB 06
## Kỹ Thuật Tấn Công Teardrop Attack (Overlapping IP Fragments & DoS)

---

### 1. Mục Tiêu & Chuẩn RFC Liên Quan

#### 1.1 Mục Tiêu Bài Học (Trích xuất từ tài liệu đề bài)
- Thấu hiểu toàn diện kiến trúc phân mảnh và tái hợp gói tin IPv4 (IP Fragmentation and Reassembly), bao gồm ý nghĩa của trường Identification, cờ More Fragments (MF) và trường Fragment Offset.
- Sử dụng thư viện Scapy để tự tay thiết kế và chế tạo các mảnh gói tin IP có độ lệch chồng lấn bất thường (Overlapping Fragments) mang đặc trưng của mã độc Teardrop lịch sử.
- Quan sát và phân tích cơ chế xử lý phòng thủ an toàn của nhân Linux hiện đại: Máy chủ không bị treo/sập (No Crash/Panic), ghi nhận sự gia tăng của chỉ số thống kê lỗi tái hợp `ReasmFails` trong `/proc/net/snmp` để chứng minh hệ thống đã hoàn toàn miễn nhiễm.

#### 1.2 Các Chuẩn RFC và Tài Liệu Học Thuật Tham Chiếu
- **RFC 791 (Internet Protocol - 1981):** Quy định cơ chế phân mảnh IP khi kích thước gói tin vượt quá Đơn vị truyền tải tối đa (MTU) của đường truyền mạng. Tiêu chuẩn này quy định trường Fragment Offset có độ dài 13 bit và được tính theo **đơn vị khối 8 byte (8-octet blocks)**.
- **CVE-1999-0015 (Teardrop IP Fragment Overlap Vulnerability):** Mã định danh bảo mật quốc tế cho lỗ hổng kinh điển xuất hiện năm 1997 gây sập hoàn toàn hệ điều hành Windows 95, Windows NT 4.0 và Linux kernel trước bản 2.0.32.
- **RFC 1858 (Security Considerations for IP Fragment Filtering - 1995):** Phân tích các mối nguy hiểm bảo mật bắt nguồn từ cơ chế phân mảnh IP (Tiny Fragment Attack, Overlapping Fragment Attack) và đề xuất kỹ thuật lọc gói tin phân mảnh cho tường lửa.
- **RFC 3128 (Protection Against a Variant of the Tiny Fragment Attack - 2001):** Bổ sung các giải pháp chống lại các biến thể chèn mảnh đè lên tiêu đề cổng TCP/UDP.

---

### 2. Nguyên Lý Tấn Công & Điểm Yếu Giao Thức

#### 2.1 Cơ Chế Phân Mảnh Và Tái Hợp IP (IP Fragmentation & Reassembly)
Khi một gói tin IP có kích thước lớn hơn MTU của chặng tiếp theo (ví dụ MTU Ethernet là 1500 bytes), router hoặc host gửi sẽ chia nhỏ payload thành các mảnh:
- **Identification (16 bit):** Mã số định danh duy nhất cho gói tin gốc. Tất cả các mảnh cắt ra từ cùng một gói tin bắt buộc phải mang cùng giá trị `IP ID`.
- **Flags (3 bit):**
  - Cờ `DF (Don't Fragment)`: Yêu cầu không được phân mảnh.
  - Cờ `MF (More Fragments)`: Nếu $= 1$ nghĩa là phía sau vẫn còn mảnh tiếp theo; nếu $= 0$ nghĩa là đây là mảnh cuối cùng.
- **Fragment Offset (13 bit):** Xác định vị trí tương đối của mảnh dữ liệu này so với điểm bắt đầu của gói tin ban đầu. Giá trị offset luôn được nhân với $8$ để ra vị trí byte thực tế trong bộ đệm.
- **Quá trình tái hợp tại bên nhận:**
  Hệ điều hành đích duy trì một danh sách liên kết các mảnh có cùng bộ định danh `(Source IP, Dest IP, Protocol, IP ID)`. Khi tất cả các mảnh từ offset 0 đến mảnh cuối cùng (`MF=0`) được thu thập đầy đủ và liên tục, kernel sẽ ghép các vùng nhớ lại và chuyển lên tầng giao vận (TCP/UDP/ICMP).

#### 2.2 Cơ Chế Lỗi Gây Crash Hệ Thống Của Teardrop (Integer Underflow)
Cuộc tấn công Teardrop khai thác một lỗi sơ đẳng trong việc kiểm tra biên và số học con trỏ tại mã nguồn ghép mảnh của các hệ điều hành thế hệ cũ:
1. Kẻ tấn công gửi **Mảnh 1:**
   - `Offset = 0` (tương ứng từ byte $0$).
   - `Flags = MF` ($1$).
   - Kích thước payload = $24\text{ bytes}$ (chiếm dải từ byte $0 \rightarrow 23$).
2. Kẻ tấn công gửi **Mảnh 2:**
   - `Offset = 1` (tương ứng vị trí bắt đầu là $1 \times 8 = \text{byte } 8$).
   - `Flags = 0` (mảnh cuối).
   - Kích thước payload = $24\text{ bytes}$ (định vị từ byte $8 \rightarrow 31$).
3. **Phân tích chồng lấn:** Dải byte từ $8 \rightarrow 23$ của Mảnh 2 bị **chồng lấn (overlap)** lên dữ liệu đã có của Mảnh 1.
4. **Lỗi trong mã nguồn cũ:**
   - Để xử lý phần chồng lấn, đoạn mã trong kernel cũ cố gắng tính toán phần dữ liệu thực sự "mới" của Mảnh 2 cần sao chép vào bộ đệm:
     $$\text{new\_len} = \text{fragment2\_len} - (\text{end\_of\_fragment1} - \text{start\_of\_fragment2})$$
   - Tuy nhiên, trong kịch bản tấn công tinh vi hơn (hoặc khi mảnh thứ hai có kích thước nhỏ hơn phần chồng lấn, ví dụ một mảnh sau nằm hoàn toàn lọt thỏm bên trong mảnh trước), phép trừ này bị tràn số dưới (Integer Underflow) sinh ra một **số nguyên âm** (ví dụ $-1$ hoặc $-4$).
   - Đoạn mã kernel sau đó truyền giá trị độ dài này vào hàm sao chép bộ nhớ `memcpy(dest, src, count)`. Trong ngôn ngữ C, tham số `count` được định nghĩa là kiểu số nguyên không dấu (`size_t` / `unsigned int`).
   - Một số nguyên âm khi bị ép kiểu thành số không dấu sẽ biến thành một con số dương khổng lồ (ví dụ $-1$ trở thành $4,294,967,295 \approx 4\text{ GB}$).
   - Hàm `memcpy` lập tức sao chép dữ liệu vượt qua biên bộ nhớ được cấp phát, ghi đè và phá hủy toàn bộ bảng trang và không gian bộ nhớ của Kernel $\rightarrow$ **Hệ thống gặp sự cố tức thì (Kernel Panic trên Linux, Blue Screen of Death - BSOD trên Windows NT).**

```
Mảnh 1:  [ Byte 0 ........................ Byte 23 ]  (MF=1, Offset=0)
Mảnh 2:              [ Byte 8 ........................ Byte 31 ] (MF=0, Offset=1)
                     |<- VÙNG CHỒNG LẤN ->|
                        (Bytes 8 -> 23)
```

#### 2.3 Phân Tích Kỹ Thuật (Senior Protocol Researcher Perspective)
Tại sao hệ thống hiện đại hoàn toàn miễn nhiễm?
- Kể từ năm 1998, tất cả các hệ điều hành hiện đại (Linux kernel $\ge 2.0.32$, Windows 2000 trở về sau) đều đã áp dụng giải thuật chuẩn hóa mảnh nghiêm ngặt:
  1. Kiểm tra tính hợp lệ của biên: Nếu một mảnh mới có vị trí bắt đầu nhỏ hơn phần kết thúc của mảnh trước đó, kernel sẽ thực hiện thao tác cắt tỉa (clipping / trimming) phần dữ liệu thừa hoặc loại bỏ mảnh xung đột.
  2. Bất kỳ phép tính số học nào có nguy cơ sinh ra độ dài âm đều bị chặn trước khi gọi `memcpy`.
  3. Nếu cấu trúc chuỗi mảnh bị sai lệch nghiêm trọng, kernel sẽ lập tức giải phóng hàng đợi tái hợp của gói tin đó, tăng bộ đếm lỗi `ReasmFails` trong bảng thống kê giao thức IP và tiếp tục hoạt động bình thường mà không hề bị ảnh hưởng.

---

### 3. Cơ Chế Phòng Thủ (Mitigation)

#### 3.1 Cập Nhật Và Vá Lỗi Hệ Điều Hành (Patching & OS Updates)
- Lỗ hổng Teardrop và các biến thể phân mảnh (như Bonk, Boink, NewTear, Jolt2) là những lỗ hổng ở tầng cài đặt mã nguồn (Software Implementation Flaw). Do đó, việc cập nhật phiên bản kernel mới là biện pháp triệt để nhất loại bỏ hoàn toàn lỗ hổng này.

#### 3.2 Kỹ Thuật Lọc & Tẩy Rửa Phân Mảnh Tại Tường Lửa (Fragment Scrubbing - RFC 1858)
- **Chuẩn hóa phân mảnh (Packet Normalization / Fragment Scrubbing):** Các thiết bị tường lửa chuyên dụng (như pfSense / Cisco ASA / Fortinet) tích hợp tính năng Fragment Scrubbing. Khi có các mảnh đi qua tường lửa, thiết bị sẽ:
  - Tạm giữ các mảnh lại và tự mình tái hợp gói tin hoàn chỉnh trước khi chuyển tiếp vào mạng nội bộ.
  - Tự động phát hiện và cắt bỏ các phần dữ liệu bị chồng lấn, chỉ giữ lại phần dữ liệu của mảnh đến đầu tiên (First-fragment policy) hoặc mảnh đến sau (Last-fragment policy) theo cấu hình an ninh đồng nhất.
  - Hủy bỏ ngay các gói tin có offset bất thường hoặc kích thước mảnh quá nhỏ (Tiny Fragments nhằm che giấu cổng TCP).

#### 3.3 Quản Lý Tài Nguyên Hàng Đợi Tái Hợp (Resource Limits)
Để chống lại việc kẻ tấn công gửi hàng triệu mảnh IP không hoàn chỉnh nhằm gây cạn kiệt bộ nhớ RAM của kernel (Fragment Flooding DoS), nhân Linux cung cấp các tham số cấu hình:
```bash
# Giới hạn dung lượng bộ nhớ tối đa dành cho việc lưu trữ các mảnh IP đang chờ ghép (bytes)
sysctl -w net.ipv4.ipfrag_high_thresh=4194304   # 4 MB
sysctl -w net.ipv4.ipfrag_low_thresh=3145728    # 3 MB

# Thời gian tối đa giữ các mảnh chưa hoàn chỉnh trong bộ nhớ trước khi hủy (giây)
sysctl -w net.ipv4.ipfrag_time=30
```

#### 3.4 Giám Sát Bằng IDS/IPS (Suricata / Snort)
- Kích hoạt luật phát hiện lưu lượng phân mảnh dị thường:
  ```text
  alert ip any any -> any any (msg:"IP Fragment Overlap Detected"; fragbits:M; ipopts:any; sid:1000006; rev:1;)
  ```

---

### 4. Giải Đáp Chi Tiết Câu Hỏi Ôn Tập (Review Questions)

#### Câu 1: Fragment offset tính theo đơn vị nào? Hai mảnh ở Bước 2.3 chồng lấn ở khoảng byte nào?
- **Đơn vị của trường Fragment Offset:**
  - Theo chuẩn RFC 791, trường Fragment Offset có độ dài 13 bit và được tính theo **đơn vị là các khối 8-byte (8-octet units)**.
  - Để tính ra vị trí byte bắt đầu thực tế của mảnh trong dữ liệu gói tin IP ban đầu, ta lấy giá trị của trường offset nhân với $8$:
    $$\text{Byte Offset} = \text{Fragment Offset} \times 8$$
- **Khoảng byte bị chồng lấn ở Bước 2.3:**
  - **Mảnh 1:** `frag = 0`, mang 24 bytes dữ liệu. Mảnh này chiếm dải từ **byte 0 đến byte 23**.
  - **Mảnh 2:** `frag = 1`, mang 24 bytes dữ liệu. Vị trí byte bắt đầu là $1 \times 8 = 8$, kéo dài 24 bytes tiếp theo, do đó mảnh này định vị từ **byte 8 đến byte 31**.
  - **Khoảng chồng lấn (Overlapping Interval):** Hai mảnh cùng tồn tại và chồng lấn lên nhau chính xác ở dải từ **byte thứ 8 đến byte thứ 23** (tổng cộng $23 - 8 + 1 = 16\text{ bytes}$ bị chồng chéo).

#### Câu 2: Vì sao các mảnh chồng lấn từng làm hệ thống cũ crash? Kernel hiện đại xử lý khác ra sao?
- **Vì sao hệ thống cũ bị crash:**
  - Trong mã nguồn xử lý tái hợp gói tin của các hệ điều hành cũ (Windows 95/NT, Linux < 2.0.32), đoạn mã giả định rằng các mảnh IP luôn được gửi theo thứ tự tuần tự hoặc ít nhất không bao giờ có dữ liệu đè lên nhau.
  - Khi xuất hiện các mảnh chồng lấn, thuật toán trừ độ dài để tìm phần dữ liệu mới bị tính toán sai, dẫn tới kết quả là một **số nguyên âm**.
  - Khi truyền số nguyên âm này vào hàm sao chép vùng nhớ hệ thống `memcpy()`, tham số kích thước nhận kiểu số nguyên không dấu (`unsigned int`), biến giá trị âm thành một số dương cực lớn (khoảng $4\text{ GB}$).
  - Hàm `memcpy` thực hiện sao chép vùng nhớ vượt quá dung lượng đệm, ghi đè làm hỏng toàn bộ cấu trúc dữ liệu quan trọng của Kernel, gây lỗi bộ nhớ nghiêm trọng dẫn đến việc sập toàn bộ hệ điều hành ngay lập tức.
- **Kernel hiện đại xử lý khác ra sao:**
  - **Kiểm tra biên an toàn (Strict Bounds Checking):** Kernel kiểm tra chặt chẽ giá trị bắt đầu và kết thúc của từng mảnh trước khi ghi vào bộ nhớ. Nếu phát hiện mảnh có offset nằm trong phạm vi đã được lấp đầy bởi mảnh trước, kernel sẽ tự động điều chỉnh cắt bỏ (trimming) phần byte trùng lặp hoặc hủy bỏ mảnh mới nếu không có dữ liệu mới hợp lệ.
  - **Bảo vệ phép tính số học (Underflow Prevention):** Kiểm tra điều kiện tiên quyết để đảm bảo độ dài sao chép luôn là một số nguyên dương.
  - **Hủy gói tin an toàn (Graceful Drop):** Nếu cấu trúc chuỗi mảnh bất thường không thể ghép nối một cách hợp lệ, kernel sẽ hủy toàn bộ các mảnh liên quan, giải phóng bộ nhớ và tăng chỉ số thống kê lỗi `ReasmFails` mà không gây ra bất kỳ gián đoạn nào cho hệ thống.

#### Câu 3: Giá trị ReasmFails thay đổi thế nào trước/sau tấn công? Nó cho biết điều gì?
- **Sự thay đổi của ReasmFails:**
  - Khi kiểm tra tệp `/proc/net/snmp` (tại dòng `Ip:`) trước khi phát động tấn công, chỉ số `ReasmFails` thường giữ nguyên ở một giá trị cố định (hoặc bằng 0 nếu máy mới khởi động).
  - Sau khi kẻ tấn công phát hai mảnh IP dị thường của kịch bản Teardrop tới máy nạn nhân, giá trị của **`ReasmFails` sẽ tăng lên** (thường tăng thêm 1 đơn vị tương ứng với 1 phiên tái hợp gói tin IP bị thất bại).
- **Ý nghĩa của chỉ số này:**
  - Chỉ số `ReasmFails` (Reassembly Failures) là bộ đếm thống kê tiêu chuẩn của SNMP đo lường số lần phân đoạn IP không thể ghép lại thành công (do hết thời gian chờ timeout, do lỗi cấu trúc mảnh, hoặc do phát hiện mảnh độc hại bị hủy).
  - Việc `ReasmFails` tăng lên trong khi máy chủ vẫn phản hồi ping bình thường và không xuất hiện thông báo hoảng loạn kernel (`dmesg` không có kernel panic) là **bằng chứng khoa học rõ ràng nhất** cho thấy hệ điều hành đã nhận diện thành công các mảnh Teardrop dị thường và chủ động từ chối xử lý chúng để tự bảo vệ.

#### Câu 4: Ngoài Teardrop, hãy nêu một tấn công khác cũng lợi dụng phân mảnh IP và cách phòng chống.
- **Tấn công kinh điển khác: Tiny Fragment Attack / Fragment Overwrite Attack (RFC 1858 / RFC 3128):**
  - **Nguyên lý:** Kẻ tấn công lợi dụng cơ chế phân mảnh để vượt qua bộ lọc tường lửa (Firewall Evasion). Tường lửa kiểm tra cổng nguồn/đích của gói tin nằm ở mảnh đầu tiên (Mảnh 0). Kẻ tấn công cố tình tạo Mảnh 0 cực nhỏ (chỉ chứa một phần IP header và một vài byte đầu của TCP header, không đủ chứa trường Destination Port). Tường lửa không thấy cổng nên cho qua. Sau đó, kẻ tấn công gửi Mảnh 1 (hoặc Mảnh có offset chồng lấn) ghi đè đúng vào vị trí chứa Port để biến gói tin thành truy cập vào một cổng cấm (ví dụ cổng SSH 22 hoặc Telnet).
  - **Một cuộc tấn công khác: Ping of Death (CVE-1999-0128):** Kẻ tấn công gửi các mảnh IP có tổng kích thước sau khi tái hợp vượt quá giới hạn tối đa cho phép của một gói IPv4 ($65,535\text{ bytes}$), gây tràn bộ đệm của hệ điều hành đích.
- **Cách phòng chống chung cho các tấn công lợi dụng phân mảnh IP:**
  1. **Fragment Scrubbing trên Tường lửa:** Thiết lập tường lửa tái hợp toàn bộ gói tin tại biên trước khi kiểm tra chính sách bảo mật (Reassemble before inspection), từ chối cho qua các mảnh rời rạc có kích thước bất thường (nhỏ hơn 68 bytes) hoặc có offset chồng chéo.
  2. **Chính sách lọc gói nghiêm ngặt (RFC 1858):** Loại bỏ ngay mảnh đầu tiên (Offset = 0) nếu nó không chứa đủ toàn bộ phần tiêu đề tối thiểu của giao thức tầng trên (TCP header tối thiểu 20 bytes).
  3. **Ưu tiên Path MTU Discovery (PMTUD):** Trong các mạng hiện đại, khuyến khích sử dụng cờ DF (Don't Fragment) kết hợp PMTUD để truyền thông không cần phân mảnh gói tin, hạn chế tối đa việc phát sinh phân mảnh trên đường truyền.

