# BÁO CÁO LÝ THUYẾT & PHÂN TÍCH CHUYÊN SÂU: LAB 07
## Kỹ Thuật Bảo Mật Mở Rộng Hệ Thống Tên Miền DNSSEC (DNS Security Extensions)

---

### 1. Mục Tiêu & Chuẩn RFC Liên Quan

#### 1.1 Mục Tiêu Bài Học (Trích xuất từ tài liệu đề bài)
- Thấu hiểu sâu sắc điểm yếu bảo mật cốt lõi của giao thức DNS truyền thống: Hoạt động không có cơ chế xác thực nguồn gốc và không bảo vệ tính toàn vẹn dữ liệu, dẫn tới nguy cơ bị đầu độc bộ nhớ đệm (DNS Cache Poisoning) hoặc giả mạo phản hồi (DNS Spoofing).
- Triển khai thành công một vùng tên miền được ký số hoàn chỉnh bằng DNSSEC sử dụng máy chủ có thẩm quyền BIND9 (`named`) và cấu hình máy chủ phân giải kiểm tra chữ ký (Validating Resolver) sử dụng Unbound.
- Quan sát và giải mã ý nghĩa của cờ `ad` (Authenticated Data) cùng các bản ghi chữ ký `RRSIG` trong kết quả truy vấn DNS thực nghiệm.
- Chứng minh cơ chế phòng thủ vượt trội của DNSSEC: Validating Resolver chủ động phát hiện bản ghi giả mạo từ máy chủ rogue và trả về mã lỗi `SERVFAIL` để bảo vệ người dùng, trong khi một resolver không bật DNSSEC sẽ hoàn toàn bị lừa.

#### 1.2 Các Chuẩn RFC và Tài Liệu Học Thuật Tham Chiếu
- **RFC 4033 (DNS Security Introduction and Requirements - 2005):** Giới thiệu tổng quan về kiến trúc DNSSEC, các mục tiêu bảo mật (Data Integrity, Origin Authentication) và những gì DNSSEC không cung cấp (Confidentiality).
- **RFC 4034 (Resource Records for the DNS Security Extensions - 2005):** Định nghĩa cấu trúc các loại bản ghi DNS mới: `DNSKEY`, `RRSIG`, `NSEC`, `DS`.
- **RFC 4035 (Protocol Modifications for the DNS Security Extensions - 2005):** Quy định chi tiết các sửa đổi trong giao thức DNS dành cho Name Server và Resolver để sinh và kiểm tra chữ ký số.
- **RFC 5155 (DNSSEC Hashed Authenticated Denial of Existence - 2008):** Định nghĩa bản ghi `NSEC3` sử dụng băm mật mã để ngăn chặn việc kẻ tấn công quét vét toàn bộ dữ liệu tên miền trong vùng (Zone Enumeration / Zone Walking).
- **RFC 6781 (DNSSEC Operational Practices - 2012):** Tiêu chuẩn hướng dẫn quy trình vận hành DNSSEC an toàn, bao gồm quản lý chu kỳ sống và đảo khóa (Key Rollover - ZSK & KSK).
- **Dan Kaminsky (2008):** *"Black Ops of DNS"* — Công bố lỗ hổng chấn động thế giới cho phép đầu độc bộ nhớ đệm DNS trong thời gian dưới 10 giây bằng cách chèn truy vấn tên miền con ngẫu nhiên.

---

### 2. Nguyên Lý Tấn Công & Điểm Yếu Giao Thức

#### 2.1 Điểm Yếu Cốt Lõi Của DNS Truyền Thống
Hệ thống tên miền DNS nguyên thủy (RFC 1034 / 1035) hoạt động trên nền giao thức UDP cổng 53:
- **Thiếu tính xác thực mật mã:** Phía Resolver tin tưởng tuyệt đối vào bất kỳ gói tin phản hồi (DNS Response) nào nếu gói tin đó thỏa mãn hai điều kiện kiểm tra đơn giản:
  1. `Transaction ID (TXID - 16 bit)`: Trùng khớp với mã yêu cầu gửi đi.
  2. `UDP Source Port (16 bit)`: Trùng khớp với cổng tạm thời mà Resolver đã dùng để mở socket hỏi.
- **Tấn công đầu độc bộ nhớ đệm (Kaminsky DNS Cache Poisoning):**
  Kẻ tấn công gửi liên tục hàng nghìn truy vấn tên miền không tồn tại (ví dụ `random1.example.com`, `random2.example.com`) tới Resolver mục tiêu, đồng thời bắn phá ồ ạt hàng vạn gói tin DNS Response giả mạo với các TXID phỏng đoán, mạo danh Authoritative Server phản hồi rằng: *"Tên miền con đó không có, nhưng nhân tiện thông báo rằng nameserver của toàn bộ domain `example.com` là máy chủ độc hại của tôi tại IP `x.x.x.x`"*.
  Vì không gian TXID chỉ có $2^{16} = 65,536$ khả năng, kẻ tấn công chỉ mất vài giây để đoán trúng. Một khi bị nhiễm độc, Resolver sẽ lưu bản ghi độc hại vào cache và điều hướng mọi người dùng trong mạng nội bộ vào website giả mạo phục vụ lừa đảo (Phishing) hoặc đánh cắp thông tin thẻ tín dụng.

#### 2.2 Kiến Trúc Phòng Vệ Của DNSSEC
DNSSEC giải quyết triệt để vấn đề trên bằng cách tích hợp **chữ ký số bất đối xứng (Public-Key Cryptography)** vào cấu trúc bản ghi DNS:
- Mọi tập bản ghi (RRset - Resource Record Set, ví dụ tất cả các bản ghi A của `www.lab.test`) đều được ký số bằng khóa riêng (Private Key) của vùng.
- Bản thân chữ ký số được lưu trong bản ghi mới có tên là **`RRSIG`**.
- Khóa công khai dùng để giải mã chữ ký được lưu trong bản ghi **`DNSKEY`**.
- Để resolver tin cậy bản ghi `DNSKEY` của vùng `lab.test`, vùng cha (Parent Zone, ví dụ vùng `.` hoặc `.test`) sẽ lưu trữ một bản băm (fingerprint) của khóa này dưới dạng bản ghi **`DS (Delegation Signer)`**.
- Khi một Resolver có bật tính năng xác thực (Validating Resolver) tiếp nhận bản ghi:
  1. Resolver lấy bản ghi `RRSIG` tương ứng và dùng khóa `DNSKEY` để kiểm tra chữ ký.
  2. Resolver kiểm tra xem khóa `DNSKEY` này có trùng khớp với bản ghi `DS` được ký bởi vùng cha hay không.
  3. Quá trình kiểm tra đệ quy ngược lên cho tới Khóa neo tin cậy gốc toàn cầu (Root Trust Anchor).
  4. Nếu chữ ký toán học hoàn toàn khớp: Dữ liệu được chứng nhận tính toàn vẹn và nguồn gốc $\rightarrow$ Resolver đặt cờ **`ad` (Authenticated Data)** trong gói trả lời cho Client.
  5. Nếu dữ liệu bị kẻ tấn công sửa đổi, hoặc đến từ máy chủ giả mạo không có khóa riêng hợp lệ $\rightarrow$ Chữ ký sai $\rightarrow$ Resolver **hủy bỏ dữ liệu và trả về lỗi `SERVFAIL`**.

```
[ Root Zone (.) ] ---------- (Root Anchor Key - Built-in)
       |
       v (Bản ghi DS xác nhận khóa KSK của vùng con)
[ TLD Zone (.test) ]
       |
       v (Bản ghi DS xác nhận khóa KSK của lab.test)
[ Zone (lab.test) ]
       |
       +--> DNSKEY (KSK & ZSK)
       +--> RRSIG (Chữ ký điện tử cho www.lab.test)
       +--> A Record (www.lab.test -> 10.0.0.80)
```

#### 2.3 Phân Tích Kỹ Thuật (Senior Protocol Researcher Perspective)
Tại sao trong bài thực hành môi trường mạng cô lập không có Internet ta lại cần tạo "Island of Trust"?
- Trong điều kiện thực tế của Internet toàn cầu, chuỗi tin cậy bắt đầu từ **Root Zone (`.`)** được ICANN quản lý và neo tin cậy này đã được nạp sẵn vào cấu hình mặc định của các Resolver hiện đại (`root.hints` / `root.key`).
- Khi thực hành trong môi trường phòng lab cô lập (`ip netns` không có Internet ngoài), chuỗi đệ quy lên Root không thể thực hiện. Do đó, ta thiết lập một "Đảo tin cậy" (Island of Trust) bằng cách:
  1. Trích xuất trực tiếp bản ghi `DNSKEY` loại KSK (Flag 257) từ máy chủ có thẩm quyền BIND9:
     ```bash
     grep -E "IN[[:space:]]+DNSKEY[[:space:]]+257" /tmp/lab.dnskey > /tmp/trust-anchor.key
     ```
  2. Khai báo tệp này trực tiếp vào Unbound thông qua chỉ thị `trust-anchor-file: "/tmp/trust-anchor.key"` và cấu hình `domain-insecure: "."`.
  3. Cấu hình này biến khóa KSK của vùng `lab.test` trở thành điểm tựa tin cậy tối cao (Root of Trust) cho Resolver Unbound trong không gian cô lập.

---

### 3. Cơ Chế Phòng Thủ (Mitigation)

#### 3.1 Quy Trình Ký Số Vùng Tên Miền (Zone Signing)
- Triển khai cặp khóa chuẩn theo khuyến nghị của IETF:
  - **KSK (Key Signing Key - Flag 257):** Khóa dài (thường dùng RSA 2048-bit hoặc ECDSA P-256), chỉ dùng để ký lên bản thân tập bản ghi `DNSKEY`.
  - **ZSK (Zone Signing Key - Flag 256):** Khóa ngắn hơn (RSA 1024/2048-bit hoặc Ed25519), dùng để ký lên toàn bộ các tập bản ghi tài nguyên dữ liệu thông thường trong zone (`A`, `AAAA`, `MX`, `TXT`).
- Đăng tải bản băm DS của KSK lên Registry của vùng cha (Parent Registrar) để hoàn tất chuỗi tin cậy.

#### 3.2 Kích Hoạt Tính Năng Xác Thực Tại Resolver (Validation Enforcement)
- Tất cả các máy chủ đệ quy nội bộ của doanh nghiệp và ISP phải kích hoạt tính năng kiểm tra DNSSEC (DNSSEC Validation):
  - **Trên Unbound:**
    ```yaml
    server:
      module-config: "validator iterator"
      harden-dnssec-stripped: yes
      val-permissive-mode: no
    ```
  - **Trên BIND9:**
    ```text
    dnssec-validation auto;
    ```
- Tham số `harden-dnssec-stripped: yes` đảm bảo rằng nếu một vùng tên miền vốn đã có DNSSEC mà kẻ tấn công cố tình cắt bỏ các bản ghi `RRSIG` trên đường truyền thì Resolver sẽ lập tức coi đó là một vụ tấn công và trả về `SERVFAIL`.

#### 3.3 Chống Quét Vét Tên Miền Bằng NSEC3 (RFC 5155)
- Thay thế bản ghi `NSEC` truyền thống (vốn để lộ danh sách tên miền kế tiếp bằng dạng văn bản rõ) bằng `NSEC3`: Bản ghi mã hóa tên miền dưới dạng hàm băm lặp với chuỗi Salt ngẫu nhiên (`Hashed Authenticated Denial of Existence`), bảo vệ quyền riêng tư của cấu trúc mạng nội bộ.

#### 3.4 Bổ Sung Tính Bí Mật Cho Đường Truyền Cuối (Last-Mile Encryption)
- Bản thân DNSSEC không mã hóa nội dung truy vấn. Để bảo vệ quyền riêng tư của người dùng trước sự theo dõi của nhà mạng hoặc kẻ nghe lén Wi-Fi công cộng, cần kết hợp DNSSEC với các giao thức mã hóa kênh truyền tầng giao vận:
  - **DNS over TLS (DoT - RFC 7858 - Port 853)**
  - **DNS over HTTPS (DoH - RFC 8484 - Port 443)**

---

### 4. Giải Đáp Chi Tiết Câu Hỏi Ôn Tập (Review Questions)

#### Câu 1: Nêu chức năng của từng bản ghi: DNSKEY, RRSIG, DS. Chuỗi tin cậy (chain of trust) hình thành thế nào?
- **Chức năng của từng loại bản ghi DNSSEC:**
  - **`DNSKEY` (DNS Public Key):** Chứa khóa công khai của vùng tên miền. Bản ghi này gồm hai loại:
    - *Key Signing Key (KSK - Flag 257):* Dùng để ký và xác thực tính hợp lệ của chính các bản ghi `DNSKEY`.
    - *Zone Signing Key (ZSK - Flag 256):* Dùng để sinh chữ ký số cho tất cả các bản ghi dữ liệu khác trong vùng (`A`, `CNAME`, `MX`,...).
  - **`RRSIG` (Resource Record Signature):** Chứa chữ ký số mật mã cho một tập bản ghi tài nguyên (RRset). Nó bao gồm các trường: thuật toán mã hóa, thời hạn hợp lệ của chữ ký (Inception và Expiration dates), nhãn, và khối dữ liệu chữ ký số được tạo bởi Private Key tương ứng.
  - **`DS` (Delegation Signer):** Chứa mã băm (fingerprint/hash) của khóa KSK thuộc vùng con, nhưng lại được lưu trữ và ký số tại vùng cha (Parent Zone). Bản ghi này đóng vai trò là "chứng chỉ ủy quyền" mà vùng cha cấp cho vùng con.
- **Cách thức hình thành Chuỗi tin cậy (Chain of Trust):**
  1. Resolver bắt đầu từ một **Neo tin cậy (Trust Anchor)** đã biết trước (khóa KSK của Root Zone `.`).
  2. Resolver truy vấn khóa `DNSKEY` của vùng con kế tiếp (ví dụ `.test`) và bản ghi `DS` tương ứng nằm ở Root Zone.
  3. Resolver xác nhận xem bản băm của khóa KSK vùng con có khớp với bản ghi `DS` đã được ký bởi Root hay không. Nếu khớp, khóa của vùng con trở thành nút tin cậy hợp lệ tiếp theo.
  4. Quá trình này được lặp lại liên tục theo từng cấp phân tầng (`Root` $\rightarrow$ `TLD .test` $\rightarrow$ `Second-level Domain lab.test`).
  5. Cuối cùng, khóa KSK của `lab.test` xác thực khóa ZSK của `lab.test`, và khóa ZSK này xác thực bản ghi `RRSIG` của bản ghi cần tìm (`www.lab.test`). Bất kỳ mắt xích nào bị đứt gãy hoặc sai lệch chữ ký đều khiến toàn bộ chuỗi bị từ chối.

#### Câu 2: Cờ AD trong phản hồi dig nghĩa là gì? Khác với cờ AA ra sao?
- **Ý nghĩa của cờ `AD` (Authenticated Data):**
  - Cờ `ad` (bit thứ 5 trong DNS Header Flags, RFC 4035) được thiết lập bởi **Máy chủ đệ quy phân giải (Validating Recursive Resolver)** gửi về cho Client.
  - Cờ này khẳng định rằng: Toàn bộ dữ liệu trong phần trả lời (Answer) và phần ủy quyền (Authority) đã được Resolver kiểm tra chữ ký mật mã thành công thông qua chuỗi tin cậy DNSSEC hợp lệ.
- **Phân biệt cờ `AD` và cờ `AA` (Authoritative Answer):**
  | Tiêu chí | Cờ `AA` (Authoritative Answer) | Cờ `AD` (Authenticated Data) |
  | :--- | :--- | :--- |
  | **Bên thiết lập** | Được thiết lập bởi **Máy chủ có thẩm quyền (Authoritative Name Server)** quản lý chính thức vùng đó. | Được thiết lập bởi **Máy chủ đệ quy (Validating Recursive Resolver)** sau khi kiểm chứng chữ ký. |
  | **Ý nghĩa** | Báo cho client biết câu trả lời đến trực tiếp từ nguồn quản lý dữ liệu gốc, không phải từ bộ nhớ đệm (cache). | Báo cho client biết dữ liệu đã được **chứng thực toàn vẹn bằng mật mã học DNSSEC**, không bị giả mạo. |
  | **Khả năng bị làm giả** | **Dễ bị làm giả:** Một kẻ tấn công giả mạo DNS response có thể tùy ý bật bit `AA=1` để lừa client. | **Không thể làm giả:** Resolver chỉ bật cờ `AD` khi đã tự mình tính toán và giải mã khớp chữ ký toán học với Trust Anchor. |

#### Câu 3: Ở Bước 5.3, vì sao resolver trả về SERVFAIL thay vì trả bản ghi giả? Điều gì đã bị thiếu/không hợp lệ?
- **Vì sao resolver trả về mã lỗi `SERVFAIL` (Server Failure):**
  - Trong Bước 5.3, Resolver Unbound được chuyển hướng sang hỏi máy chủ giả mạo (Rogue DNS Server tại `10.0.0.66`).
  - Máy chủ Rogue trả về bản ghi địa chỉ giả mạo `www.lab.test -> 6.6.6.6`.
  - Tuy nhiên, Resolver Unbound là một Validating Resolver đang nắm giữ Trust Anchor của vùng `lab.test`. Resolver yêu cầu phải có bằng chứng chữ ký số hợp lệ kèm theo để chấp nhận bản ghi.
  - Vì dữ liệu từ máy chủ giả mạo không thể vượt qua bước thẩm định mật mã, cơ chế an toàn nghiêm ngặt của DNSSEC quy định Resolver tuyệt đối không được chuyển dữ liệu không đáng tin cậy cho người dùng, mà bắt buộc phải trả về mã lỗi hệ thống **`SERVFAIL`** để bảo vệ an toàn cho ứng dụng của người dùng cuối.
- **Những gì đã bị thiếu hoặc không hợp lệ:**
  1. **Thiếu bản ghi chữ ký `RRSIG` hợp lệ:** Máy chủ Rogue không sở hữu Private Key của vùng `lab.test` nên không thể sinh ra bản ghi `RRSIG` tương ứng cho địa chỉ giả `6.6.6.6`.
  2. **Chữ ký không khớp với Trust Anchor:** Nếu máy chủ Rogue tự sinh một cặp khóa giả mạo khác để ký, thì khóa công khai `DNSKEY` do Rogue cung cấp sẽ có bản băm toán học không trùng khớp với khóa `DNSKEY 257` đã được nạp làm neo tin cậy trong tệp `/tmp/trust-anchor.key` của Resolver.

#### Câu 4: DNSSEC bảo vệ toàn vẹn & xác thực nguồn gốc nhưng KHÔNG cung cấp tính bí mật. Giải thích và nêu giải pháp bổ sung.
- **Giải thích vì sao DNSSEC không cung cấp tính bí mật (Confidentiality):**
  - Bản chất thiết kế của DNSSEC (RFC 4033) chỉ tập trung giải quyết hai bài toán bảo mật:
    1. **Tính toàn vẹn dữ liệu (Data Integrity):** Dữ liệu không bị chỉnh sửa trên đường truyền.
    2. **Xác thực nguồn gốc (Origin Authentication):** Dữ liệu chắc chắn xuất phát từ đúng chủ sở hữu tên miền.
  - DNSSEC thực hiện điều này bằng cách thêm vào các chữ ký số công khai (`RRSIG`). Tuy nhiên, **toàn bộ nội dung của các bản ghi DNS (tên miền truy vấn, địa chỉ IP trả về) và gói tin trao đổi vẫn được truyền tải dưới dạng văn bản rõ (Plaintext)** qua cổng UDP/TCP 53.
  - Bất kỳ ai nằm trên đường truyền (nhà mạng ISP, quản trị Wi-Fi, kẻ nghe lén mạng, cơ quan giám sát) đều có thể nhìn thấy rõ người dùng đang truy cập trang web nào (ví dụ đang truy vấn `benhvien.vn` hay `taichinh.com`). Do đó, DNSSEC hoàn toàn không bảo vệ quyền riêng tư của người dùng.
- **Giải pháp bảo mật bổ sung:**
  Để đạt được tính bí mật cho thông tin phân giải tên miền, người dùng và tổ chức bắt buộc phải kết hợp đồng thời DNSSEC với các công nghệ mã hóa đường truyền:
  1. **DNS over TLS (DoT - RFC 7858):** Đóng gói toàn bộ luồng trao đổi DNS bên trong một đường hầm mã hóa TLS sử dụng cổng riêng biệt `853`.
  2. **DNS over HTTPS (DoH - RFC 8484):** Đóng gói truy vấn DNS vào giao thức HTTP/2 hoặc HTTP/3 được mã hóa HTTPS qua cổng `443`, giúp ngụy trang lưu lượng DNS lẫn vào lưu lượng lướt web thông thường.
  - *Mô hình hoàn hảo:* Dùng DoH/DoT để mã hóa chặng kết nối giữa Client và Resolver (bảo mật tính riêng tư), kết hợp DNSSEC giữa Resolver và Authoritative Server (bảo đảm tính toàn vẹn và xác thực nguồn gốc dữ liệu).

#### Câu 5: Phân biệt hai mối đe dọa: DNS cache poisoning (Kaminsky) và DNS spoofing trên đường truyền. DNSSEC chống được cái nào?
- **Phân biệt hai mối đe dọa:**
  | Tiêu chí | DNS Cache Poisoning (Kaminsky Attack) | DNS Spoofing trên đường truyền (On-path DNS Spoofing) |
  | :--- | :--- | :--- |
  | **Vị trí kẻ tấn công** | Thường là **Off-path** (ngoài luồng), không cần nằm trên tuyến cáp truyền tải giữa Resolver và Root/Authoritative Server. | Là **On-path** hoặc **Man-in-the-Middle** (nằm cùng mạng LAN bị nhiễm độc ARP, kiểm soát bộ phát Wi-Fi, hoặc kiểm soát router trung gian). |
  | **Kỹ thuật thực hiện** | Gửi hàng loạt truy vấn ngẫu nhiên kết hợp bắn phá các phản hồi giả mạo để dò đoán (brute-force) trường Transaction ID (16-bit) và Source Port của Resolver. | Kẻ tấn công bắt được trực tiếp gói tin truy vấn DNS thật bay qua card mạng, đọc chính xác TXID và Source Port, sau đó tức tốc phát gói phản hồi giả mạo tới trước khi gói của server thật kịp về. |
  | **Mục tiêu bị tấn công** | Tấn công trực tiếp vào **Máy chủ phân giải đệ quy (Recursive Resolver)** của cơ quan, trường học hoặc ISP. | Tấn công trực tiếp vào **Máy trạm người dùng cuối (Client Host)** trong một mạng cục bộ cụ thể. |
  | **Phạm vi ảnh hưởng** | **Cực kỳ lớn:** Khi Resolver bị nhiễm độc, hàng nghìn đến hàng triệu người dùng sử dụng Resolver đó đều sẽ bị điều hướng sang trang web giả mạo trong suốt thời gian TTL của bản ghi độc hại. | **Cục bộ:** Chỉ ảnh hưởng tới các nạn nhân kết nối qua cùng switch hoặc router bị kẻ tấn công chiếm quyền. |
- **DNSSEC chống được cái nào?**
  - **DNSSEC CHỐNG ĐƯỢC CẢ HAI MỐI ĐE DỌA NÀY.**
  - **Cơ chế chống:**
    - Đối với **DNS Cache Poisoning**: Dù kẻ tấn công có đoán trúng Transaction ID và Source Port để đưa gói tin vào Resolver trước, Resolver vẫn kiểm tra chữ ký `RRSIG`. Vì kẻ tấn công không thể giả mạo khóa bí mật toán học của vùng tên miền, chữ ký số sẽ không thể giải mã được với Trust Anchor $\rightarrow$ Resolver từ chối lưu vào bộ đệm, cuộc tấn công thất bại hoàn toàn.
    - Đối với **On-path DNS Spoofing**: Dù kẻ tấn công đứng giữa bắt được toàn bộ gói tin và phản hồi ngay lập tức với đúng TXID và Port, gói tin phản hồi của kẻ tấn công vẫn không có chữ ký hợp lệ $\rightarrow$ Phía nhận (nếu có kích hoạt kiểm tra DNSSEC) sẽ lập tức phát hiện bản ghi bị làm giả và hủy bỏ gói tin ngay lập tức.

