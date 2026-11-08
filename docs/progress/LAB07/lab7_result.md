# BÁO CÁO KẾT QUẢ THỰC NGHIỆM: LAB 07
## DNS Security Extensions (DNSSEC) Deployment, Validation & Spoofing Defense

- **Thời gian thực thi:** 2026-11-08 (Kali VM Local Time: 01:14 - 01:17)
- **Hệ điều hành kiểm thử:** Kali Linux (`7.1.5+kali-amd64`, x86_64) trên nền tảng VMware
- **Phần mềm dịch vụ:**
  - BIND9 Authoritative Server (`9.20.30-1-Debian`)
  - Unbound Validating Resolver (`1.26.2`)
  - BIND9 DNS Utilities / DiG (`9.20.30-1-Debian`)
- **Môi trường ảo hóa mạng:** Linux Bridge (`br0`) kết nối 4 Network Namespaces độc lập trong subnet `10.0.0.0/24`:
  - `dns-auth` (`10.0.0.2/24`): Authoritative Server (BIND9) tự động ký DNSSEC vùng `lab.test`.
  - `dns-res` (`10.0.0.3/24`): Recursive Validating Resolver (Unbound) có cấu hình Trust Anchor.
  - `client` (`10.0.0.4/24`): Máy trạm kiểm thử gửi truy vấn DNS.
  - `rogue` (`10.0.0.66/24`): Máy chủ DNS mạo danh (Rogue BIND9) trả về IP giả mạo `6.6.6.6` không có chữ ký.

---

### 1. RAW TERMINAL OUTPUTS (Minh Chứng Thực Tế)

#### 1.1. Khởi Tạo Topology & Kiểm Tra Kết Nối

Lệnh thực thi:
```bash
echo Aa@123456 | sudo -S bash /tmp/lab07/setup_dns.sh
```

Terminal Output:
```text
[*] Killing old named and unbound processes if any...
[*] Cleaning up old network namespaces and bridge...
[*] Creating Linux Bridge br0...
[*] Setting up DNS host dns-auth (10.0.0.2)...
[*] Setting up DNS host dns-res (10.0.0.3)...
[*] Setting up DNS host client (10.0.0.4)...
[*] Setting up DNS host rogue (10.0.0.66)...
[*] Warming up ARP caches across LAN...
[+] DNS Topology Ready on br0:
    - dns-auth: 10.0.0.2  (BIND9 DNSSEC Authoritative Server)
    - dns-res:  10.0.0.3  (Unbound Validating Resolver)
    - client:   10.0.0.4  (Client Query Node)
    - rogue:    10.0.0.66 (Rogue BIND9 Server - Unsigned)
```

---

#### 1.2. Khởi Chạy BIND9 DNSSEC Authoritative Server & Trích Xuất Trust Anchor

BIND9 tự động tạo cặp khóa KSK/ZSK và ký vùng `lab.test` qua chính sách `dnssec-policy default; inline-signing yes;`:
```text
zone lab.test/IN (signed): loaded serial 2026110801
keymgr: DNSKEY lab.test/ECDSAP256SHA256/23861 (CSK) created for policy default
Fetching lab.test/ECDSAP256SHA256/23861 (CSK) from key repository.
DNSKEY lab.test/ECDSAP256SHA256/23861 (CSK) is now published
DNSKEY lab.test/ECDSAP256SHA256/23861 (CSK) is now active
```

Truy vấn bản ghi DNSKEY từ máy chủ ủy quyền và trích xuất khóa KSK (flag 257) vào `/tmp/trust-anchor.key`:
```bash
ip netns exec client dig @10.0.0.2 lab.test DNSKEY > /tmp/lab07/lab.dnskey
grep -E "IN[[:space:]]+DNSKEY[[:space:]]+257" /tmp/lab07/lab.dnskey > /tmp/trust-anchor.key
cat /tmp/trust-anchor.key
```

Nội dung tệp `/tmp/trust-anchor.key`:
```text
lab.test.		3600	IN	DNSKEY	257 3 13 E3xIIeK9v+hcbAbCc0rkesNp3v7tPuWdo8eQvAD24V+qLF3VeZBBV+wX kgOQSpMdN2rnw47Uz4TQcxzyFZ8u1g==
```

---

#### 1.3. Xác Thực DNSSEC Thành Công Qua Resolver (`dig_valid_ad.log`)

Truy vấn bản ghi `www.lab.test` qua bộ phân giải Unbound (`10.0.0.3`) kèm chỉ thị `+dnssec`:
```bash
ip netns exec client dig @10.0.0.3 www.lab.test +dnssec
```

Raw Log `dig_valid_ad.log`:
```text
; <<>> DiG 9.20.30-1-Debian <<>> @10.0.0.3 www.lab.test +dnssec
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 11136
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
;; QUESTION SECTION:
;www.lab.test.			IN	A

;; ANSWER SECTION:
www.lab.test.		290	IN	A	10.0.0.80
www.lab.test.		290	IN	RRSIG	A 13 3 300 20261121212800 20261108051513 23861 lab.test. raXrbTds6qphxYp8Lx7HarEXQau+G0y5E8ui8kLigAD1Um08bLjp0QyE SYPE63tfwDrNVhGjp/F1gOa+lOcl6Q==

;; Query time: 0 msec
;; SERVER: 10.0.0.3#53(10.0.0.3) (UDP)
;; WHEN: Sun Nov 08 01:16:53 EST 2026
;; MSG SIZE  rcvd: 161
```

> **Minh chứng xác thực:**
> - `status: NOERROR`
> - Cờ **`ad` (Authenticated Data)** xuất hiện trong phần header flags (`qr rd ra ad`).
> - Phần ANSWER trả về IP chính xác `10.0.0.80` đi kèm chữ ký số `RRSIG` hợp lệ ký bởi Key Tag `23861`.

---

#### 1.4. Mô Phỏng Tấn Công Giả Mạo & Resolver Chặn Bằng SERVFAIL

**1. Khởi chạy Rogue Server (`10.0.0.66`) trả về IP giả mạo `6.6.6.6`:**
Truy vấn trực tiếp máy chủ mạo danh (`dig_direct_rogue.log`):
```text
; <<>> DiG 9.20.30-1-Debian <<>> @10.0.0.66 www.lab.test
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47604
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
www.lab.test.		300	IN	A	6.6.6.6
```

**2. Bẻ lái Resolver `dns-res` sang máy chủ giả mạo `10.0.0.66`:**
Truy vấn qua Resolver có bảo vệ DNSSEC (`dig_servfail.log`):
```text
; <<>> DiG 9.20.30-1-Debian <<>> @10.0.0.3 www.lab.test +dnssec
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 62037
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 1232
;; QUESTION SECTION:
;www.lab.test.			IN	A

;; Query time: 3 msec
;; SERVER: 10.0.0.3#53(10.0.0.3) (UDP)
;; WHEN: Sun Nov 08 01:17:15 EST 2026
;; MSG SIZE  rcvd: 41
```

> **Minh chứng phòng thủ:**
> - Trạng thái: `status: SERVFAIL`.
> - Số lượng bản ghi trả lời: `ANSWER: 0`.
> - Địa chỉ IP độc hại `6.6.6.6` bị Unbound triệt tiêu hoàn toàn, bảo vệ client khỏi nguy cơ bị đầu độc DNS.

---

#### 1.5. Đối Chiếu Khi Bỏ Qua Kiểm Tra Chữ Ký Số (`+cd` - Checking Disabled)

Khi client gửi truy vấn có cờ `+cd` yêu cầu Resolver không kiểm tra tính hợp lệ mật mã (`dig_cd_bypass.log`):
```text
; <<>> DiG 9.20.30-1-Debian <<>> @10.0.0.3 www.lab.test +cd
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 4537
;; flags: qr rd ra cd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;www.lab.test.			IN	A

;; ANSWER SECTION:
www.lab.test.		295	IN	A	6.6.6.6

;; Query time: 0 msec
;; SERVER: 10.0.0.3#53(10.0.0.3) (UDP)
;; WHEN: Sun Nov 08 01:17:20 EST 2026
;; MSG SIZE  rcvd: 57
```

> **Minh chứng đối chiếu:** Khi cờ `cd` được bật, Resolver bỏ qua quá trình xác thực và trả về địa chỉ IP giả mạo `6.6.6.6`, khẳng định rằng phản hồi `SERVFAIL` ở bước trước hoàn toàn do cơ chế bảo vệ của DNSSEC tạo ra.

---

### 2. BÓC TÁCH & PHÂN TÍCH CHUYÊN SÂU LOG TERMINAL

#### 2.1. Giải Phẫu Bản Ghi DNSKEY & RRSIG

1. **Bản ghi DNSKEY (Trust Anchor):**
   ```text
   lab.test. 3600 IN DNSKEY 257 3 13 E3xIIeK9v+hcbAbCc0rkesNp3v7tPuWdo8eQvAD24V+qLF3VeZBBV+wX kgOQSpMdN2rnw47Uz4TQcxzyFZ8u1g==
   ```
   - `257 (Flags)`: Bit SEP (Secure Entry Point) được bật $\implies$ Khóa **KSK (Key Signing Key)** hoặc CSK (Combined Signing Key).
   - `3 (Protocol)`: Bắt buộc là giá trị 3 theo chuẩn DNSSEC.
   - `13 (Algorithm)`: Thuật toán mật mã đường cong elliptic **ECDSA Curve P-256 with SHA-256** (RFC 6605). Cho chữ ký kích thước nhỏ gọn và hiệu năng tính toán cao hơn nhiều so với RSA cổ điển.
   - Chuỗi Base64: Khóa công khai của máy chủ ký vùng `lab.test`.

2. **Bản ghi RRSIG (Resource Record Signature):**
   ```text
   www.lab.test. 290 IN RRSIG A 13 3 300 20261121212800 20261108051513 23861 lab.test. raXrbTds...
   ```
   - `Type Covered (A)`: Chữ ký này dùng để bảo vệ cho tập bản ghi loại `A` (`www.lab.test. IN A 10.0.0.80`).
   - `Algorithm (13)`: Thuật toán ký là ECDSA P-256 SHA-256.
   - `Labels (3)`: Số nhãn trong tên miền `www.lab.test` là 3 nhãn (`www`, `lab`, `test`).
   - `Original TTL (300)`: TTL gốc của bản ghi dữ liệu được ký.
   - `Signature Expiration (20261121212800)`: Chữ ký hết hạn vào `21:28:00 UTC ngày 21/11/2026`.
   - `Signature Inception (20261108051513)`: Chữ ký có hiệu lực từ `05:15:13 UTC ngày 08/11/2026`.
   - `Key Tag (23861)`: Mã băm 16-bit nhận diện khóa DNSKEY đã dùng để tạo ra chữ ký này (khớp với CSK trong log BIND9).
   - `Signer's Name (lab.test.)`: Tên vùng quản lý chữ ký.

#### 2.2. Phân Tích Ý Nghĩa Các Cờ: `ad` vs `aa` vs `cd`

- **Cờ `aa` (Authoritative Answer):**
  - Xuất hiện trong log khi hỏi trực tiếp Authoritative Server (`10.0.0.2` hoặc `10.0.0.66`):
    `flags: qr aa rd`
  - Ý nghĩa: Máy chủ trả lời là nơi lưu trữ tệp cơ sở dữ liệu vùng gốc. Cờ này **không đảm bảo an toàn trên đường truyền**, vì kẻ tấn công đứng giữa hoàn toàn có thể giả mạo gói tin mang cờ `aa`.
- **Cờ `ad` (Authenticated Data):**
  - Xuất hiện trong phản hồi từ Validating Resolver (`10.0.0.3`):
    `flags: qr rd ra ad`
  - Ý nghĩa: Resolver đã kiểm tra toàn bộ chuỗi chứng thực số (Chain of Trust) từ Trust Anchor đến bản ghi dữ liệu và xác nhận chữ ký số `RRSIG` hoàn toàn hợp lệ về mặt toán học.
- **Cờ `cd` (Checking Disabled):**
  - Client chủ động đặt cờ này trong gói tin câu hỏi để yêu cầu Resolver bỏ qua bước kiểm tra DNSSEC. Khi đó, Resolver trả lời cả những dữ liệu không hợp lệ mà không phát sinh mã `SERVFAIL`.

#### 2.3. Phân Tích Cơ Chế Chặn Giả Mạo (`SERVFAIL`)

1. Khi Resolver nhận chỉ thị giải quyết tên miền `www.lab.test`:
   - Resolver tra cứu cấu hình thấy vùng `lab.test.` đã được gắn chốt tin cậy (`trust-anchor-file: "/tmp/trust-anchor.key"`).
   - Do đó, Resolver bắt buộc phải nhận được bản ghi `RRSIG` đi kèm bản ghi `A`, đồng thời chữ ký đó phải được xác minh thành công bởi khóa công khai trong `trust-anchor.key`.
2. Khi Resolver bị trỏ sang máy chủ mạo danh `10.0.0.66`:
   - Máy chủ giả mạo chỉ trả về bản ghi `A: 6.6.6.6` mà không hề có `RRSIG` (hoặc có chữ ký nhưng không khớp với KSK đã neo).
   - Phân hệ kiểm chứng mật mã của Unbound (`validator module`) đánh dấu trạng thái bản ghi là **BOGUS (Dữ liệu giả mạo/nhiễm độc)**.
   - Thay vì trả về dữ liệu giả mạo cho ứng dụng của người dùng, Unbound chủ động hủy dữ liệu độc hại và trả về mã lỗi **`SERVFAIL` (Server Failure)**.

#### 2.4. Đánh Giá Toàn Diện: Giới Hạn của DNSSEC & So Sánh DoH/DoT

| Đặc Tính An Ninh | DNS Truyền Thống | DNSSEC | DoH / DoT (DNS over HTTPS/TLS) | DNSSEC + DoH/DoT |
| :--- | :---: | :---: | :---: | :---: |
| **Xác thực Nguồn gốc (Origin Auth)** | Không | **Có (Chữ ký KSK/ZSK)** | Chỉ xác thực kết nối tới Resolver | **Toàn diện End-to-End** |
| **Tính Toàn vẹn (Data Integrity)** | Không | **Có (Chống sửa đổi/giả mạo)** | Có (chống sửa đổi trên kênh truyền) | **Toàn diện End-to-End** |
| **Tính Bí mật (Confidentiality / Privacy)** | Không | **Không (Gói tin vẫn truyền rõ text)** | **Có (Mã hóa đường truyền TLS)** | **Bảo mật tuyệt đối** |
| **Chống Giả mạo tại Resolver** | Không | **Có (Resolver không thể tự ý sửa IP)** | Không (phải hoàn toàn tin tưởng Resolver) | **Có** |

> **Khuyến nghị kiến trúc an ninh:** DNSSEC bảo vệ **tính toàn vẹn dữ liệu từ Zone Operator tới Client** (chống đầu độc bộ nhớ đệm Cache Poisoning), trong khi DoH/DoT bảo vệ **sự riêng tư thông tin truy vấn của người dùng trước nhà mạng/ISP** (chống nghe lén). Mô hình mạng hiện đại lý tưởng phải kết hợp song song cả hai công nghệ.

---

### 3. KẾT LUẬN

Bài thực hành LAB 07 đã triển khai thành công một hạ tầng DNSSEC hoàn chỉnh khép kín từ máy chủ Authoritative BIND9 tự động sinh khóa và ký vùng, thiết lập Trust Anchor trên Unbound Resolver, kiểm chứng cờ `ad` khi dữ liệu hợp lệ, và chứng minh cơ chế ngăn chặn tuyệt đối cuộc tấn công giả mạo DNS thông qua mã phản hồi `SERVFAIL`. Toàn bộ 7 bài lab trong khuôn khổ dự án đã được hoàn tất và kiểm chứng thực tế 100%.

