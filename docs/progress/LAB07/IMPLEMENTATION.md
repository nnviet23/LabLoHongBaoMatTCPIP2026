# TÀI LIỆU KỸ THUẬT & KIẾN TRÚC THỰC THI: LAB 07
## DNS Security Extensions (DNSSEC) Architecture & Cryptographic Validation

---

### 1. TỔNG QUAN KIẾN TRÚC MÔ HÌNH THỰC NGHIỆM

```
                     +---------------------------------------+
                     |           Linux Bridge br0            |
                     |         Subnet 10.0.0.0/24            |
                     +---+---------------+---------------+---+
                         |               |               |
                         v               v               v
                   +-----------+   +-----------+   +-----------+
                   |  client   |   |  dns-res  |   | dns-auth  |
                   | 10.0.0.4  |   | 10.0.0.3  |   | 10.0.0.2  |
                   +-----------+   +-----------+   +-----------+
                     (Querier)      (Validating)     (Signed)
                                         |
                                         | (Khi bị bẻ lái)
                                         v
                                   +-----------+
                                   |   rogue   |
                                   | 10.0.0.66 |
                                   +-----------+
                                    (Unsigned)
```

- **Môi trường cách ly:** 4 Linux Network Namespaces kết nối qua Linux Bridge `br0`:
  - `dns-auth` (`10.0.0.2`): Máy chủ Authoritative chạy BIND9, bật ký tự động DNSSEC (inline-signing).
  - `dns-res` (`10.0.0.3`): Máy chủ Recursive Resolver chạy Unbound, nạp KSK của `lab.test` làm Trust Anchor.
  - `client` (`10.0.0.4`): Máy trạm phát lệnh truy vấn `dig`.
  - `rogue` (`10.0.0.66`): Máy chủ BIND9 giả mạo trả về bản ghi chưa ký `6.6.6.6`.

---

### 2. CƠ CHẾ MẬT MÃ CỦA DNSSEC & CHUỖI TIN CẬY (CHAIN OF TRUST)

#### 2.1. Các Bản Ghi Tài Nguyên DNSSEC Cốt Lõi

1. **DNSKEY (DNS Public Key):**
   - Chứa khóa công khai được sử dụng để xác thực chữ ký số trong vùng.
   - **KSK (Key Signing Key - Flag 257):** Khóa dùng để ký chính tập bản ghi `DNSKEY` của vùng đó. Bản ghi băm của KSK được gửi lên vùng cha (Parent Zone) dưới dạng bản ghi DS để thiết lập Chain of Trust.
   - **ZSK (Zone Signing Key - Flag 256):** Khóa dùng để ký các tập bản ghi dữ liệu thông thường (`A`, `AAAA`, `MX`, `TXT`) trong vùng.
   - **CSK (Combined Signing Key):** Trong BIND 9.16+, chính sách mặc định gộp cả hai vai trò vào một khóa duy nhất với cờ `257` (sử dụng thuật toán hiện đại ECDSA Curve P-256).
2. **RRSIG (Resource Record Signature):**
   - Chứa chữ ký số mật mã cho một tập bản ghi (RRset). Mỗi khi vùng được cập nhật, BIND9 tự động sinh ra bản ghi `RRSIG` tương ứng.
3. **DS (Delegation Signer):**
   - Chứa mã băm SHA-256 của khóa KSK, được đặt tại vùng cha (ví dụ `.test` hoặc `.`) nhằm liên kết tính tin cậy từ cấp cao xuống cấp thấp.
4. **NSEC / NSEC3 (Next Secure):**
   - Cung cấp chứng minh có mật mã về sự không tồn tại của một tên miền (Authenticated Denial of Existence), ngăn chặn kẻ tấn công giả mạo trả lời NXDOMAIN.

#### 2.2. Luồng Xác Thực Mật Mã (Cryptographic Validation Flow)

```
[Trust Anchor: /tmp/trust-anchor.key]
                 |
                 v (Khóa KSK công khai: Key Tag 23861)
       [Xác minh RRSIG của tập DNSKEY]
                 |
                 v (Trích xuất Khóa ZSK)
       [Xác minh RRSIG của tập bản ghi www.lab.test A]
                 |
        +--------+--------+
        |                 |
  (Chữ ký Hợp lệ)    (Chữ ký Sai / Thiếu)
        |                 |
        v                 v
   [Bật cờ `ad`]     [Trả về `SERVFAIL`]
   [status: NOERROR] [Hủy IP độc hại 6.6.6.6]
```

---

### 3. CẤU HÌNH DỊCH VỤ CHI TIẾT

#### 3.1. Cấu hình BIND9 Authoritative Server (`named-auth.conf`)

```text
options {
    directory "/var/cache/bind";
    listen-on { 10.0.0.2; };
    listen-on-v6 { none; };
    allow-query { any; };
    recursion no;
    key-directory "/var/cache/bind/keys";
};

zone "lab.test" {
    type primary;
    file "/var/cache/bind/db.lab.test";
    dnssec-policy default;
    inline-signing yes;
};
```

- `dnssec-policy default;`: Kích hoạt cơ chế tự động quản lý vòng đời khóa (Key Lifecycle Management) của BIND9, tự động sinh khóa ECDSA P-256.
- `inline-signing yes;`: Giữ nguyên tệp dữ liệu vùng gốc `db.lab.test` ở dạng văn bản thuần, và lưu trữ các bản ghi ký số trong cơ sở dữ liệu động `.signed`.

#### 3.2. Cấu hình Unbound Validating Resolver (`unbound.conf`)

```text
server:
    verbosity: 1
    interface: 10.0.0.3
    port: 53
    do-ip4: yes
    do-udp: yes
    do-tcp: yes
    access-control: 0.0.0.0/0 allow
    chroot: ""
    username: ""
    trust-anchor-file: "/tmp/trust-anchor.key"
    local-zone: "test." transparent
    local-zone: "lab.test." transparent

stub-zone:
    name: "lab.test"
    stub-addr: 10.0.0.2
```

- `trust-anchor-file: "/tmp/trust-anchor.key"`: Khai báo mỏ neo tin cậy cục bộ chứa bản ghi KSK (DNSKEY 257). Unbound sử dụng khóa này làm gốc tin cậy tuyệt đối cho mọi tên miền kết thúc bằng `lab.test`.
- `local-zone: "test." transparent`: Vượt qua cơ chế chặn mặc định đối với các tên miền đặc biệt theo chuẩn RFC 6761 (Unbound mặc định trả về NXDOMAIN cho TLD `.test`).

---

### 4. PHÂN TÍCH TÁC ĐỘNG BẢO VỆ TRƯỚC CÁC CUỘC TẤN CÔNG

1. **DNS Cache Poisoning / Kaminsky Attack:**
   - Kẻ tấn công bơm bản ghi IP giả mạo vào bộ đệm của Resolver.
   - Với DNSSEC: Bất kỳ bản ghi nào không đi kèm chữ ký `RRSIG` được ký bởi ZSK hợp lệ đều bị Resolver gắn cờ `BOGUS` và hủy ngay lập tức $\rightarrow$ Kaminsky Attack hoàn toàn bất khả thi.
2. **Authoritative Server Impersonation (Rogue Server):**
   - Kẻ tấn công chiếm quyền định tuyến (BGP Hijacking / ICMP Redirect) để chuyển tiếp truy vấn tới máy chủ DNS giả mạo `10.0.0.66`.
   - Với DNSSEC: Do kẻ tấn công không sở hữu khóa bí mật KSK/ZSK tương ứng với Trust Anchor đã nạp trên Resolver, Resolver phát hiện thiếu chữ ký và trả về `SERVFAIL` cho client, ngăn ngừa việc người dùng truy cập vào trang web lừa đảo.

