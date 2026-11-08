# HƯỚNG DẪN TRIỂN KHAI & PHÂN TÍCH KỸ THUẬT: LAB 07
## DNS Security Extensions (DNSSEC) Deployment & Spoofing Defense

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG

#### 1.1 Mục Tiêu & Cơ Sở Lý Thuyết
- **Điểm yếu của DNS truyền thống (RFC 1035 / Dan Kaminsky 2008):** Hệ thống DNS nguyên thủy giao tiếp qua UDP cổng 53 không có cơ chế xác thực nguồn gốc (Origin Authentication) hay bảo vệ tính toàn vẹn (Data Integrity). Kẻ tấn công có thể giả mạo gói tin DNS Response với Transaction ID (TXID) phỏng đoán để đầu độc bộ nhớ đệm (DNS Cache Poisoning / Spoofing), chuyển hướng người dùng tới các trang web lừa đảo.
- **Kiến trúc phòng thủ DNSSEC (RFC 4033, 4034, 4035):** DNSSEC tích hợp chữ ký số bất đối xứng (Public-Key Cryptography) vào hệ thống tên miền:
  - `RRSIG (Resource Record Signature)`: Chữ ký số mã hóa cho từng tập bản ghi (RRset) được ký bởi khóa riêng (Private Key).
  - `DNSKEY`: Bản ghi lưu trữ khóa công khai (Public Key) dùng để giải mã và xác thực chữ ký `RRSIG`.
  - `DS (Delegation Signer)`: Bản ghi băm mật mã của khóa DNSKEY đặt tại vùng cha nhằm thiết lập chuỗi tin cậy liên tục (Chain of Trust).
  - `Trust Anchor`: Khóa công khai gốc được cấu hình tin cậy tuyệt đối tại Resolver để làm điểm tựa xác thực chuỗi chữ ký.
- **Cơ chế phản ứng của Validating Resolver:**
  - Nếu chữ ký hợp lệ: Resolver trả về bản ghi kèm cờ **`ad` (Authenticated Data)**.
  - Nếu bản ghi bị giả mạo hoặc đến từ máy chủ Rogue không có khóa riêng hợp lệ: Quá trình xác thực mật mã thất bại $\rightarrow$ Resolver **hủy bỏ dữ liệu và trả về lỗi `SERVFAIL` (Server Failure)** để bảo vệ người dùng khỏi việc tiếp nhận IP độc hại.
- **Mục tiêu thực nghiệm trong Lab 07:**
  1. Triển khai hạ tầng DNSSEC 4 nút mạng ảo hóa trên Linux Bridge `br0`.
  2. Cấu hình BIND9 (`dns-auth`) tự động sinh cặp khóa ECDSA P-256 (`dnssec-policy default`) và ký vùng `lab.test`.
  3. Trích xuất khóa KSK (flag 257) làm Trust Anchor cho máy chủ Unbound Resolver (`dns-res`).
  4. Thực hiện truy vấn `dig` từ `client` và kiểm chứng cờ `ad` cùng bản ghi `RRSIG`.
  5. Dựng Rogue BIND9 Server (`rogue`) trả về IP giả `6.6.6.6` không ký, bẻ lái Resolver và chứng minh Unbound chặn đứng cuộc tấn công bằng mã lỗi `SERVFAIL` (hoàn toàn không để lọt IP `6.6.6.6` tới client).

#### 1.2 Topology Mạng & Quy Ước Thực Thi
- **Mô hình kết nối:** Mạng LAN chia sẻ trên Linux Bridge `br0` (`10.0.0.0/24`):
  - `[AUTHORITATIVE SERVER - dns-auth]`: `10.0.0.2/24` (BIND9 Server ký DNSSEC cho vùng `lab.test`).
  - `[VALIDATING RESOLVER - dns-res]`: `10.0.0.3/24` (Unbound Resolver kiểm tra tính hợp lệ của chữ ký).
  - `[CLIENT - client]`: `10.0.0.4/24` (Máy trạm kiểm thử gửi truy vấn `dig`).
  - `[ROGUE SERVER - rogue]`: `10.0.0.66/24` (Máy chủ DNS mạo danh trả về IP giả `6.6.6.6`).

> 💡 **Quy ước thực thi lệnh:**
> - `[AUTHORITATIVE SERVER - dns-auth]`: Lệnh chạy trên BIND9 Authoritative Server (tiền tố `ip netns exec dns-auth`).
> - `[VALIDATING RESOLVER - dns-res]`: Lệnh chạy trên Unbound Resolver (tiền tố `ip netns exec dns-res`).
> - `[CLIENT - client]`: Lệnh chạy trên máy trạm kiểm thử (tiền tố `ip netns exec client`).
> - `[ROGUE SERVER - rogue]`: Lệnh chạy trên máy chủ mạo danh Rogue BIND9 (tiền tố `ip netns exec rogue`).
> - `[HOST / CHUNG]`: Lệnh chạy trực tiếp trên máy ảo Kali.

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC TỆP CẤU HÌNH

Trong bước này, ta chuẩn bị 6 tệp cấu hình và kịch bản tại `/tmp/lab07`:

#### 2.1 Kịch Bản `setup_dns.sh` (DNS Network Topology Setup)
- **Tại sao lại đặt tên như vậy?** Đặt tên là `setup_dns` vì kịch bản này tạo toàn bộ topology 4 nút cho hệ sinh thái DNS.
- **Ý nghĩa của script:** Khởi tạo hạ tầng mạng bridge, tắt các tiến trình DNS chạy ngầm của host để tránh xung đột cổng 53, và gán IP cho 4 namespace.
- **Ý chính của script làm gì?**
  1. Tắt sạch các tiến trình `named` và `unbound` cũ bằng `pkill -9`.
  2. Tạo bridge `br0` và 4 host: `dns-auth` (`.2`), `dns-res` (`.3`), `client` (`.4`), `rogue` (`.66`).
  3. Ping khởi động ARP giữa các nút.

#### 2.2 Tệp Cấu Hình BIND9 Thẩm Quyền: `named-auth.conf` & `db.lab.test`
- **Tại sao lại đặt tên như vậy?**
  - `named-auth.conf`: Cấu hình cho daemon `named` đóng vai trò Authoritative Server.
  - `db.lab.test`: Tệp cơ sở dữ liệu vùng (Zone File) cho tên miền `lab.test`.
- **Ý nghĩa kỹ thuật:** Khởi chạy máy chủ nắm giữ bản ghi gốc và kích hoạt tính năng tự động ký DNSSEC của BIND 9.16+.
- **Ý chính của cấu hình:**
  1. `dnssec-policy default;`: Chỉ định chính sách DNSSEC mặc định của BIND9, tự động sinh khóa KSK và ZSK sử dụng thuật toán elliptic curve **ECDSA Curve P-256 with SHA-256** (Algorithm 13).
  2. `inline-signing yes;`: Cho phép BIND9 tự động ký vùng trong nền mà không làm thay đổi trực tiếp file gốc `db.lab.test`.
  3. `db.lab.test`: Định nghĩa bản ghi SOA, NS và bản ghi `www.lab.test. IN A 10.0.0.80`.

#### 2.3 Tệp Cấu Hình Unbound Resolver: `unbound.conf`
- **Tại sao lại đặt tên như vậy?** Tệp cấu hình tiêu chuẩn của phần mềm phân giải tên miền đệ quy Unbound.
- **Ý nghĩa kỹ thuật:** Thiết lập máy chủ Resolver có nhiệm vụ xác thực mật mã các câu trả lời nhận được trước khi chuyển về cho Client.
- **Ý chính của cấu hình:**
  1. `trust-anchor-file: "/tmp/trust-anchor.key";`: Chỉ định tệp chứa khóa công khai tin cậy làm điểm neo xác thực.
  2. `local-zone: "test." transparent;` & `local-zone: "lab.test." transparent;`: **Cấu hình quan trọng:** Theo RFC 6761, Unbound mặc định coi đuôi `.test` là vùng thử nghiệm cục bộ và sẽ chặn không cho phân giải ra ngoài. Thiết lập `transparent` cho phép Unbound tiếp tục chuyển tiếp truy vấn tới Authoritative Server.
  3. `stub-zone`: Chỉ định rõ địa chỉ máy chủ thẩm quyền cho vùng `lab.test` ban đầu là `10.0.0.2`.

#### 2.4 Tệp Cấu Hình Rogue BIND9: `named-rogue.conf` & `db.lab.rogue`
- **Tại sao lại đặt tên như vậy?** Tên gọi `rogue` (mạo danh / độc hại) đại diện cho máy chủ DNS của kẻ tấn công.
- **Ý nghĩa kỹ thuật:** Mô phỏng máy chủ DNS giả mạo trong cuộc tấn công DNS Spoofing / Hijacking.
- **Ý chính của cấu hình:**
  1. Trả về bản ghi `www.lab.test. IN A 6.6.6.6` (địa chỉ IP độc hại).
  2. **Hoàn toàn không có cấu hình DNSSEC:** Kẻ tấn công không sở hữu khóa riêng (Private Key) hợp lệ nên không thể sinh ra chữ ký `RRSIG` khớp với Trust Anchor.

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG & PHÂN QUYỀN APPARMOR

Thực thi thiết lập và cấu hình quyền hạn hệ thống:

```bash
# [HOST / CHUNG] Chạy thiết lập mạng LAN bridge br0
sudo bash /tmp/lab07/setup_dns.sh

# [HOST / CHUNG] Vô hiệu hóa AppArmor cho named và unbound
sudo aa-disable /etc/apparmor.d/usr.sbin.named 2>/dev/null || true
sudo aa-disable /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true

# [HOST / CHUNG] Copy zone file vào /var/cache/bind và cấp quyền ghi
sudo cp /tmp/lab07/db.lab.test /var/cache/bind/db.lab.test
sudo cp /tmp/lab07/db.lab.rogue /var/cache/bind/db.lab.rogue
sudo chmod -R 777 /var/cache/bind /tmp/lab07
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `aa-disable <profile>`:
   - **Giải quyết lỗi then chốt trong thực tế:** Trên hệ điều hành Debian/Ubuntu/Kali, AppArmor là module bảo mật MAC (Mandatory Access Control) kiểm soát chặt chẽ các daemon `named` và `unbound`. Mặc định AppArmor chặn không cho `named` đọc các tệp cấu hình nằm trong `/tmp` hoặc ghi khóa vào thư mục tùy biến. Lệnh `aa-disable` gỡ bỏ hồ sơ kiểm soát tạm thời cho phép hai dịch vụ khởi chạy trơn tru với các tệp cấu hình tùy biến của bài lab.
2. `chmod -R 777 /var/cache/bind /tmp/lab07`:
   - Cấp toàn quyền đọc/ghi cho user `bind` để tiến trình BIND9 có thể sinh khóa mật mã và ghi các tệp ký tự động (`.signed` và `.jbk`).

---

### 4. BƯỚC 3: KHỞI CHẠY BIND9 & TRÍCH XUẤT TRUST ANCHOR

Khởi chạy Authoritative Server và trích xuất khóa công khai KSK:

```bash
# 1. [AUTHORITATIVE SERVER - dns-auth] Khởi chạy BIND9 ký DNSSEC
sudo ip netns exec dns-auth named -u bind -c /tmp/lab07/named-auth.conf -g > /tmp/lab07/named_auth.log 2>&1 &
sleep 4

# 2. [CLIENT - client] Truy vấn DNSKEY và trích xuất khóa KSK vào trust-anchor.key
sudo ip netns exec client dig @10.0.0.2 lab.test DNSKEY | grep -E "IN[[:space:]]+DNSKEY[[:space:]]+257" > /tmp/trust-anchor.key
sudo chmod 666 /tmp/trust-anchor.key
cat /tmp/trust-anchor.key
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `named -u bind -c /tmp/lab07/named-auth.conf -g`:
   - `-u bind`: Chạy daemon dưới danh nghĩa người dùng hệ thống `bind`.
   - `-c <file>`: Chỉ định tệp cấu hình tùy biến.
   - `-g`: Chạy ở chế độ tiền cảnh (foreground) và chuyển toàn bộ nhật ký lỗi chuẩn ra stderr thay vì ghi vào syslog của hệ thống, giúp ta dễ dàng chuyển hướng vào `/tmp/lab07/named_auth.log`.
2. `dig @10.0.0.2 lab.test DNSKEY | grep -E "IN[[:space:]]+DNSKEY[[:space:]]+257"`:
   - `dig @<server> <zone> <type>`: Công cụ truy vấn DNS tiêu chuẩn.
   - `DNSKEY`: Loại bản ghi chứa khóa công khai.
   - **Phân biệt cờ 256 và 257 (RFC 4034):**
     - Cờ `256`: Khóa ký vùng (ZSK - Zone Signing Key), dùng để ký các tập bản ghi nội bộ (RRset A, MX...).
     - Cờ `257`: Khóa ký khóa (KSK - Key Signing Key), dùng để ký chính tập bản ghi DNSKEY và làm cầu nối với vùng cha (hoặc làm Trust Anchor).
     - Bộ lọc `grep ... 257` trích xuất chính xác dòng chứa KSK để đưa vào `/tmp/trust-anchor.key` cho Unbound sử dụng.

---

### 5. BƯỚC 4: KHỞI CHẠY UNBOUND & KIỂM CHỨNG XÁC THỰC THÀNH CÔNG

Khởi chạy Unbound Resolver và thực hiện truy vấn hợp lệ:

```bash
# 1. [VALIDATING RESOLVER - dns-res] Khởi chạy Unbound Resolver trên dns-res
sudo ip netns exec dns-res unbound -c /tmp/lab07/unbound.conf -d > /tmp/lab07/unbound.log 2>&1 &
sleep 2

# 2. [CLIENT - client] Thực hiện truy vấn DNSSEC từ máy trạm client
sudo ip netns exec client dig @10.0.0.3 www.lab.test +dnssec
```

#### Phân Tích Kết Quả Thực Nghiệm (Validation Success):
Kết quả trả về từ `dig`:
```text
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 32145
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
www.lab.test.       300 IN  A       10.0.0.80
www.lab.test.       300 IN  RRSIG   A 13 3 300 20261129... 20261108... 12345 lab.test. kA8...==
```

- **Ý nghĩa cờ `ad` (Authenticated Data):** Đây là dấu hiệu then chốt trong header của gói tin DNS Response. Cờ `ad` khẳng định Resolver đã xác thực thành công toàn bộ chữ ký toán học từ bản ghi `RRSIG` bằng khóa trong `trust-anchor.key`.
- **Phần ANSWER:** Trả về địa chỉ IP chính xác `10.0.0.80` đi kèm bản ghi chữ ký `RRSIG` thuật toán 13 (ECDSA P-256).

---

### 6. BƯỚC 5: MÔ PHỎNG TẤN CÔNG GIẢ MẠO & KIỂM CHỨNG CHẶN BẰNG SERVFAIL

Mô phỏng kịch bản tấn công đầu độc / chiếm quyền: Kẻ tấn công dựng máy chủ mạo danh và Resolver bị chuyển hướng hỏi máy chủ này:

```bash
# 1. [ROGUE SERVER / CLIENT] Khởi chạy Rogue Server (10.0.0.66) và kiểm tra
# [ROGUE SERVER - rogue]
sudo ip netns exec rogue named -u bind -c /tmp/lab07/named-rogue.conf -g > /tmp/lab07/named_rogue.log 2>&1 &
sleep 2
# [CLIENT - client] Hỏi thử trực tiếp máy chủ mạo danh:
sudo ip netns exec client dig @10.0.0.66 www.lab.test +short

# 2. [VALIDATING RESOLVER - dns-res] Bẻ lái Resolver dns-res sang máy chủ giả mạo
sudo sed -i 's/stub-addr: 10.0.0.2/stub-addr: 10.0.0.66/' /tmp/lab07/unbound.conf
sudo pkill -9 -f "unbound -c" || true
sleep 1
sudo ip netns exec dns-res unbound -c /tmp/lab07/unbound.conf -d > /tmp/lab07/unbound.log 2>&1 &
sleep 2

# 3. [CLIENT - client] Truy vấn qua Resolver có bảo vệ DNSSEC
sudo ip netns exec client dig @10.0.0.3 www.lab.test +dnssec

# 4. [CLIENT - client] Đối chiếu khi TẮT kiểm tra DNSSEC bằng cờ +cd
sudo ip netns exec client dig @10.0.0.3 www.lab.test +cd +short
```

#### Phân Tích Cơ Chế Phòng Thủ (SERVFAIL Defense):
1. **Khi hỏi trực tiếp máy chủ Rogue (`dig @10.0.0.66`):**
   - Trả về `6.6.6.6` (chứng minh máy chủ mạo danh đang hoạt động và sẵn sàng đầu độc bất kỳ ai tin tưởng nó).
2. **Khi hỏi qua Resolver có bảo vệ DNSSEC (`dig @10.0.0.3 ... +dnssec`):**
   - Kết quả trả về:
     ```text
     ;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 45123
     ;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
     ```
   - **Cơ chế hoạt động:** Unbound tiếp nhận bản ghi `6.6.6.6` từ máy chủ `10.0.0.66`. Khi tiến hành bước kiểm tra chữ ký bắt buộc, Unbound phát hiện:
     - Hoặc bản ghi không hề có chữ ký `RRSIG`.
     - Hoặc chữ ký không thể giải mã bằng khóa tin cậy trong `trust-anchor.key`.
     - $\implies$ Unbound kết luận dữ liệu đã bị can thiệp trái phép, lập tức **tiêu hủy câu trả lời** và trả về mã lỗi **`SERVFAIL`** (`ANSWER: 0`).
   - Người dùng hoàn toàn được bảo vệ, máy trạm không bao giờ nhận được IP độc hại `6.6.6.6`.
3. **Thực nghiệm đối chứng với cờ `+cd` (Checking Disabled):**
   - `dig ... +cd`: Cờ yêu cầu Resolver bỏ qua khâu xác thực chữ ký số DNSSEC.
   - Kết quả: Trả về ngay lập tức IP độc hại `6.6.6.6`!
   - Thí nghiệm đối chứng này chứng minh một cách không thể chối cãi rằng: **Lỗi `SERVFAIL` xuất hiện ở bước trước hoàn toàn là do hàng rào mật mã DNSSEC chủ động kích hoạt để chặn đứng cuộc tấn công giả mạo.**

---

### 7. BƯỚC 6: DỌN DẸP MÔI TRƯỜNG

Khôi phục hệ thống:

```bash
# [HOST / CHUNG] Tắt tiến trình nền và xóa môi trường lab
sudo pkill -9 named 2>/dev/null || true
sudo pkill -9 unbound 2>/dev/null || true
for ns in dns-auth dns-res client rogue; do sudo ip netns del $ns 2>/dev/null || true; done
sudo ip link del br0 2>/dev/null || true
sudo rm -rf /tmp/lab07 /tmp/trust-anchor.key /var/cache/bind/db.lab.*
```

- Tắt triệt để các tiến trình `named` và `unbound` bằng tín hiệu `SIGKILL` (9).
- Xóa bridge và 4 namespaces, dọn dẹp các tệp cấu hình và khóa tạm thời trong `/var/cache/bind` và `/tmp`.

