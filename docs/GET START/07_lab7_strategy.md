# WORKFLOW EXECUTION: LAB 07 - DNS SECURITY EXTENSIONS (DNSSEC) DEPLOYMENT & VALIDATION

Bạn hãy đóng vai trò là một **Senior DNS Infrastructure Architect, Cryptography & Network Security Engineer và Linux Systems Specialist**.

## 1. MỤC TIÊU & BỐI CẢNH KỸ THUẬT
- **Mục tiêu:** Triển khai hạ tầng DNS khép kín trong môi trường Linux Network Namespaces trên máy ảo Kali Linux qua tool `kali-vm:ssh_execute` để kiểm chứng cơ chế bảo vệ của DNSSEC trước tấn công giả mạo DNS (DNS Spoofing / Forgery).
- **Cơ chế cốt lõi:**
  - DNS truyền thống không xác thực nguồn gốc và tính toàn vẹn dữ liệu, khiến client dễ dàng nhận IP giả (`6.6.6.6`) từ máy chủ mạo danh.
  - DNSSEC sử dụng chữ ký số công khai: Máy chủ ủy quyền (`dns-auth` - BIND9) tự động ký vùng `lab.test` bằng cặp khóa KSK (Key Signing Key - flag 257) và ZSK (Zone Signing Key - flag 256), sinh ra các bản ghi chữ ký `RRSIG` và khóa `DNSKEY`.
  - Máy chủ phân giải (`dns-res` - Unbound) cấu hình `trust-anchor` chứa KSK của `lab.test`. Khi truy vấn hợp lệ, Unbound kiểm tra chữ ký thành công và bật cờ **`ad` (Authenticated Data)**. Khi bị chuyển hướng sang máy chủ giả mạo (`rogue` - không có chữ ký hợp lệ), Unbound phát hiện sai lệch và lập tức trả về **`SERVFAIL`**, chặn đứng cuộc tấn công.

---

## 2. QUY TRÌNH THỰC THI CHI TIẾT (6 GIAI ĐOẠN)

### GIAI ĐOẠN 1: Kiểm tra Gói Cài đặt & Khởi tạo Script Cục bộ
1. Tạo thư mục `docs/progress/LAB07/scripts/` trên workspace host.
2. Tạo các file cấu hình và script trong `docs/progress/LAB07/scripts/`:
   - `setup_dns.sh`:
     - Dọn dẹp sạch các tiến trình `named`, `unbound` cũ (`pkill -9 named 2>/dev/null || true; pkill -9 unbound 2>/dev/null || true`).
     - Xóa sạch các namespace cũ (`dns-auth`, `dns-res`, `client`, `rogue`, `h1`, `h2`, `vic`, `atk`, `gw`, `dst`, `amp*`) và bridge `br0`.
     - Tạo bridge `br0` và 4 namespaces kết nối vào mạng LAN `10.0.0.0/24`:
       - `dns-auth`: `10.0.0.2/24` (BIND9 Authoritative Server có ký DNSSEC)
       - `dns-res`: `10.0.0.3/24` (Unbound Validating Resolver)
       - `client`: `10.0.0.4/24` (Máy trạm truy vấn)
       - `rogue`: `10.0.0.66/24` (BIND9 Rogue Server giả mạo không ký)
   - `named-auth.conf`: Cấu hình BIND9 lắng nghe tại `10.0.0.2`, vùng `lab.test` sử dụng `dnssec-policy default; inline-signing yes;`.
   - `db.lab.test`: Tệp dữ liệu vùng hợp lệ (`www IN A 10.0.0.80`).
   - `unbound.conf`: Cấu hình Unbound lắng nghe tại `10.0.0.3`, nạp `trust-anchor-file: "/tmp/trust-anchor.key"`, `domain-insecure: "."`, và `stub-zone` cho `lab.test` trỏ về `10.0.0.2`.
   - `named-rogue.conf`: Cấu hình BIND9 giả mạo lắng nghe tại `10.0.0.66` (không bật DNSSEC).
   - `db.lab.rogue`: Tệp dữ liệu vùng giả mạo (`www IN A 6.6.6.6`).

### GIAI ĐOẠN 2: Triển khai Topology & Khởi chạy Authoritative DNS (BIND9)
1. Dùng `ssh_execute` kiểm tra và cài đặt các gói bắt buộc trên Kali VM (nếu chưa có):
   ```bash
   sudo apt update && sudo apt install -y bind9 bind9-dnsutils unbound apparmor-utils
   ```
2. Tạo thư mục `/tmp/lab07` và đẩy toàn bộ tệp cấu hình lên Kali VM.
3. Chạy `setup_dns.sh` và kiểm tra kết nối ping từ `client` tới `.2`, `.3`, `.66`.
4. Chuẩn bị quyền hạn và AppArmor cho BIND9:
   ```bash
   sudo aa-complain /usr/sbin/named 2>/dev/null || true
   sudo mkdir -p /var/cache/bind/keys
   sudo cp /tmp/lab07/db.lab.test /var/cache/bind/db.lab.test
   sudo chown -R bind:bind /var/cache/bind
   ```
5. Khởi chạy `named` trên `dns-auth` và chờ 4 giây để BIND9 tự động sinh khóa KSK/ZSK và ký vùng `lab.test`:
   ```bash
   sudo ip netns exec dns-auth named -c /tmp/lab07/named-auth.conf -g > /tmp/lab07/named_auth.log 2>&1 &
   sleep 4
   ```

### GIAI ĐOẠN 3: Trích xuất Trust Anchor (KSK - 257) & Khởi chạy Unbound Resolver
1. Từ `client`, dùng `dig` truy vấn bản ghi DNSKEY từ `10.0.0.2` và lọc lấy khóa KSK (flag 257) làm mỏ neo tin cậy (Trust Anchor):
   ```bash
   sudo ip netns exec client dig @10.0.0.2 lab.test DNSKEY > /tmp/lab07/lab.dnskey
   grep -E "IN[[:space:]]+DNSKEY[[:space:]]+257" /tmp/lab07/lab.dnskey > /tmp/trust-anchor.key
   cat /tmp/trust-anchor.key
   ```
   (Kiểm tra chắc chắn tệp `/tmp/trust-anchor.key` không bị rỗng trước khi sang bước tiếp theo).
2. Khởi chạy bộ phân giải `unbound` trong namespace `dns-res` (`10.0.0.3`):
   ```bash
   sudo ip netns exec dns-res unbound -c /tmp/lab07/unbound.conf -d > /tmp/lab07/unbound.log 2>&1 &
   sleep 2
   ```

### GIAI ĐOẠN 4: Kiểm chứng Xác thực DNSSEC Thành công (Cờ ad)
1. Thực hiện truy vấn từ `client` qua bộ phân giải `10.0.0.3` kèm cờ `+dnssec`:
   ```bash
   sudo ip netns exec client dig @10.0.0.3 www.lab.test +dnssec > /tmp/lab07/dig_valid_ad.log
   cat /tmp/lab07/dig_valid_ad.log
   ```
2. Xác nhận kết quả trả về:
   - `status: NOERROR`
   - Phần `flags:` có xuất hiện cờ **`ad` (Authenticated Data)**.
   - Phần `ANSWER SECTION` trả về `www.lab.test. IN A 10.0.0.80` đi kèm bản ghi chữ ký số `RRSIG`.

### GIAI ĐOẠN 5: Mô phỏng Tấn công DNS Spoofing & Kiểm chứng DNSSEC Chặn Giả mạo
1. **Dựng máy chủ giả mạo (`rogue` - `10.0.0.66`):**
   ```bash
   sudo cp /tmp/lab07/db.lab.rogue /var/cache/bind/db.lab.rogue
   sudo chown bind:bind /var/cache/bind/db.lab.rogue
   sudo ip netns exec rogue named -c /tmp/lab07/named-rogue.conf -g > /tmp/lab07/named_rogue.log 2>&1 &
   sleep 2
   ```
2. **Bẻ lái Resolver sang máy chủ giả mạo:**
   Đổi `stub-addr` trong `/tmp/lab07/unbound.conf` từ `10.0.0.2` sang `10.0.0.66` và khởi động lại `unbound`:
   ```bash
   sed -i 's/stub-addr: 10.0.0.2/stub-addr: 10.0.0.66/' /tmp/lab07/unbound.conf
   sudo pkill -f "unbound -c" || true
   sleep 1
   sudo ip netns exec dns-res unbound -c /tmp/lab07/unbound.conf -d > /tmp/lab07/unbound_hijacked.log 2>&1 &
   sleep 2
   ```
3. **Truy vấn qua Resolver có bảo vệ DNSSEC:**
   ```bash
   sudo ip netns exec client dig @10.0.0.3 www.lab.test +dnssec > /tmp/lab07/dig_servfail.log
   cat /tmp/lab07/dig_servfail.log
   ```
   *Kỳ vọng:* Nhận trạng thái `status: SERVFAIL`, không có địa chỉ IP giả `6.6.6.6` nào được trả về cho client.
4. **Đối chiếu khi TẮT kiểm tra DNSSEC:**
   ```bash
   # (a) Hỏi trực tiếp máy chủ giả mạo
   sudo ip netns exec client dig @10.0.0.66 www.lab.test +short > /tmp/lab07/dig_direct_rogue.log

   # (b) Hỏi qua Resolver nhưng dùng cờ +cd (Checking Disabled - bỏ qua kiểm tra chữ ký)
   sudo ip netns exec client dig @10.0.0.3 www.lab.test +cd +short > /tmp/lab07/dig_cd_bypass.log
   ```
   *Kỳ vọng:* Cả hai trường hợp đều trả về IP độc hại `6.6.6.6`.

### GIAI ĐOẠN 6: Tổng hợp Báo cáo, Hoàn thiện Tổng kết Dự án & Dọn dẹp
1. Tạo tệp `docs/progress/LAB07/IMPLEMENTATION.md`:
   - Giải thích chi tiết kiến trúc Chain of Trust (KSK, ZSK, RRSIG, DS).
   - Giải thích luồng xác thực mật mã từ lúc Unbound tải `trust-anchor.key` cho đến khi kiểm tra `RRSIG`.
2. Tạo tệp `docs/progress/LAB07/lab7_result.md` theo đúng cấu trúc yêu cầu ở Mục 3 bên dưới.
3. Dọn dẹp sạch toàn bộ tiến trình và môi trường ảo hóa:
   ```bash
   sudo pkill -9 named 2>/dev/null || true
   sudo pkill -9 unbound 2>/dev/null || true
   for ns in dns-auth dns-res client rogue; do sudo ip netns del $ns 2>/dev/null || true; done
   sudo ip link del br0 2>/dev/null || true
   sudo rm -rf /tmp/lab07 /tmp/trust-anchor.key /var/cache/bind/db.lab.*
   ```
4. Đánh dấu `[x]` hoàn thành cho Lab 07 trong `PLAN.md` (hoàn tất 7/7 bài thực hành).

---

## 3. YÊU CẦU CẤU TRÚC BÁO CÁO docs/progress/LAB07/lab7_result.md
Tệp báo cáo kết quả phải bao gồm:
- **Metadata:** Thời gian thực thi, Phiên bản BIND9 & Unbound, Sơ đồ 4 namespaces trên `br0`.
- **Terminal Outputs thô (Raw Logs):** Đầy đủ output của `setup_dns.sh`, nội dung khóa `trust-anchor.key` (DNSKEY 257), output `dig_valid_ad.log` (`NOERROR` + cờ `ad`), output `dig_servfail.log` (`SERVFAIL`), và output khi dùng cờ `+cd` (`6.6.6.6`).
- **BÓC TÁCH & PHÂN TÍCH CHUYÊN SÂU LOG TERMINAL (BẮT BUỘC):**
  - **Giải phẫu Bản ghi DNSKEY & RRSIG:** Trích xuất dòng DNSKEY 257 (KSK) và DNSKEY 256 (ZSK) cùng dòng RRSIG trong `dig_valid_ad.log`. Giải thích ý nghĩa các trường trong bản ghi RRSIG (Type Covered, Algorithm, Labels, Original TTL, Signature Expiration, Inception, Key Tag, Signer's Name).
  - **Phân tích Ý nghĩa Cờ `ad` vs `aa` vs `cd`:** Giải thích sự khác biệt giữa cờ `aa` (Authoritative Answer - trả lời trực tiếp từ server gốc) và cờ `ad` (Authenticated Data - dữ liệu đã được Resolver kiểm chứng chữ ký số thành công).
  - **Phân tích Cơ chế Chặn Giả mạo (SERVFAIL):** Trích xuất log từ `unbound_hijacked.log` và `dig_servfail.log` để giải thích tại sao khi nhận phản hồi `6.6.6.6` từ `10.0.0.66` (thiếu RRSIG hợp lệ), Unbound lại chuyển đổi mã phản hồi thành `SERVFAIL` để bảo vệ client.
  - **Đánh giá Giới hạn của DNSSEC:** Giải thích tại sao DNSSEC đảm bảo tính Toàn vẹn (Integrity) và Xác thực nguồn gốc (Origin Authentication) nhưng không đảm bảo tính Bí mật (Confidentiality), và cách kết hợp với DoH/DoT (DNS over HTTPS/TLS).

---

## 4. STRICT RULES
- Mọi thao tác trên Kali VM BẮT BUỘC gọi qua `kali-vm:ssh_execute`.
- Quản lý chặt chẽ tiến trình `named` và `unbound`: Phải đảm bảo file `/tmp/trust-anchor.key` có dữ liệu hợp lệ trước khi khởi chạy `unbound`.
- Sau khi hoàn thành bài lab, BẮT BUỘC phải `pkill` sạch `named` và `unbound` để giải phóng bộ nhớ cho máy ảo.
- Toàn bộ log `dig` và khóa DNSKEY/RRSIG trong `lab7_result.md` phải lấy nguyên văn từ kết quả chạy thực tế trên Kali VM.
