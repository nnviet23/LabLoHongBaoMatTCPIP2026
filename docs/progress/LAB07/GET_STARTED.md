# HƯỚNG DẪN THỰC HÀNH: LAB 07
## DNS Security Extensions (DNSSEC) Deployment & Spoofing Defense

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG
- **Mục tiêu:** Xây dựng hạ tầng DNSSEC hoàn chỉnh trong mạng LAN ảo gồm máy chủ Authoritative (BIND9) tự động ký số bằng ECDSA P-256, máy chủ Recursive Resolver (Unbound) xác thực chữ ký bằng Trust Anchor. Kiểm chứng cờ `ad` khi dữ liệu hợp lệ, và chứng minh Unbound chặn đứng tấn công giả mạo DNS mạo danh bằng mã lỗi `SERVFAIL`.
- **Topology:** Mạng LAN trên `br0` (`10.0.0.0/24`) gồm 4 namespaces:
  - `dns-auth`: `10.0.0.2` (BIND9 Authoritative Server - DNSSEC Signed Zone `lab.test`)
  - `dns-res`: `10.0.0.3` (Unbound Validating Resolver)
  - `client`: `10.0.0.4` (Máy trạm kiểm thử gửi truy vấn `dig`)
  - `rogue`: `10.0.0.66` (Rogue BIND9 Server trả về IP giả `6.6.6.6` không ký)

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC TỆP CẤU HÌNH

Tạo thư mục `/tmp/lab07` và tạo các tệp kịch bản / cấu hình bằng `cat << 'EOF'` (hoặc dùng `nano <tên_file>` để soạn thảo):

```bash
mkdir -p /tmp/lab07 /var/cache/bind/keys && cd /tmp/lab07

# 1. Script thiết lập mạng: setup_dns.sh
cat << 'EOF' > /tmp/lab07/setup_dns.sh
#!/usr/bin/env bash
set -e

echo "[*] Tắt tiến trình named và unbound cũ nếu có..."
pkill -9 named 2>/dev/null || true
pkill -9 unbound 2>/dev/null || true

echo "[*] Dọn dẹp namespace và bridge cũ..."
for ns in dns-auth dns-res client rogue h1 h2 vic gw atk dst amp1 amp2 amp3; do
    ip netns del "$ns" 2>/dev/null || true
done
ip link del br0 2>/dev/null || true

echo "[*] Tạo Linux Bridge br0..."
ip link add name br0 type bridge
ip link set dev br0 up

add_host() {
    local ns=$1; local ip=$2
    ip netns add "$ns"
    ip link add "veth_${ns}" type veth peer name "${ns}0"
    ip link set "${ns}0" netns "$ns"
    ip link set "veth_${ns}" master br0
    ip link set "veth_${ns}" up
    ip netns exec "$ns" ip link set dev lo up
    ip netns exec "$ns" ip addr add "${ip}/24" brd 10.0.0.255 dev "${ns}0"
    ip netns exec "$ns" ip link set dev "${ns}0" up
}
add_host "dns-auth" "10.0.0.2"
add_host "dns-res"  "10.0.0.3"
add_host "client"   "10.0.0.4"
add_host "rogue"    "10.0.0.66"

for ip in 10.0.0.2 10.0.0.3 10.0.0.66; do
    ip netns exec client ping -c 1 -W 1 "$ip" >/dev/null 2>&1 || true
done
echo "[+] Topology DNS 4 node đã sẵn sàng!"
EOF
chmod +x /tmp/lab07/setup_dns.sh

# 2. Cấu hình BIND9 Server ủy quyền: named-auth.conf
cat << 'EOF' > /tmp/lab07/named-auth.conf
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
EOF

# 3. Dữ liệu vùng DNSSEC hợp lệ: db.lab.test
cat << 'EOF' > /tmp/lab07/db.lab.test
$TTL 300
@   IN  SOA ns1.lab.test. admin.lab.test. ( 2026110801 3600 1800 604800 300 )
@   IN  NS  ns1.lab.test.
ns1 IN  A   10.0.0.2
www IN  A   10.0.0.80
EOF

# 4. Cấu hình Unbound Resolver: unbound.conf
cat << 'EOF' > /tmp/lab07/unbound.conf
server:
    verbosity: 1
    interface: 10.0.0.3
    port: 53
    do-ip4: yes
    access-control: 0.0.0.0/0 allow
    chroot: ""
    username: ""
    trust-anchor-file: "/tmp/trust-anchor.key"
    local-zone: "test." transparent
    local-zone: "lab.test." transparent
stub-zone:
    name: "lab.test"
    stub-addr: 10.0.0.2
EOF

# 5. Cấu hình BIND9 Rogue Server (giả mạo): named-rogue.conf
cat << 'EOF' > /tmp/lab07/named-rogue.conf
options {
    directory "/var/cache/bind";
    listen-on { 10.0.0.66; };
    listen-on-v6 { none; };
    allow-query { any; };
    recursion no;
};
zone "lab.test" {
    type primary;
    file "/var/cache/bind/db.lab.rogue";
};
EOF

# 6. Dữ liệu vùng giả mạo: db.lab.rogue
cat << 'EOF' > /tmp/lab07/db.lab.rogue
$TTL 300
@   IN  SOA ns1.lab.test. admin.lab.test. ( 2026110801 3600 1800 604800 300 )
@   IN  NS  ns1.lab.test.
ns1 IN  A   10.0.0.66
www IN  A   6.6.6.6
EOF
```

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG & PHÂN QUYỀN APPARMOR

```bash
# Chạy thiết lập mạng LAN
sudo bash /tmp/lab07/setup_dns.sh

# Vô hiệu hóa AppArmor cho named và unbound để cho phép đọc file cấu hình tùy biến
sudo aa-disable /etc/apparmor.d/usr.sbin.named 2>/dev/null || true
sudo aa-disable /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true

# Copy zone file vào /var/cache/bind và cấp quyền ghi
sudo cp /tmp/lab07/db.lab.test /var/cache/bind/db.lab.test
sudo cp /tmp/lab07/db.lab.rogue /var/cache/bind/db.lab.rogue
sudo chmod -R 777 /var/cache/bind /tmp/lab07
```

---

### 4. BƯỚC 3: KHỞI CHẠY BIND9 & TRÍCH XUẤT TRUST ANCHOR

1. Khởi chạy Authoritative Server trên `dns-auth` (tự động ký DNSSEC):
   ```bash
   sudo ip netns exec dns-auth named -u bind -c /tmp/lab07/named-auth.conf -g > /tmp/lab07/named_auth.log 2>&1 &
   sleep 4
   ```
2. Từ `client`, truy vấn bản ghi DNSKEY từ máy chủ `10.0.0.2` và trích xuất khóa KSK (flag 257) vào `/tmp/trust-anchor.key`:
   ```bash
   sudo ip netns exec client dig @10.0.0.2 lab.test DNSKEY | grep -E "IN[[:space:]]+DNSKEY[[:space:]]+257" > /tmp/trust-anchor.key
   sudo chmod 666 /tmp/trust-anchor.key
   cat /tmp/trust-anchor.key
   ```
   > **Quan sát:** Tệp xuất hiện bản ghi `lab.test. IN DNSKEY 257 3 13 ...` chứa khóa công khai ECDSA P-256.

---

### 5. BƯỚC 4: KHỞI CHẠY UNBOUND & KIỂM CHỨNG XÁC THỰC THÀNH CÔNG

1. Khởi chạy Unbound Resolver trên `dns-res`:
   ```bash
   sudo ip netns exec dns-res unbound -c /tmp/lab07/unbound.conf -d > /tmp/lab07/unbound.log 2>&1 &
   sleep 2
   ```
2. Thực hiện truy vấn DNSSEC từ máy trạm `client`:
   ```bash
   sudo ip netns exec client dig @10.0.0.3 www.lab.test +dnssec
   ```
   *Kỳ vọng:*
   - `status: NOERROR`
   - Cờ xuất hiện cờ **`ad` (Authenticated Data)**: `flags: qr rd ra ad`.
   - Phần ANSWER trả về `www.lab.test. IN A 10.0.0.80` đi kèm bản ghi chữ ký số `RRSIG`.

---

### 6. BƯỚC 5: MÔ PHỎNG TẤN CÔNG GIẢ MẠO & KIỂM CHỨNG CHẶN BẰNG SERVFAIL

1. Khởi chạy máy chủ mạo danh Rogue Server (`10.0.0.66`) trả về IP giả `6.6.6.6`:
   ```bash
   sudo ip netns exec rogue named -u bind -c /tmp/lab07/named-rogue.conf -g > /tmp/lab07/named_rogue.log 2>&1 &
   sleep 2
   # Hỏi thử trực tiếp máy chủ mạo danh:
   sudo ip netns exec client dig @10.0.0.66 www.lab.test +short
   # (Trả về 6.6.6.6)
   ```
2. Bẻ lái Resolver `dns-res` sang máy chủ giả mạo:
   ```bash
   sudo sed -i 's/stub-addr: 10.0.0.2/stub-addr: 10.0.0.66/' /tmp/lab07/unbound.conf
   sudo pkill -9 -f "unbound -c" || true
   sleep 1
   sudo ip netns exec dns-res unbound -c /tmp/lab07/unbound.conf -d > /tmp/lab07/unbound.log 2>&1 &
   sleep 2
   ```
3. Truy vấn qua Resolver có bảo vệ DNSSEC:
   ```bash
   sudo ip netns exec client dig @10.0.0.3 www.lab.test +dnssec
   ```
   > **Quan sát phòng thủ:** Trả về **`status: SERVFAIL`**, `ANSWER: 0`. IP giả mạo `6.6.6.6` bị Resolver triệt tiêu hoàn toàn, bảo vệ người dùng!

4. Đối chiếu khi TẮT kiểm tra DNSSEC bằng cờ `+cd` (Checking Disabled):
   ```bash
   sudo ip netns exec client dig @10.0.0.3 www.lab.test +cd +short
   ```
   > **Quan sát:** Trả về `6.6.6.6` (chứng minh việc nhận `SERVFAIL` trước đó là nhờ cơ chế bảo vệ mật mã của DNSSEC).

---

### 7. BƯỚC 6: DỌN DẸP MÔI TRƯỜNG

```bash
sudo pkill -9 named 2>/dev/null || true
sudo pkill -9 unbound 2>/dev/null || true
for ns in dns-auth dns-res client rogue; do sudo ip netns del $ns 2>/dev/null || true; done
sudo ip link del br0 2>/dev/null || true
sudo rm -rf /tmp/lab07 /tmp/trust-anchor.key /var/cache/bind/db.lab.*
```
