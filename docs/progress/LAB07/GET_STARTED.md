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

### 2. CÁCH 1: CHẠY NHANH TỪ CÁC SCRIPT CÓ SẴN

```bash
# Bước 1: Khởi tạo topology mạng 4 nodes trên br0
sudo bash docs/progress/LAB07/scripts/setup_dns.sh

# Bước 2: Chuẩn bị quyền thư mục và AppArmor cho BIND9
sudo aa-disable /etc/apparmor.d/usr.sbin.named 2>/dev/null || true
sudo aa-disable /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true
sudo mkdir -p /var/cache/bind/keys
sudo cp docs/progress/LAB07/scripts/db.lab.test /var/cache/bind/db.lab.test
sudo cp docs/progress/LAB07/scripts/db.lab.rogue /var/cache/bind/db.lab.rogue
sudo chmod -R 777 /var/cache/bind

# Bước 3: Khởi chạy Authoritative Server (BIND9) trên dns-auth
sudo ip netns exec dns-auth named -u bind -c docs/progress/LAB07/scripts/named-auth.conf -g > /tmp/named_auth.log 2>&1 &
sleep 4

# Bước 4: Trích xuất Trust Anchor (Khóa KSK - DNSKEY 257) từ máy chủ ủy quyền
sudo ip netns exec client dig @10.0.0.2 lab.test DNSKEY > /tmp/lab.dnskey
grep -E "IN[[:space:]]+DNSKEY[[:space:]]+257" /tmp/lab.dnskey | sudo tee /tmp/trust-anchor.key
sudo chmod 666 /tmp/trust-anchor.key

# Bước 5: Khởi chạy Validating Resolver (Unbound) trên dns-res
sudo ip netns exec dns-res unbound -c docs/progress/LAB07/scripts/unbound.conf -d > /tmp/unbound.log 2>&1 &
sleep 2

# Bước 6: Kiểm chứng xác thực DNSSEC thành công (Kỳ vọng: cờ "ad" và RRSIG)
sudo ip netns exec client dig @10.0.0.3 www.lab.test +dnssec

# Bước 7: Khởi chạy Rogue Server (10.0.0.66) trả về IP giả 6.6.6.6
sudo ip netns exec rogue named -u bind -c docs/progress/LAB07/scripts/named-rogue.conf -g > /tmp/named_rogue.log 2>&1 &
sleep 2

# Bước 8: Bẻ lái Resolver sang Rogue Server và kiểm chứng Unbound chặn bằng SERVFAIL
sudo sed -i 's/stub-addr: 10.0.0.2/stub-addr: 10.0.0.66/' docs/progress/LAB07/scripts/unbound.conf
sudo pkill -9 -f "unbound -c" || true
sleep 1
sudo ip netns exec dns-res unbound -c docs/progress/LAB07/scripts/unbound.conf -d > /tmp/unbound.log 2>&1 &
sleep 2

# Truy vấn có bảo vệ: Nhận SERVFAIL (IP giả mạo 6.6.6.6 bị hủy)
sudo ip netns exec client dig @10.0.0.3 www.lab.test +dnssec

# Truy vấn bỏ qua xác thực (+cd): Nhận IP giả 6.6.6.6
sudo ip netns exec client dig @10.0.0.3 www.lab.test +cd +short
```

---

### 3. CÁCH 2: CHẠY ĐỘC LẬP BẰNG COPY-PASTE (STANDALONE)

Dán trực tiếp khối lệnh dưới đây vào Terminal Kali Linux:

```bash
# === 1. TẠO THƯ MỤC CẤU HÌNH VÀ TẮT APPARMOR ===
sudo aa-disable /etc/apparmor.d/usr.sbin.named 2>/dev/null || true
sudo aa-disable /etc/apparmor.d/usr.sbin.unbound 2>/dev/null || true
sudo pkill -9 named 2>/dev/null || true
sudo pkill -9 unbound 2>/dev/null || true
sudo mkdir -p /tmp/lab07 /var/cache/bind/keys
sudo chmod -R 777 /tmp/lab07 /var/cache/bind

# === 2. TẠO TOPOLOGY BRIDGE VÀ 4 NAMESPACES ===
for ns in dns-auth dns-res client rogue; do sudo ip netns del $ns 2>/dev/null || true; done
sudo ip link del br0 2>/dev/null || true
sudo ip link add name br0 type bridge
sudo ip link set dev br0 up

add_host() {
    local ns=$1; local ip=$2
    sudo ip netns add "$ns"
    sudo ip link add "veth_${ns}" type veth peer name "${ns}0"
    sudo ip link set "${ns}0" netns "$ns"
    sudo ip link set "veth_${ns}" master br0
    sudo ip link set "veth_${ns}" up
    sudo ip netns exec "$ns" ip link set dev lo up
    sudo ip netns exec "$ns" ip addr add "${ip}/24" brd 10.0.0.255 dev "${ns}0"
    sudo ip netns exec "$ns" ip link set dev "${ns}0" up
}
add_host "dns-auth" "10.0.0.2"
add_host "dns-res"  "10.0.0.3"
add_host "client"   "10.0.0.4"
add_host "rogue"    "10.0.0.66"

# === 3. TẠO CẤU HÌNH VÀ CHẠY BIND9 KÝ DNSSEC ===
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

cat << 'EOF' > /var/cache/bind/db.lab.test
$TTL 300
@   IN  SOA ns1.lab.test. admin.lab.test. ( 2026110801 3600 1800 604800 300 )
@   IN  NS  ns1.lab.test.
ns1 IN  A   10.0.0.2
www IN  A   10.0.0.80
EOF

sudo ip netns exec dns-auth named -u bind -c /tmp/lab07/named-auth.conf -g > /tmp/lab07/auth.log 2>&1 &
sleep 4

# Trích xuất Trust Anchor KSK 257
sudo ip netns exec client dig @10.0.0.2 lab.test DNSKEY | grep -E "IN[[:space:]]+DNSKEY[[:space:]]+257" > /tmp/trust-anchor.key
echo "[+] Đã trích xuất Trust Anchor:"
cat /tmp/trust-anchor.key

# === 4. TẠO CẤU HÌNH VÀ CHẠY UNBOUND VALIDATING RESOLVER ===
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

sudo ip netns exec dns-res unbound -c /tmp/lab07/unbound.conf -d > /tmp/lab07/unbound.log 2>&1 &
sleep 2

# === 5. KIỂM CHỨNG TRUY VẤN DNSSEC HỢP LỆ ===
echo "=== TRUY VẤN QUA UNBOUND (CỜ AD ĐƯỢC BẬT) ==="
sudo ip netns exec client dig @10.0.0.3 www.lab.test +dnssec
```

---

### 4. QUAN SÁT & TIÊU CHÍ THÀNH CÔNG
1. **Truy vấn hợp lệ (`dig @10.0.0.3 www.lab.test +dnssec`):**
   - Trạng thái: `status: NOERROR`
   - Cờ: Xuất hiện cờ `ad` (`flags: qr rd ra ad`)
   - Trả lời: `www.lab.test. IN A 10.0.0.80` đi kèm bản ghi chữ ký `RRSIG`.
2. **Khi Resolver bị bẻ lái sang Rogue Server:**
   - Truy vấn có kiểm tra: Trả về **`status: SERVFAIL`**, hoàn toàn chặn IP giả `6.6.6.6`.
   - Truy vấn dùng cờ `+cd`: Trả về `6.6.6.6` (chứng minh việc chặn trước đó là nhờ DNSSEC).

---

### 5. LỆNH DỌN DẸP MÔI TRƯỜNG
```bash
sudo pkill -9 named 2>/dev/null || true
sudo pkill -9 unbound 2>/dev/null || true
for ns in dns-auth dns-res client rogue; do sudo ip netns del $ns 2>/dev/null || true; done
sudo ip link del br0 2>/dev/null || true
sudo rm -rf /tmp/lab07 /tmp/trust-anchor.key /var/cache/bind/db.lab.*
```

