# TÀI LIỆU KỸ THUẬT & KIẾN TRÚC THỰC THI: LAB 04
## Smurf Attack (ICMP Broadcast Amplification) & Mitigation Architecture

---

### 1. KIẾN TRÚC MÔ HÌNH THỰC NGHIỆM (TOPOLOGY ARCHITECTURE)

```
                       +-----------------------------------+
                       |         Linux Bridge br0          |
                       |       (Software L2 Switch)        |
                       +--+---------+---------+----+---+---+
                          |         |         |    |   |
             +------------+         |         |    |   +------------+
             |                      |         |    |                |
             v                      v         v    v                v
       +-----------+          +-----------+  +------------------------+
       |    atk    |          |    vic    |  |  amp1   amp2   amp3    |
       |10.0.0.100 |          |10.0.0.200 |  |10.0.0.11 .12   .13     |
       +-----------+          +-----------+  +------------------------+
        (Attacker)              (Victim)            (Amplifiers)
```

- **Môi trường ảo hóa:** Sử dụng Linux Virtual Ethernet (`veth`) và Linux Software Bridge (`br0`) để tạo ra môi trường tương đương một switch mạng L2 thực tế.
- **Tính chất Directed Broadcast:**
  - Trong subnet `10.0.0.0/24`, địa chỉ broadcast theo quy ước CIDR là `10.0.0.255`.
  - Khi một khung Ethernet chứa địa chỉ IP đích `10.0.0.255` được đưa vào switch/bridge, khung Ethernet có địa chỉ MAC đích là Broadcast L2 (`ff:ff:ff:ff:ff:ff`).
  - Bridge sao chép và chuyển tiếp (flood) khung này ra toàn bộ các cổng mạng thành viên (`veth_vic`, `veth_amp1`, `veth_amp2`, `veth_amp3`), trừ cổng nhận gói.

---

### 2. CƠ CHẾ KỸ THUẬT CỦA SMURF ATTACK

#### 2.1. Chuỗi Sự Kiện Tấn Công (Attack Sequence)

1. **Giả mạo nguồn (IP Spoofing):**
   - Host tấn công `atk` (`10.0.0.100`) chế tạo gói tin ICMP Echo Request (`Type 8`, `Code 0`) nhưng điền trường `IP.src = 10.0.0.200` (địa chỉ của nạn nhân `vic`) và `IP.dst = 10.0.0.255` (Directed Broadcast của subnet).
2. **Khuếch đại Broadcast (Broadcast Distribution):**
   - Bridge L2 nhân bản gói tin ra mọi máy trạm trong subnet.
   - Các máy trạm `amp1`, `amp2`, `amp3` nhận được gói tin ICMP Echo Request gửi tới địa chỉ broadcast của chính mạng mình.
3. **Phản hồi đồng loạt (Simultaneous Echo Replies):**
   - Nếu hệ điều hành của các máy khuếch đại không được cấu hình ngăn chặn phản hồi broadcast, stack mạng của kernel sẽ tự động tạo gói ICMP Echo Reply (`Type 0`, `Code 0`).
   - Địa chỉ đích của gói Echo Reply được trích xuất từ `IP.src` của gói Request $\rightarrow$ toàn bộ dội thẳng về `10.0.0.200` (`vic`).
4. **Hậu quả cạn kiệt tài nguyên (Resource Exhaustion):**
   - Nạn nhân phải tiếp nhận số lượng gói tin gấp $N$ lần số gói tin kẻ tấn công gửi đi, dẫn đến nghẽn băng thông đường truyền tải xuống (downlink saturation), tràn bộ đệm nhận của card mạng (NIC RX Ring Buffer drop), và tăng vọt tải CPU xử lý ngắt mạng (softirq).

---

### 3. CHI TIẾT KỊCH BẢN TRIỂN KHAI & THAM SỐ SCAPY

#### 3.1. Kịch bản Khởi tạo Topology: `setup_lan.sh`

```bash
# Tạo Linux Bridge
ip link add name br0 type bridge
ip link set dev br0 up

# Tạo namespace và veth pair kết nối vào bridge
ip netns add "$ns"
ip link add "veth_${ns}" type veth peer name "${ns}0"
ip link set "${ns}0" netns "$ns"
ip link set "veth_${ns}" master br0
ip link set "veth_${ns}" up

# Khai báo địa chỉ IP và broadcast rõ ràng
ip netns exec "$ns" ip addr add "${ip}/24" brd 10.0.0.255 dev "${ns}0"
```

> **Lưu ý thiết kế:** Tham số `brd 10.0.0.255` là bắt buộc khi gán IP bằng lệnh `ip addr add`. Nếu thiếu cờ này, Linux kernel có thể không nhận diện đúng các gói tin directed broadcast ở tầng L3.

#### 3.2. Cấu hình Dễ bị Tấn công trên Máy khuếch đại

```bash
for h in amp1 amp2 amp3; do
    ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0
done
```

Theo mặc định trên hầu hết các bản phân phối Linux hiện đại, giá trị này bằng `1` (bỏ qua). Để thực nghiệm và đo lường hệ số khuếch đại, giá trị được chuyển tạm thời về `0`.

#### 3.3. Script Phát Gói Scapy: `smurf_attack.py`

```python
from scapy.all import IP, ICMP, send

# Thiết lập gói tin IP với src giả mạo và dst là broadcast
pkt = IP(src="10.0.0.200", dst="10.0.0.255") / ICMP(id=0x1337)

# Gửi 10 gói tin với khoảng cách thời gian giữa các gói là 0.1s
send(pkt, count=10, inter=0.1, verbose=0)
```

- `id=0x1337`: Đặt Identifier cố định để dễ dàng lọc và đối chiếu trong log bắt gói `tcpdump`.
- `inter=0.1`: Đảm bảo các gói tin được gửi tuần tự, tránh tình trạng xung đột hoặc rụng gói trên bridge ảo.

---

### 4. CÁC BIỆN PHÁP PHÒNG THỦ & ĐỐI CHIẾU CHUẨN RFC

#### 4.1. Phòng thủ Tầng Máy Trạm (Host Layer Mitigation)

- **Cấu hình:** `net.ipv4.icmp_echo_ignore_broadcasts = 1`
- **Cơ chế:** Khi gói tin ICMP Echo Request có địa chỉ đích là Broadcast L2 (`ff:ff:ff:ff:ff:ff`) hoặc Broadcast L3 (`x.y.z.255`), hàm xử lý ICMP của nhân Linux (`icmp_rcv` trong `net/ipv4/icmp.c`) kiểm tra cờ này:
  - Nếu `sysctl = 1`: Kernel lập tức drop gói tin và không tạo gói Echo Reply.
  - Kết quả kiểm chứng: Số lượng phản hồi giảm từ 30 về 0 tuyệt đối.

#### 4.2. Phòng thủ Tầng Bộ Định Tuyến (Router Boundary Mitigation - RFC 2644)

- **Chuẩn RFC 2644 (Thay thế RFC 1812 section 5.3.5.2):** *Changing the Default for Directed Broadcasts in Routers*.
- **Cơ chế:**
  - Quy định mọi Router theo chuẩn Internet phải **mặc định vô hiệu hóa tính năng chuyển tiếp gói tin Directed Broadcast** (`no ip directed-broadcast` trên thiết bị Cisco/Juniper).
  - Khi một gói tin từ Internet có đích đến là `192.168.1.255`, Router biên sẽ hủy gói tin ngay lập tức thay vì chuyển đổi thành gói Ethernet Broadcast trên mạng LAN cục bộ. Điều này ngăn chặn hoàn toàn kẻ tấn công từ bên ngoài Internet khai thác mạng LAN làm trạm khuếch đại.

#### 4.3. Phòng thủ Tầng Nhà Mạng (Carrier / ISP Ingress Filtering - BCP 38 / RFC 2827)

- **Best Current Practice 38 (BCP 38):** *Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing*.
- **Cơ chế:**
  - Router biên của ISP triển khai tính năng **Unicast Reverse Path Forwarding (uRPF)**.
  - Khi nhận gói tin từ một khách hàng, router kiểm tra bảng định tuyến: Nếu địa chỉ nguồn (`IP.src`) không thuộc dải địa chỉ IP hợp lệ được gán cho giao diện khách hàng đó, router sẽ drop gói tin ngay tại cửa ngõ.
  - Đây là biện pháp căn cơ nhất loại bỏ nguồn gốc của mọi cuộc tấn công giả mạo IP nguồn (Smurf, DNS Amplification, NTP Amplification).

