# WORKFLOW EXECUTION: LAB 04: ICMP BROADCAST SIMULATION & DIRECTED BROADCAST DEFENSE (RFC 2644)

Bạn hãy đóng vai trò là một **Senior Network Security Engineer, DDoS Mitigation Specialist và Linux Kernel Networking Architect**.

## 1. MỤC TIÊU & BỐI CẢNH KỸ THUẬT
- **Mục tiêu:** Thực hành môn An toàn mạng nội bộ trong môi trường cô lập Linux Namespace phục vụ mục đích phòng thủ và nghiên cứu RFC 2644 trên mạng LAN ảo (Linux Bridge + 5 Network Namespaces) qua tool `kali-vm:ssh_execute`.
- **Cơ chế cốt lõi:** Kẻ tấn công (`atk` - `10.0.0.100`) gửi các gói ICMP Echo Request tới địa chỉ Directed Broadcast của mạng (`10.0.0.255`), nhưng giả mạo địa chỉ IP nguồn thành IP của nạn nhân (`vic` - `10.0.0.200`). Toàn bộ các host cấu hình yếu trong mạng (`amp1`, `amp2`, `amp3`) nhận gói broadcast sẽ đồng loạt phản hồi ICMP Echo Reply dội thẳng về `vic`, tạo ra hệ số khuếch đại lưu lượng gấp N lần số máy khuếch đại.
- **Mục tiêu phòng thủ:** Đo lường hệ số khuếch đại thực tế, sau đó kích hoạt cơ chế phòng vệ ở tầng Kernel (`net.ipv4.icmp_echo_ignore_broadcasts = 1`) và đối chiếu kết quả.

---

## 2. QUY TRÌNH THỰC THI CHI TIẾT (5 GIAI ĐOẠN)

### GIAI ĐOẠN 1: Chuẩn bị Script Cục bộ & Khởi tạo Topology LAN
1. Tạo thư mục `docs/progress/LAB04/scripts/` trên workspace host.
2. Tạo script `setup_lan.sh`:
   - Dọn dẹp sạch các namespace cũ (`atk`, `vic`, `amp1`, `amp2`, `amp3`, `h1`, `h2`) và bridge `br0` nếu còn tồn tại.
   - Tạo Linux Bridge `br0` và bật trạng thái `up`.
   - Viết hàm `add_host()` tạo 5 namespace nối vào `br0` qua các cặp veth:
     - `atk`: `10.0.0.100/24` (Attacker)
     - `vic`: `10.0.0.200/24` (Victim)
     - `amp1`: `10.0.0.11/24` (Amplifier 1)
     - `amp2`: `10.0.0.12/24` (Amplifier 2)
     - `amp3`: `10.0.0.13/24` (Amplifier 3)
   - **LƯU Ý KỸ THUẬT QUAN TRỌNG:** Khi gán địa chỉ IP trong hàm `add_host`, bắt buộc phải khai báo rõ địa chỉ broadcast `brd 10.0.0.255` (ví dụ: `ip netns exec $ns ip addr add ${ipaddr}/24 brd 10.0.0.255 dev ${ns}0`) để Linux bridge xử lý chính xác gói tin L3 directed broadcast.
   - **Tái tạo điều kiện dễ bị tấn công:** Bật phản hồi broadcast trên 3 máy khuếch đại:
     ```bash
     for h in amp1 amp2 amp3; do
         ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0
     done
     ```
3. Tạo script tấn công `broadcast_tester.py`:
   - Sử dụng Scapy gửi 10 gói ICMP Echo Request:
     ```python
     from scapy.all import IP, ICMP, send
     send(IP(src="10.0.0.200", dst="10.0.0.255") / ICMP(), count=10, verbose=0)
     print("[+] Sent 10 ICMP echo packets to broadcast with spoofed src = victim")
     ```

### GIAI ĐOẠN 2: Triển khai lên Kali VM & Kiểm tra Trạng thái Mạng
1. Dùng `ssh_execute` tạo thư mục `/tmp/lab04` trên Kali VM.
2. Đẩy `setup_lan.sh` và `broadcast_tester.py` lên `/tmp/lab04/`, cấp quyền thực thi và chạy `setup_lan.sh`.
3. Kiểm tra kết nối cơ bản từ `atk` tới `vic` và kiểm tra thông số `sysctl` trên `amp1`, `amp2`, `amp3`.

### GIAI ĐOẠN 3: Phát động Tấn công ICMP BROADCAST & Đo lường Hệ số Khuếch đại
1. Mở `tcpdump` trên nạn nhân (`vic`) với timeout 8 giây để ghi lại toàn bộ gói ICMP dội về:
   ```bash
   ip netns exec vic timeout 8 tcpdump -i vic0 -nn icmp > /tmp/lab04/tcpdump_vic_attack.log 2>&1 &
   ```
2. Chờ 1 giây rồi phát động tấn công từ `atk`:
   ```bash
   ip netns exec atk python3 /tmp/lab04/broadcast_tester.py
   ```
3. Chờ tiến trình tcpdump kết thúc, đọc file `/tmp/lab04/tcpdump_vic_attack.log` và đếm tổng số dòng gói tin echo reply nhận được:
   ```bash
   grep "echo reply" /tmp/lab04/tcpdump_vic_attack.log | wc -l
   ```
   *Kỳ vọng:* 10 gói gửi đi từ `atk` sẽ sinh ra đúng 30 gói Echo Reply (10 từ `.11`, 10 từ `.12`, 10 từ `.13`) dội về `10.0.0.200` (Hệ số khuếch đại = $\times 3$).

### GIAI ĐOẠN 4: Kích hoạt Phòng thủ & Kiểm chứng
1. Bật tính năng bỏ qua ping broadcast trên cả 3 máy khuếch đại:
   ```bash
   for h in amp1 amp2 amp3; do
       ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
   done
   ```
2. Mở lại `tcpdump` trên `vic` (timeout 6 giây, lưu vào `/tmp/lab04/tcpdump_vic_defended.log`) và chạy lại `broadcast_tester.py` từ `atk`.
3. Đọc log `/tmp/lab04/tcpdump_vic_defended.log` để xác nhận: 0 gói tin phản hồi nào dội về nạn nhân.

### GIAI ĐOẠN 5: Tổng hợp Báo cáo & Dọn dẹp
1. Tạo file `docs/progress/LAB04/IMPLEMENTATION.md`: Giải thích kiến trúc Bridge L2, cơ chế Directed Broadcast và vai trò của RFC 2644 / BCP 38.
2. Tạo file `docs/progress/LAB04/lab4_result.md` theo đúng cấu trúc yêu cầu ở Mục 3 bên dưới.
3. Dọn dẹp sạch môi trường:
   ```bash
   for ns in atk vic amp1 amp2 amp3; do ip netns del $ns 2>/dev/null || true; done
   ip link del br0 2>/dev/null || true
   rm -rf /tmp/lab04
   ```
4. Đánh dấu `[x]` cho Lab 04 trong `PLAN.md`.

---

## 3. YÊU CẦU CẤU TRÚC BÁO CÁO docs/progress/LAB04/lab4_result.md
Tệp báo cáo kết quả phải bao gồm:
- **Metadata:** Thời gian thực thi, Kernel version, Topology 5 hosts trên `br0`.
- **Terminal Outputs thô (Raw Logs):** Toàn bộ stdout/stderr của quá trình tạo bridge, cấu hình sysctl, log tcpdump khi bị tấn công (30 gói) và sau khi bật phòng thủ (0 gói).
- **BÓC TÁCH & PHÂN TÍCH CHUYÊN SÂU LOG TERMINAL (BẮT BUỘC):**
  - **Phân tích Cơ chế Khuếch đại (Amplification Mechanics):** Trích xuất các dòng log trong `tcpdump_vic_attack.log` chứng minh với cùng một seq (hoặc id), nạn nhân `10.0.0.200` nhận liên tiếp 3 gói ICMP echo reply từ 3 địa chỉ nguồn khác nhau (`10.0.0.11`, `10.0.0.12`, `10.0.0.13`) dù nạn nhân không hề gửi bất kỳ gói echo request nào.
  - **Phân tích Tác động Băng thông:** Lập công thức tính hệ số khuếch đại $K = N_{\text{amplifiers}}$ và giải thích tại sao ở cấp độ mạng thực tế (hàng trăm host trên subnet /24), kỹ thuật này gây nghẽn mạch (DoS) tức thì cho nạn nhân.
  - **Đối chiếu Phòng thủ Đa lớp:** Phân tích sự khác biệt giữa việc chặn tại Host (`icmp_echo_ignore_broadcasts=1`), chặn tại Router biên (`no ip directed-broadcast` - RFC 2644) và lọc IP nguồn giả mạo tại ISP (BCP 38).

---

## 4. STRICT RULES
- Mọi thao tác trên Kali VM BẮT BUỘC gọi qua `kali-vm:ssh_execute`.
- Lệnh `tcpdump` luôn phải đi kèm timeout để tránh treo phiên SSH.
- Không giả lập log; toàn bộ kết quả đếm gói và log tcpdump phải lấy từ thực tế chạy trên Kali VM.
