# HƯỚNG DẪN TRIỂN KHAI & PHÂN TÍCH KỸ THUẬT: LAB 04
## Smurf Attack (ICMP Broadcast Amplification DoS)

---

### 1. MỤC TIÊU & MÔ HÌNH MẠNG

#### 1.1 Mục Tiêu & Cơ Sở Lý Thuyết
- **Bản chất tấn công khuếch đại (RFC 792 / CERT CA-1998-01):** Tấn công Smurf là hình mẫu kinh điển của kỹ thuật tấn công Từ chối Dịch vụ (DoS) dựa trên phản xạ và khuếch đại lưu lượng (Reflection & Amplification Attack). Bằng cách gửi một gói tin ICMP Echo Request tới địa chỉ Directed Broadcast (`10.0.0.255`) với IP nguồn giả mạo của nạn nhân (`10.0.0.200`), switch/bridge sẽ nhân bản gói tin tới toàn bộ $N$ máy trạm trong subnet. Toàn bộ $N$ máy trạm này sẽ đồng loạt sinh gói phản hồi ICMP Echo Reply dội ngược về nạn nhân.
- **Hệ số khuếch đại (Amplification Factor - $K$):**
  $$K = \frac{\text{Số gói Echo Reply nhận được tại nạn nhân}}{\text{Số gói Echo Request phát đi từ Attacker}} = N$$
  Trong đó $N$ là số lượng máy trạm khuếch đại trong mạng.
- **Tiêu chuẩn phòng thủ hiện đại (RFC 2644 / BCP 34):** Các router mạng bắt buộc phải tắt chuyển tiếp Directed Broadcast, và các hệ điều hành máy trạm (như Linux kernel) mặc định kích hoạt tham số `net.ipv4.icmp_echo_ignore_broadcasts = 1` để drop âm thầm mọi gói ping gửi đến địa chỉ broadcast.
- **Mục tiêu thực nghiệm trong Lab 04:**
  1. Xây dựng phân đoạn mạng LAN ảo 5 nút trên Linux Bridge `br0`.
  2. Tái tạo môi trường dễ bị tấn công bằng cách cấu hình `icmp_echo_ignore_broadcasts = 0` trên 3 máy khuếch đại (`amp1`, `amp2`, `amp3`).
  3. Gửi 10 gói ICMP mạo danh nguồn và đo lường hệ số khuếch đại thực nghiệm đạt chính xác $K = \times 3$ (30 gói phản hồi dội về nạn nhân).
  4. Kích hoạt cơ chế phòng thủ hạt nhân và kiểm chứng lưu lượng dội về giảm 100% (về đúng 0 gói).

#### 1.2 Topology Mạng & Quy Ước Thực Thi
- **Mô hình kết nối:** Mạng LAN chia sẻ môi trường truyền dẫn trên Linux Bridge ảo `br0` (`10.0.0.0/24`):
  - `[ATTACKER - atk]`: `10.0.0.100/24` trên `atk0`.
  - `[VICTIM - vic]`: `10.0.0.200/24` trên `vic0`.
  - `[MÁY KHUẾCH ĐẠI - amp1]`: `10.0.0.11/24` trên `amp10`.
  - `[MÁY KHUẾCH ĐẠI - amp2]`: `10.0.0.12/24` trên `amp20`.
  - `[MÁY KHUẾCH ĐẠI - amp3]`: `10.0.0.13/24` trên `amp30`.

> 💡 **Quy ước thực thi lệnh:**
> - `[VICTIM - vic]`: Lệnh chạy trong namespace nạn nhân (tiền tố `ip netns exec vic`).
> - `[ATTACKER - atk]`: Lệnh chạy trong namespace kẻ tấn công (tiền tố `ip netns exec atk`).
> - `[MÁY KHUẾCH ĐẠI - amp1/2/3]`: Lệnh cấu hình trên 3 trạm khuếch đại (tiền tố `ip netns exec ampX`).
> - `[HOST / CHUNG]`: Lệnh chạy trực tiếp trên máy ảo Kali.

---

### 2. BƯỚC 1: KHỞI TẠO THƯ MỤC VÀ TẠO CÁC SCRIPT

Trong bước này, ta chuẩn bị 2 tệp kịch bản tại `/tmp/lab04`:

#### 2.1 Kịch Bản `setup_lan.sh` (Bridge-based Multi-node LAN Setup)
- **Tại sao lại đặt tên như vậy?** Đặt tên là `setup_lan` vì kịch bản này thiết lập cả một phân đoạn mạng cục bộ (LAN) gồm nhiều máy trạm cùng cắm vào một thiết bị chuyển mạch ảo (Switch/Bridge `br0`).
- **Ý nghĩa của script:** Khởi tạo hạ tầng mạng chia sẻ môi trường broadcast và chủ động tắt cơ chế phòng ngự của các trạm khuếch đại để mô phỏng mạng nội bộ thập niên 1990 chưa được gia cố an ninh.
- **Ý chính của script làm gì?**
  1. Tạo Linux Bridge `br0` đóng vai trò Virtual Switch Tầng 2.
  2. Tạo hàm `add_host` tự động hóa việc tạo 5 namespace, gắn các cặp veth vào bridge và cấu hình địa chỉ IP kèm broadcast subnet (`brd 10.0.0.255`).
  3. Cấu hình tham số kernel trên cả 3 trạm: `sysctl -w net.ipv4.icmp_echo_ignore_broadcasts = 0`.
  4. Thực hiện ping mồi để làm ấm bộ đệm ARP giữa các máy trạm trong subnet.
- **Móc nối lý thuyết (Theory Hook):**
  - Móc nối với cơ chế xử lý gói tin Broadcast Tầng 2: Bridge `br0` khi nhận được frame mang địa chỉ MAC đích `FF:FF:FF:FF:FF:FF` (tương ứng IP `10.0.0.255`) sẽ thực hiện kỹ thuật **Flooding**: sao chép frame ra tất cả các cổng mạng khác ngoại trừ cổng vừa nhận vào.

#### 2.2 Kịch Bản `smurf_attack.py` (Smurf Packet Crafter)
- **Tại sao lại đặt tên như vậy?** Tên gọi đặt theo tên cuộc tấn công lịch sử **Smurf Attack** (gợi nhớ đến bộ phim hoạt hình Xì Trum khi một cá thể nhỏ bé có thể huy động cả một cộng đồng đông đảo để tạo ra sức mạnh áp đảo).
- **Ý nghĩa của script:** Công cụ phát động tấn công DoS khuếch đại dựa trên Scapy.
- **Ý chính của script làm gì?**
  1. Định nghĩa đích broadcast: `TARGET_BCAST = "10.0.0.255"`.
  2. Định nghĩa IP nạn nhân bị mạo danh: `SPOOFED_VIC = "10.0.0.200"`.
  3. Đóng gói gói tin `IP(src="10.0.0.200", dst="10.0.0.255") / ICMP(id=0x1337)`.
  4. Gửi lặp lại đúng 10 gói tin (`NUM_PACKETS = 10`) với khoảng cách 0.1s giữa các gói (`inter=0.1`).
- **Móc nối lý thuyết (Theory Hook):**
  - Móc nối với công thức khuếch đại: Kẻ tấn công chỉ tốn băng thông gửi đúng 10 gói tin nhỏ ($10 \times 64 = 640$ bytes), nhưng bắt mạng phải sinh ra 30 gói tin dội về đầu nạn nhân ($30 \times 64 = 1920$ bytes), chứng minh khả năng bất đối xứng tài nguyên giữa kẻ tấn công và mục tiêu.

---

### 3. BƯỚC 2: CHẠY THIẾT LẬP MẠNG

Thực thi kịch bản thiết lập:

```bash
# [HOST / CHUNG] Thiết lập topology mạng LAN bridge br0
sudo bash /tmp/lab04/setup_lan.sh
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `ip link add name br0 type bridge`:
   - Tạo một thiết bị Switch ảo mềm trong nhân Linux. Thiết bị bridge duy trì bảng MAC (FDB - Forwarding Database) và xử lý việc chuyển mạch khung Ethernet lớp 2 chuẩn IEEE 802.1D.
2. `ip link set <veth_host> master br0`:
   - Cắm một đầu dây veth vào switch ảo `br0` (tương đương cắm dây mạng RJ45 vào cổng switch).
3. `ip addr add 10.0.0.X/24 brd 10.0.0.255 dev <dev>`:
   - Tham số `brd 10.0.0.255`: Chỉ định rõ địa chỉ broadcast của subnet cho giao diện mạng. Nếu không có tham số này, kernel có thể không xác định đúng địa chỉ broadcast cục bộ để lắng nghe gói tin.
4. `sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0`:
   - Ghi đè biến nhân kernel cho phép máy chủ trả lời các gói ICMP gửi đến broadcast.

---

### 4. BƯỚC 3: PHÁT ĐỘNG TẤN CÔNG & ĐO LƯỜNG HỆ SỐ KHUẾCH ĐẠI

Tiến hành phát động tấn công và đo lường lưu lượng dội về nạn nhân:

```bash
# 1. [VICTIM - vic] Mở tcpdump trên nạn nhân đón bắt các gói phản hồi
sudo ip netns exec vic tcpdump -i vic0 -nn icmp > /tmp/lab04/tcpdump_vic_attack.log 2>&1 &
sleep 1

# 2. [ATTACKER - atk] Phát động tấn công từ atk
sudo ip netns exec atk python3 /tmp/lab04/smurf_attack.py
sleep 3

# 3. [VICTIM - vic] Đếm số lượng gói Echo Reply nhận được tại nạn nhân
grep "echo reply" /tmp/lab04/tcpdump_vic_attack.log | wc -l
```

#### Phân Tích Cú Pháp & Các Lệnh Quan Trọng:
1. `grep "echo reply" /tmp/lab04/tcpdump_vic_attack.log | wc -l`:
   - `grep "echo reply"`: Lọc tất cả các dòng nhật ký chứa thông điệp phản hồi ICMP Echo Reply (bỏ qua các gói ARP hoặc Request nếu có).
   - `wc -l` (Word Count - Lines): Đếm số dòng xuất ra, tương ứng với số lượng gói tin phản hồi nhận được.
2. **Phân tích kết quả thực tế:**
   - Kết quả đếm trả về con số chính xác: **`30`**.
   - **Xác thực hệ số khuếch đại:**
     $$K = \frac{30\text{ (gói Echo Reply)}}{10\text{ (gói Echo Request gửi đi)}} = \times 3$$
   - Khi soi chi tiết file `tcpdump_vic_attack.log`, ta thấy cứ mỗi lần kẻ tấn công phát 1 gói Request tới `10.0.0.255`, thì chỉ trong vòng vài miligiây, nạn nhân nhận đồng thời 3 gói Echo Reply dội về từ 3 địa chỉ IP khác nhau:
     ```text
     10.0.0.11 > 10.0.0.200: ICMP echo reply, id 4919, seq 0
     10.0.0.12 > 10.0.0.200: ICMP echo reply, id 4919, seq 0
     10.0.0.13 > 10.0.0.200: ICMP echo reply, id 4919, seq 0
     ```

---

### 5. BƯỚC 4: KÍCH HOẠT PHÒNG THỦ & TÁI KIỂM CHỨNG

Triển khai cơ chế phòng thủ mặc định của nhân Linux hiện đại:

```bash
# 1. [MÁY KHUẾCH ĐẠI - amp1/2/3] Bật cơ chế phòng vệ bỏ qua ping broadcast
for h in amp1 amp2 amp3; do
    sudo ip netns exec $h sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
done

# 2. [ATTACKER / VICTIM] Mở lại tcpdump trên vic và phát lại gói tin từ atk
sudo ip netns exec vic tcpdump -i vic0 -nn icmp > /tmp/lab04/tcpdump_vic_defended.log 2>&1 &
sleep 1
sudo ip netns exec atk python3 /tmp/lab04/smurf_attack.py
sleep 2

# 3. [VICTIM - vic] Đếm số lượng gói Echo Reply sau phòng thủ
grep "echo reply" /tmp/lab04/tcpdump_vic_defended.log | wc -l
```

#### Phân Tích Cơ Chế Phòng Thủ:
- Khi bật `icmp_echo_ignore_broadcasts = 1`, trong mã nguồn kernel Linux (`net/ipv4/icmp.c` hàm `icmp_echo()`), kernel kiểm tra loại địa chỉ đích của gói tin bằng macro `RTN_BROADCAST` hoặc `RTN_MULTICAST`:
  - Nếu đích đến là địa chỉ quảng bá, hàm xử lý sẽ hủy bỏ gói tin ngay lập tức trước khi sinh gói phản hồi.
- **Kết quả trên `tcpdump_vic_defended.log`:**
  - Lệnh `grep "echo reply" ... | wc -l` trả về đúng con số: **`0`**.
  - Toàn bộ 10 gói tin broadcast của kẻ tấn công phát ra đã bị các máy trạm hấp thụ và loại bỏ âm thầm trong kernel, giảm triệt để 100% lưu lượng phản xạ dội về nạn nhân. Cuộc tấn công Smurf hoàn toàn bị vô hiệu hóa!

---

### 6. BƯỚC 5: DỌN DẸP MÔI TRƯỜNG

Khôi phục hệ thống:

```bash
# [HOST / CHUNG] Tắt tiến trình nền và xóa mạng LAN bridge
sudo pkill -f tcpdump 2>/dev/null || true
for ns in atk vic amp1 amp2 amp3; do sudo ip netns del $ns 2>/dev/null || true; done
sudo ip link del br0 2>/dev/null || true
sudo rm -rf /tmp/lab04
```

- Lệnh `ip link del br0` xóa bridge ảo khỏi kernel, đồng thời giải phóng tất cả các cổng mạng và bảng FDB liên kết với bridge đó.

