# HƯỚNG DẪN TRIỂN KHAI & PHÂN TÍCH KỸ THUẬT: LAB 02
## Phân Tích Lỗ Hổng IP Source Routing (LSRR/SSRR) & Kỹ Thuật Lọc Biên

---

### 1. Kiến Trúc Mạng & Mục Đích Từng Bước Triển Khai

Thực nghiệm sử dụng mô hình hai máy ảo cô lập bằng Linux Network Namespaces (`h1` - Attacker tại `10.0.0.1/24`, `h2` - Victim tại `10.0.0.2/24`) nối với nhau qua cặp card mạng ảo `veth1 <-> veth2`.

```
[ Namespace h1 (Attacker) ]                     [ Namespace h2 (Victim) ]
+-------------------------+                     +-------------------------+
| IP: 10.0.0.1/24         |                     | IP: 10.0.0.2/24         |
| Interface: veth1        | <=== (veth link) => | Interface: veth2        |
| Script: ssrr.py         |                     | Defense: sysctl config  |
+-------------------------+                     +-------------------------+
```

#### Phân Tích Các Tham Số Cấu Hình Hạt Nhân (Kernel Sysctl):
- `net.ipv4.conf.*.accept_source_route`:
  - **Khi bằng 1 (Tái tạo lỗ hổng):** Kernel cho phép xử lý và tuân thủ các chỉ dẫn định tuyến nằm trong trường Option của tiêu đề IPv4 (LSRR/SSRR).
  - **Khi bằng 0 (Mặc định phòng thủ):** Kernel loại bỏ ngay lập tức bất kỳ gói tin nào chứa tùy chọn Source Routing tại điểm vào `ip_rcv_finish_core` thông qua macro `IN_DEV_SOURCE_ROUTE`.
- `net.ipv4.conf.*.rp_filter`:
  - Tham số Reverse Path Filtering (RFC 3704).
  - Khi đặt bằng 0: Vô hiệu hóa việc kiểm tra tính đối xứng của cổng nhận gói với bảng định tuyến FIB, cho phép các gói tin mang địa chỉ IP nguồn lạ hoặc giả mạo (`10.0.0.77`) đi vào tầng mạng.
- `net.ipv4.ip_forward`:
  - Khi bật bằng 1: Cho phép máy Victim chuyển tiếp gói tin theo danh sách chặng router quy định trong tùy chọn SSRR khi nó đóng vai trò là một chặng trung gian.

---

### 2. Giải Mã Kỹ Thuật Mã Nguồn Scapy `IPOption_SSRR`

Trong kịch bản `ssrr.py`:
```python
pkt = IP(src="10.0.0.77", dst="10.0.0.2",
         options=[IPOption_SSRR(routers=["10.0.0.1", "10.0.0.2"])]) \
      / ICMP(id=0x4242) / b"src-routed-probe"
```

#### Ý Nghĩa Từng Trường Trong Gói Tin:
1. `src="10.0.0.77"`:
   - Địa chỉ IP nguồn bị giả mạo. Trong một mạng thực tế, đây có thể là địa chỉ của máy chủ quản trị tin cậy (Trusted Admin Host) nằm phía sau một phân đoạn mạng khác.
2. `dst="10.0.0.2"`:
   - Địa chỉ IP đích của Victim.
3. `options=[IPOption_SSRR(routers=["10.0.0.1", "10.0.0.2"])]`:
   - `Type = 137 (0x89)`: Strict Source and Record Route.
   - `Length = 11 bytes` (hoặc 12 bytes kèm padding làm tròn 32-bit): Gồm 1 byte Type, 1 byte Length, 1 byte Pointer, và 8 bytes chứa 2 địa chỉ IP.
   - `Pointer = 4`: Trỏ vào địa chỉ IP đầu tiên trong danh sách (`10.0.0.1`).
   - `routers`: Danh sách các nút bắt buộc phải đi qua. Bằng việc đưa địa chỉ của chính mình (`10.0.0.1`) vào danh sách, kẻ tấn công ép máy nhận phải chuyển tiếp gói tin quay trở lại mình dù địa chỉ IP nguồn chính thức là `10.0.0.77`.

---

### 3. Cơ Chế Phát Hiện Gói Tin Bằng Biểu Thức BPF `ip[0] & 0x0f > 5`

Cấu trúc byte đầu tiên của IPv4 Header:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |    Type of Service    |          Total Length |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Byte 0 (`ip[0]`) bao gồm:
  - 4 bit cao: `Version` (cho IPv4 luôn là `4` $\rightarrow$ `0100` nhị phân).
  - 4 bit thấp: `IHL` (Internet Header Length $\rightarrow$ số lượng từ 32-bit của IP header).
- Để trích xuất trường IHL, ta dùng phép toán bitwise AND với mặt nạ `0x0f` (`00001111`):
  $$\text{IHL} = \text{ip}[0] \ \& \ 0\text{x0f}$$
- Với một gói IP tiêu chuẩn không chứa IP Options: Header dài 20 bytes $\implies \text{IHL} = 20 / 4 = 5$.
- Bất kỳ gói tin nào mang thêm Options (như LSRR, SSRR, Record Route, Timestamp) đều có kích thước header tối thiểu 24 bytes hoặc lớn hơn $\implies \text{IHL} \ge 6 > 5$.
- Do đó, biểu thức lọc `ip[0] & 0x0f > 5` là một chữ ký nhận diện cực kỳ nhẹ, tối ưu và chuẩn xác tuyệt đối để các thiết bị tường lửa biên (Edge Firewall) loại bỏ các gói tin chứa nguy cơ tiềm ẩn mà không cần tốn chi phí giải mã sâu.

---

### 4. Kết Luận Phòng Thủ & Tiêu Chuẩn Hiện Đại

1. **Vô hiệu hóa toàn diện trên End-host (RFC 1122 & Linux Defaults):**
   - Thiết lập `net.ipv4.conf.all.accept_source_route = 0` và `net.ipv4.conf.default.accept_source_route = 0`. Mặc định trên toàn bộ các bản phân phối Linux và Windows hiện đại, tính năng này đều đã bị tắt vĩnh viễn.
2. **Loại bỏ gói tin tại Router Biên (RFC 7126 / BCP 38):**
   - Không chuyển tiếp và hủy bỏ ngay các gói tin chứa tùy chọn Source Routing tại các cổng tiếp giáp Internet của nhà mạng và doanh nghiệp (`no ip source-route`).
3. **Kích hoạt Strict Reverse Path Filtering (`rp_filter = 1`):**
   - Bảo đảm mọi gói tin có địa chỉ IP nguồn bất thường không thể tiếp cận ngăn xếp mạng nội bộ.

