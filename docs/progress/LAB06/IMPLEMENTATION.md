# TÀI LIỆU KỸ THUẬT & KIẾN TRÚC THỰC THI: LAB 06
## Teardrop Attack (IP Fragmentation Overlap) & Kernel Reassembly Mechanics

---

### 1. NGUYÊN LÝ PHÂN MẢNH VÀ TÁI HỢP IPV4 (RFC 791)

Trong kiến trúc mạng IPv4, mỗi môi trường truyền dẫn vật lý có một giới hạn kích thước gói tin tối đa gọi là **Maximum Transmission Unit (MTU)** (ví dụ Ethernet chuẩn là 1500 bytes). Khi một router hoặc host cần truyền một gói tin lớn hơn MTU của chặng kế tiếp, gói tin bắt buộc phải được chia nhỏ (Fragmentation).

Quá trình tái hợp tại đích đến dựa trên 3 trường chính trong IPv4 Header (kích thước 32 bits):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

1. **Identification (16 bits):** Định danh duy nhất cho toàn bộ các mảnh thuộc về cùng một gói tin IP gốc.
2. **Flags (3 bits):**
   - Bit 0: Reserved (bắt buộc bằng 0).
   - Bit 1: **DF (Don't Fragment)** - Nếu bằng 1, cấm phân mảnh; router sẽ hủy gói và gửi ICMP Type 3 Code 4 (Fragmentation Needed) nếu gói vượt quá MTU.
   - Bit 2: **MF (More Fragments)** - Nếu bằng 1, báo hiệu vẫn còn mảnh tiếp theo phía sau; nếu bằng 0, báo hiệu đây là mảnh cuối cùng.
3. **Fragment Offset (13 bits):**
   - Chỉ định vị trí bắt đầu của khối dữ liệu trong gói tin gốc.
   - **Đơn vị tính toán:** Đo theo các khối **8 bytes (64 bits)**.
   - Công thức chuyển đổi: $\text{Byte Offset Thực Tế} = \text{Fragment Offset} \times 8$.

---

### 2. GIẢI PHẪU KỸ THUẬT TEARDROP ATTACK (CVE-1999-0015)

#### 2.1. Sơ Đồ Chồng Lấn Vùng Nhớ

Teardrop Attack lợi dụng việc tính toán sai lệch trường `Fragment Offset` để tạo ra sự giao thoa dữ liệu giữa các mảnh:

```
Vị trí Byte:  0       8               23      31
              +-------+---------------+-------+
Mảnh 1:       |       24 bytes (A)    |       |   (frag=0, MF=1, len=24)
              +-------+---------------+-------+
                      ^               ^
                      |<- 16 bytes  ->|
                      |   CHỒNG LẤN   |
                      +---------------+-------+
Mảnh 2:               |       24 bytes (B)    |   (frag=1, MF=0, len=24)
                      +---------------+-------+
```

- **Mảnh 1:** `frag = 0`, `MF = 1`, chứa 24 bytes ký tự `'A'` $\implies$ Vùng dữ liệu: `0 .. 23`.
- **Mảnh 2:** `frag = 1` ($\implies 1 \times 8 = \text{byte } 8$), `MF = 0`, chứa 24 bytes ký tự `'B'` $\implies$ Vùng dữ liệu: `8 .. 31`.
- **Vùng chồng lấn (Overlap):** Dải byte từ `8` đến `23` ($24 - 8 = 16\text{ bytes}$).

#### 2.2. Lỗ Hổng Tràn Bộ Đệm Nhân Cũ (Integer Underflow to Buffer Overflow)

1. Trên các nhân hệ điều hành cũ (Windows 95/98/NT 4.0, Linux Kernel < 2.0.32), khi mảnh 2 đến, kernel cố gắng tính toán độ dài dữ liệu còn lại chưa được ghi nhận từ mảnh 1:
   $$\text{offset\_diff} = \text{frag1.end} - \text{frag2.start} = 24 - 8 = 16$$
   $$\text{copy\_len} = \text{frag2.length} - \text{offset\_diff}$$
2. Nếu kẻ tấn công tinh chỉnh sao cho `frag2.length < offset_diff`, kết quả phép tính ra số âm. Trong ngôn ngữ C, biến độ dài thường khai báo là kiểu số nguyên không dấu (`size_t` hoặc `unsigned short`). Phép trừ số âm bị tràn số ngược (Integer Underflow):
   $$-1 \implies 0\text{xFFFFFFFF} \approx 4.29\text{ tỷ bytes}$$
3. Lệnh `memcpy(dst, src, copy_len)` thực hiện sao chép vùng nhớ khổng lồ đè bẹp toàn bộ bảng trang và bộ nhớ nhân, gây sập hệ điều hành tức thì (**Blue Screen of Death / Kernel Panic**).

---

### 3. CƠ CHẾ PHÒNG THỦ & XỬ LÝ CỦA LINUX KERNEL HIỆN ĐẠI

Trong nhân Linux hiện đại (Kernel 6.x / 7.x):

1. **Cấu trúc Dữ liệu Hàng đợi Mảnh (`inet_frag_queue`):**
   - Các mảnh được quản lý bằng cây nhị phân cân bằng Red-Black (`rb_node`), sắp xếp theo thứ tự `offset` tăng dần.
2. **Kiểm Tra Biên & Cắt Tỉa (Boundary Trimming):**
   - Khi một mảnh mới đến trong hàm `ip_frag_queue()` (`net/ipv4/ip_fragment.c`):
     - Kernel kiểm tra xem mảnh mới có giao thoa với mảnh đứng trước (`prev`) hay mảnh đứng sau (`next`) hay không.
     - Nếu có sự chồng lấn, kernel thực hiện điều chỉnh con trỏ dữ liệu `skb->data` và tăng `offset` để loại bỏ phần dư thừa, hoặc từ chối ghép mảnh nếu dữ liệu bị xung đột nghiêm trọng.
3. **Bộ Đếm Lỗi SNMP (`IPSTATS_MIB_REASMFAILS`):**
   - Nếu quá trình tái hợp thất bại hoặc quá hạn thời gian lưu giữ (`sysctl net.ipv4.ipfrag_time`, mặc định 30s), toàn bộ hàng đợi mảnh bị hủy bỏ và biến đếm `ReasmFails` trong `/proc/net/snmp` được cộng dồn đúng 1 đơn vị.

---

### 4. CÁC BIỆN PHÁP BẢO MẬT MẠNG TỔNG THỂ (RFC 1858 & RFC 3128)

1. **Kỹ thuật Lọc Phân Mảnh (Fragment Filtering - RFC 1858):**
   - Tường lửa (Firewall / IDS) phải kiểm tra mảnh đầu tiên (`offset = 0`): Nếu độ dài của mảnh đầu không đủ chứa toàn bộ Transport Header (ví dụ 20 bytes cho TCP, 8 bytes cho UDP), gói tin phải bị drop ngay lập tức (Tiny Fragment Attack).
2. **Kỹ thuật Làm Sạch Phân Mảnh (Fragment Scrubbing / Reassembly at Firewall):**
   - Tường lửa thế hệ mới (NGFW) đóng vai trò trung gian tái hợp (Virtual Reassembly): Thu thập toàn bộ các mảnh tại biên mạng, chuẩn hóa và tái hợp thành một gói tin IP hoàn chỉnh duy nhất trước khi chuyển tiếp vào mạng nội bộ. Điều này loại bỏ hoàn toàn các biến thể tấn công phân mảnh chồng lấn nhắm vào hệ thống đầu cuối.

