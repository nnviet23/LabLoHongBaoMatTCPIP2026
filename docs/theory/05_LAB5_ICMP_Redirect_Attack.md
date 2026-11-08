# BÁO CÁO LÝ THUYẾT & PHÂN TÍCH CHUYÊN SÂU: LAB 05
## Kỹ Thuật Tấn Công ICMP Redirect Attack (Route Hijacking & Man-in-the-Middle)

---

### 1. Mục Tiêu & Chuẩn RFC Liên Quan

#### 1.1 Mục Tiêu Bài Học (Trích xuất từ tài liệu đề bài)
- Thấu hiểu cơ chế hoạt động của thông điệp ICMP Redirect (Type 5) và nguyên lý hệ điều hành cập nhật bảng lưu tạm định tuyến (Route Cache / FIB Exceptions) khi tiếp nhận thông báo này.
- Kỹ thuật chế tạo và gửi gói tin ICMP Redirect giả mạo từ máy kẻ tấn công nhằm ép nạn nhân chuyển hướng toàn bộ lưu lượng định tuyến tới một đích cụ thể đi qua máy kẻ tấn công (Man-in-the-Middle - MITM).
- Quan sát và ghi nhận trực tiếp sự thay đổi trong Route Cache của nạn nhân bằng các công cụ `iproute2`; sau đó cấu hình các tham số bảo vệ hạt nhân (`accept_redirects=0`) để kiểm chứng khả năng miễn nhiễm.

#### 1.2 Các Chuẩn RFC và Tài Liệu Học Thuật Tham Chiếu
- **RFC 792 (Internet Control Message Protocol - 1981):** Định nghĩa cấu trúc thông điệp ICMP Redirect (Type 5) với 4 mã Code:
  - Code 0: Redirect datagrams for the Network.
  - Code 1: Redirect datagrams for the Host.
  - Code 2: Redirect datagrams for the Type of Service and Network.
  - Code 3: Redirect datagrams for the Type of Service and Host.
- **RFC 1122 (Requirements for Internet Hosts - Communication Layers - 1989):** Quy định các điều kiện an toàn nghiêm ngặt mà một máy trạm (Host) bắt buộc phải kiểm tra trước khi chấp nhận cập nhật bảng định tuyến từ gói ICMP Redirect (Section 3.2.2.2).
- **Linux Kernel Documentation (`Documentation/networking/ip-sysctl.txt`):** Quy định chi tiết các cờ kiểm soát của nhân hệ điều hành Linux đối với việc gửi và nhận thông điệp chuyển hướng định tuyến (`accept_redirects`, `secure_redirects`, `send_redirects`).

---

### 2. Nguyên Lý Tấn Công & Điểm Yếu Giao Thức

#### 2.1 Mục Đích Ban Đầu Của ICMP Redirect Trong Mạng IP
Trong mô hình mạng chia sẻ môi trường truyền dẫn (Broadcast Media / Shared Subnet):
- Một mạng LAN có thể có nhiều hơn một Gateway kết nối tới các vùng mạng bên ngoài khác nhau (ví dụ $GW_1$ đi ra Internet, $GW_2$ đi vào mạng diện rộng nội bộ WAN).
- Máy trạm ban đầu thường chỉ trỏ Default Gateway duy nhất về $GW_1$. Khi máy trạm gửi một gói tin tới một đích nằm sau $GW_2$, $GW_1$ nhận gói tin và nhận thấy cổng mạng đi ra (outbound interface) lại chính là cổng mạng vừa nhận gói tin (inbound interface).
- Để tối ưu hóa đường truyền và tránh lãng phí băng thông chuyển tiếp 2 lần trên cùng một dây cáp, $GW_1$ sẽ:
  1. Vẫn chuyển tiếp gói tin đó tới $GW_2$.
  2. Đồng thời gửi một thông điệp **ICMP Redirect (Type 5, Code 1)** về máy trạm với nội dung: *"Lần sau, nếu gửi tới địa chỉ đích đó, hãy gửi trực tiếp đến $GW_2$ ($10.0.0.66$) thay vì gửi cho tôi"*.
- Máy trạm nhận được thông điệp sẽ lưu tạm một tuyến đường ngoại lệ (Route Cache / Exception) để các gói tiếp theo đi thẳng tới $GW_2$.

#### 2.2 Điểm Yếu Giao Thức & Kỹ Thuật Chiếm Phiên Định Tuyến (Route Hijacking)
- **Điểm yếu cốt lõi:** Thông điệp ICMP Redirect hoàn toàn **không có bất kỳ cơ chế xác thực hoặc chữ ký mật mã nào**. Hệ điều hành chỉ dựa vào việc so khớp thông tin tiêu đề gói tin để quyết định tin cậy.
- **Quy trình tấn công:**
  1. Máy nạn nhân ($10.0.0.2$) đang gửi dữ liệu tới một máy chủ đích ($10.0.1.5$) thông qua Gateway hợp pháp ($10.0.0.1$).
  2. Kẻ tấn công ($10.0.0.66$) nằm cùng phân đoạn mạng LAN chế tạo một gói tin ICMP Redirect đặc biệt:
     - $IP_{\text{src}} = 10.0.0.1$ (Giả mạo chính xác địa chỉ IP của Gateway hiện tại).
     - $IP_{\text{dst}} = 10.0.0.2$ (Địa chỉ IP của Nạn nhân).
     - `Type = 5`, `Code = 1` (Redirect for Host).
     - `Gateway Address = 10.0.0.66` (Chỉ định Gateway tối ưu mới chính là máy của Attacker).
     - `Payload = IP Header + 8 bytes` dữ liệu của gói tin mà nạn nhân vừa mới gửi đi trước đó.
  3. Khi nạn nhân nhận được gói tin, kiểm tra thấy nguồn gửi đúng là Gateway quen thuộc ($10.0.0.1$) và gói tin đính kèm đúng là gói mình vừa gửi, kernel nạn nhân lập tức cập nhật Route Cache: trỏ tuyến đường đi $10.0.1.5$ qua Gateway mới là $10.0.0.66$.
  4. Toàn bộ các gói tin tiếp theo từ nạn nhân tới đích $10.0.1.5$ sẽ được chuyển thẳng tới máy của Attacker. Attacker chính thức thiết lập vị trí đứng giữa (Man-in-the-Middle) để nghe lén, ghi lại thông tin hoặc sửa đổi gói tin trước khi chuyển tiếp tiếp tới đích.

```
[ Victim (10.0.0.2) ] --------------------> [ Gateway (10.0.0.1) ] ---> [ Dst (10.0.1.5) ]
         |                                           ^
         |                                           |
         | (1. Attacker giả danh Gateway gửi         |
         |     ICMP Redirect: "Dùng GW 10.0.0.66")   |
         v                                           |
[ Attacker (10.0.0.66) ] <----------------------------
         |
         +--> Toàn bộ gói tin tới 10.0.1.5 giờ bị ép gửi qua Attacker (MITM)!
```

---

### 3. Cơ Chế Phòng Thủ (Mitigation)

#### 3.1 Cấu Hình Hệ Điều Hành Nhân Linux (Kernel Sysctl)
Đây là biện pháp hiệu quả và triệt để nhất trên các máy trạm hiện đại:
```bash
# Vô hiệu hóa tiếp nhận ICMP Redirect trên mọi interface (Bắt buộc cho Server và Desktop)
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0

# Tắt tính năng tự động sinh và gửi gói ICMP Redirect trên các máy chủ không làm router
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0

# Xóa bỏ các tuyến đường rác đang bị lưu tạm trong cache
ip route flush cache
```
- Khi `accept_redirects = 0`: Kernel sẽ vứt bỏ hoàn toàn mọi gói tin ICMP Type 5 mà nó nhận được, giữ vững bảng định tuyến tĩnh đã được cấu hình từ trước.

#### 3.2 Cơ Chế Secure Redirects (`net.ipv4.conf.*.secure_redirects`)
- Linux cung cấp cờ `secure_redirects` (mặc định = 1 trên nhiều bản phân phối). Khi cờ này bật, kernel chỉ chấp nhận thông điệp ICMP Redirect nếu nó đến từ một Gateway đã được khai báo sẵn trong bảng định tuyến tĩnh chính thức của hệ thống. Tuy nhiên, nếu kẻ tấn công giả mạo được đúng IP của Gateway đó thì cơ chế này vẫn có thể bị đánh lừa. Do đó, cách an toàn nhất cho máy trạm thông thường là tắt hẳn `accept_redirects=0`.

#### 3.3 Phòng Thủ Tầng Liên Kết Dữ Liệu (Layer 2 Defenses)
- **Phân đoạn mạng (VLAN Segmentation):** Tách kẻ tấn công và các máy trạm nhạy cảm vào các Broadcast Domain khác nhau. Vì gói tin giả mạo IP của Gateway đòi hỏi kẻ tấn công phải ở cùng phân đoạn L2 để đẩy gói Ethernet trực tiếp tới nạn nhân.
- **Dynamic ARP Inspection (DAI) & IP Source Guard:** Ngăn chặn việc kẻ tấn công chiếm đoạt hoặc giả mạo địa chỉ IP/MAC của Gateway trên switch cứng.

#### 3.4 Giám Sát An Ninh Mạng (IDS / SIEM)
- Thiết lập luật phát hiện trên Snort / Suricata cảnh báo khi có sự xuất hiện bất thường của gói ICMP Type 5 trên phân đoạn mạng người dùng:
  ```text
  alert icmp any any -> any any (msg:"Suspicious ICMP Redirect Detected"; itype:5; sid:1000005; rev:1;)
  ```

---

### 4. Giải Đáp Chi Tiết Câu Hỏi Ôn Tập (Review Questions)

#### Câu 1: Điều kiện nào để Linux chấp nhận một gói ICMP Redirect? Vì sao attacker phải đặt src = địa chỉ GW?
- **Các điều kiện bắt buộc để nhân Linux (Kernel) chấp nhận một gói ICMP Redirect:**
  1. Tham số hệ thống `net.ipv4.conf.<interface>.accept_redirects` phải đang được kích hoạt (bằng $1$).
  2. Gói tin ICMP Redirect phải có địa chỉ IP nguồn ($IP_{\text{src}}$) **trùng khớp chính xác** với địa chỉ IP của Gateway hiện tại mà host nạn nhân đang sử dụng để tiếp cận địa chỉ đích.
  3. Gói tin phải đính kèm phần dữ liệu hợp lệ gồm tiêu đề IP ban đầu kèm tối thiểu 8 bytes dữ liệu tầng giao vận của một gói tin mà chính host nạn nhân đã phát ra gần đây tới địa chỉ đích.
  4. Nếu cờ `secure_redirects = 1`, địa chỉ Gateway mới được gợi ý bắt buộc phải nằm trên cùng một phân đoạn mạng cục bộ (directly connected subnet) với giao diện mạng nhận gói.
  5. Hệ điều hành hiện tại không được kích hoạt chế độ IP Forwarding (tức không phải là Router).
- **Vì sao attacker bắt buộc phải đặt $IP_{\text{src}} = \text{địa chỉ GW}$:**
  - Theo logic an toàn của RFC 1122 và mã nguồn kernel Linux, một máy trạm chỉ chấp nhận sự điều chỉnh đường đi từ chính thiết bị mà nó đang ủy thác chuyển tiếp gói tin (Default Gateway hiện tại).
  - Nếu attacker gửi gói tin với $IP_{\text{src}}$ là IP riêng của attacker ($10.0.0.66$), kernel nạn nhân sẽ ngay lập tức phát hiện đây là thông điệp từ một nút mạng không có thẩm quyền định tuyến cho luồng đó và hủy bỏ gói tin ngay lập tức.

#### Câu 2: Vai trò của phần 'gói gốc' đính kèm trong thông điệp redirect là gì?
- **Cấu trúc phần 'gói gốc':** Theo quy định của RFC 792, sau 8 bytes tiêu đề ICMP Redirect bắt buộc phải chứa nguyên vẹn tiêu đề IP (IP Header) cộng thêm tối thiểu 64 bit (8 bytes) đầu tiên của vùng dữ liệu (Data) thuộc về gói tin đã kích hoạt việc sinh ra Redirect (gói tin ban đầu mà nạn nhân gửi đi).
- **Vai trò quan trọng:**
  1. **Xác thực ngữ cảnh kết nối (State Verification):** Giúp kernel của host nạn nhân kiểm tra xem thông điệp chuyển hướng này có thực sự tương ứng với một phiên truyền thông mà máy trạm đang thực hiện hay không.
  2. **Trích xuất thông số định tuyến:** Kernel lấy địa chỉ IP đích nằm trong tiêu đề của gói gốc để biết chính xác tuyến đường tới Host nào cần phải cập nhật sang Gateway mới.
  3. **Ngăn chặn tấn công ngẫu nhiên (Blind Attack Defense):** Nếu không có yêu cầu đính kèm gói gốc, kẻ tấn công ngoài mạng có thể gửi các thông điệp redirect vu vơ để làm sai lệch toàn bộ bảng định tuyến của hệ thống.

#### Câu 3: So sánh ICMP Redirect attack với ARP spoofing về mục tiêu và tầng hoạt động.
| Tiêu chí | ICMP Redirect Attack | ARP Spoofing / Poisoning |
| :--- | :--- | :--- |
| **Tầng hoạt động** | **Tầng Mạng (Layer 3 - Network Layer)**, đóng gói trực tiếp trong giao thức IP. | **Tầng Liên kết dữ liệu (Layer 2 - Data Link Layer)**, hoạt động trên các khung Ethernet thô. |
| **Giao thức khai thác** | Giao thức điều khiển ICMP (Type 5). | Giao thức phân giải địa chỉ ARP (ARP Reply / Gratuitous ARP). |
| **Bảng dữ liệu bị sửa đổi** | **Bảng bộ nhớ định tuyến tạm thời (Route Cache / FIB Exception Table)** của hệ điều hành. | **Bảng ánh xạ địa chỉ IP-MAC (ARP Cache / Neighbor Table)** của card mạng. |
| **Phạm vi tác động** | Có thể chuyển hướng định tuyến của một **địa chỉ IP đích cụ thể** nằm ở mạng khác (Host-specific Redirect), giữ nguyên đường đi của các đích khác. | Đánh tráo toàn bộ lưu lượng qua lại giữa nạn nhân với Default Gateway (chuyển hướng tất cả mọi lưu lượng tầng 2). |
| **Điều kiện tiên quyết** | Nạn nhân phải đang kích hoạt `accept_redirects=1` và phải có một luồng gói tin gửi đi để kích hoạt. | Nạn nhân chấp nhận gói ARP Reply mà không kiểm tra trạng thái yêu cầu trước đó (State-less). |
| **Mục tiêu tấn công** | Man-in-the-Middle (MITM), định tuyến lại lưu lượng, hoặc gây Từ chối dịch vụ (DoS trỏ vào blackhole IP). | Man-in-the-Middle (MITM), nghe lén toàn bộ mạng LAN, bắt trộm mật khẩu, DNS Spoofing. |

#### Câu 4: Giải thích khác biệt giữa `accept_redirects=0` và `secure_redirects=1`. Nên dùng cái nào cho máy trạm?
- **Khác biệt về mặt cơ chế:**
  - `accept_redirects = 0`: **Vô hiệu hóa tuyệt đối.** Hệ điều hành từ chối, vứt bỏ $100\%$ mọi thông điệp ICMP Redirect mà nó nhận được trên giao diện mạng, bất kể gói tin đó được gửi từ ai (kể cả router hợp pháp hay kẻ tấn công). Bảng định tuyến của host là cố định và chỉ thay đổi khi quản trị viên hoặc tiến trình DHCP can thiệp.
  - `secure_redirects = 1`: **Chấp nhận có điều kiện hạn chế.** Kernel chỉ chấp nhận gói ICMP Redirect nếu: (1) Địa chỉ IP nguồn của gói tin trùng khớp với một trong các Gateway đã được cấu hình trong bảng định tuyến, VÀ (2) Gateway mới được trỏ tới phải nằm trên cùng phân đoạn mạng (subnet) cục bộ. Tuy nhiên, tính năng này **không chống được** trường hợp kẻ tấn công cùng phân đoạn mạng LAN mạo danh địa chỉ IP của Gateway hợp pháp.
- **Khuyến nghị cho máy trạm (End-host / Workstation):**
  - **NÊN DÙNG `accept_redirects = 0`**.
  - **Lý do:** Đối với các máy trạm và máy chủ thông thường trong doanh nghiệp, cấu hình mạng thường rất đơn giản và ổn định (mỗi subnet thường chỉ có một Default Gateway duy nhất ra mạng ngoài). Khả năng mạng nội bộ cần tối ưu định tuyến bằng ICMP Redirect trong thực tế gần như bằng không. Việc để `secure_redirects=1` vẫn tiềm ẩn lỗ hổng bị tấn công MITM bởi kẻ nội gián (Insider Threat) cùng mạng LAN mạo danh IP Gateway. Tắt hoàn toàn (`accept_redirects=0`) là tiêu chuẩn an ninh mạng nghiêm ngặt nhất được khuyến nghị bởi CIS Benchmarks và NIST.

