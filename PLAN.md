# Kế Hoạch Triển Khai Thực Nghiệm An Toàn Giao Thức TCP/IP

> **Dự án:** Chuyên đề Tấn công & Phòng thủ Lỗ hổng Bảo mật Giao thức TCP/IP  
> **Đơn vị:** Khoa CNTT - Trường Đại học Khoa học Tự nhiên, ĐHQG-HCM (HCMUS)  
> **Vai trò:** Senior Network Security Engineer & Protocol Researcher

---

## 1. Tổng Quan Môi Trường Thực Nghiệm

- **Máy chủ điều khiển (Host):** Windows OS, Antigravity Agent Workspace.
- **Hạ tầng máy ảo kiểm thử (Target/Execution Platform):**
  - **Hệ điều hành:** Kali Linux (VMware Workstation / VirtualBox, RAM $\ge$ 2GB).
  - **Địa chỉ IP quản trị:** `192.168.208.132/24` (Giao diện SSH Port 22, User: `tainbow`).
  - **Cơ chế cô lập mạng:** Linux Network Namespaces (`ip netns`), Linux Virtual Ethernet Pairs (`veth`), Linux Software Bridge (`br0`).
  - **Cơ chế tương tác:** Tự động hóa qua MCP Tool `kali-vm:ssh_execute`.
- **Nguyên tắc an toàn:**
  - Tuyệt đối không chạy lệnh Linux trực tiếp trên shell Windows của host.
  - Mọi kịch bản khai thác được giới hạn hoàn toàn trong các network namespace cục bộ của Kali VM, tránh rò rỉ lưu lượng tấn công ra mạng bên ngoài.
  - Dọn dẹp tài nguyên (`ip netns del`, `ip link del`, tắt tiến trình nền `pkill`) trước và sau mỗi bài thực hành.

---

## 2. Ma Trận Tiến Độ 7 Bài Thực Hành

| Mã Lab | Tên Bài Thực Hành | Mục Tiêu & Cơ Chế Trọng Tâm | Phân Loại Kỹ Thuật | Công Cụ & Thư Viện | Trạng Thái |
| :--- | :--- | :--- | :--- | :--- | :---: |
| **LAB 01** | **TCP ISN Prediction & Blind Spoofing** | Dự đoán số thứ tự ban đầu (ISN), bắt tay 3 bước giả mạo mù (off-path/on-path), đánh giá RFC 6528. | TCP Spoofing, Session Hijacking | `Scapy`, `tcpdump`, `ncat`, `iptables` | [x] Verified |
| **LAB 02** | **IP Source Routing Vulnerability** | Lợi dụng tùy chọn IP LSRR/SSRR ép định tuyến phản hồi, vượt qua kiểm tra chống giả mạo nguồn. | Route Hijacking, IP Spoofing | `Scapy (IPOption_SSRR)`, `tcpdump`, `sysctl` | [x] Verified |
| **LAB 03** | **ICMP Tunneling (Covert Channel)** | Tạo kênh truyền ngầm tuồn dữ liệu (data exfiltration) qua ICMP Echo payload, vượt tường lửa tầng 4. | Covert Channel, Firewall Evasion | `Scapy`, `tcpdump`, `iptables`, `sysctl` | [x] Verified |
| **LAB 04** | **Smurf Attack (ICMP Broadcast Amplification)** | Khuếch đại từ chối dịch vụ (DoS) bằng ICMP echo broadcast kết hợp giả mạo IP nguồn của nạn nhân. | Amplification DoS, IP Spoofing | `Scapy`, `tcpdump`, `sysctl` (bridge LAN) | [x] Verified |
| **LAB 05** | **ICMP Redirect Attack** | Giả mạo thông điệp ICMP Redirect (Type 5) từ Default Gateway để chuyển hướng định tuyến của nạn nhân (MITM). | Route Hijacking, Man-in-the-Middle | `Scapy`, `tcpdump`, `iproute2`, `sysctl` | [x] Verified |
| **LAB 06** | **Teardrop Attack (Fragment Overlap)** | Chế tạo các mảnh IP phân đoạn chồng lấn (overlapping fragments) kiểm tra cơ chế tái hợp gói của kernel. | Denial of Service, Fragmentation | `Scapy`, `tcpdump`, `/proc/net/snmp` | [x] Verified |
| **LAB 07** | **DNS Security Extensions (DNSSEC)** | Triển khai vùng DNSSEC có chữ ký (BIND9), cấu hình validating resolver (Unbound), phát hiện giả mạo bản ghi. | DNS Spoofing Defense, Integrity & Auth | `BIND9 (named)`, `Unbound`, `dig`, `tcpdump` | [x] Verified |

*Ghi chú quy ước trạng thái:* `[ ] Not Started` (Chưa thực hiện) $\rightarrow$ `[ ] In Progress` (Đang triển khai) $\rightarrow$ `[x] Verified` (Đã kiểm chứng & có đầy đủ log minh chứng).

---

## 3. Quy Trình Chuẩn Triển Khai Từng Bài (Execution Workflow)

1. **Giai đoạn 0: Khởi tạo tài liệu lý thuyết & Lập kế hoạch** *(Hiện tại)*
   - Đọc kỹ tài liệu PDF đề bài.
   - Trích xuất tài liệu lý thuyết, chuẩn RFC, phân tích nguyên lý tấn công, giải pháp phòng thủ và giải đáp câu hỏi ôn tập vào `docs/theory/`.
   - Thiết lập `PLAN.md`.
2. **Giai đoạn 1: Chuẩn bị Script cục bộ**
   - Viết scripts cấu hình topo (`setup_*.sh`), scripts Scapy tấn công và kịch bản quan sát vào `docs/progress/LAB0X/scripts/`.
3. **Giai đoạn 2: Triển khai từ xa & Thực nghiệm**
   - Đẩy scripts lên Kali VM qua SSH MCP, thiết lập quyền thực thi.
   - Chạy kịch bản tấn công và thu thập log kết quả thực tế (stdout, stderr, pcap/tcpdump text).
4. **Giai đoạn 3: Tổng hợp báo cáo & Đóng gói minh chứng**
   - Ghi nhận output terminal thực tế vào `docs/progress/LAB0X/labX_result.md`.
   - Viết tài liệu phân tích chi tiết vào `docs/progress/LAB0X/labX_IMPLEMENTATION.md`.
   - Dọn dẹp sạch sẽ môi trường lab trên Kali VM và cập nhật trạng thái `PLAN.md`.

