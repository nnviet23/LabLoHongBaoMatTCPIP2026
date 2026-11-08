# Chuyên Đề Nghiên Cứu & Thực Nghiệm Lỗ Hổng Bảo Mật Giao Thức TCP/IP

> **Học phần:** Chuyên đề Tốt nghiệp Mạng máy tính & An toàn Thông tin  
> **Đơn vị:** Khoa Công nghệ Thông tin - Trường Đại học Khoa học Tự nhiên, ĐHQG-HCM (HCMUS)  
> **Nền tảng kiểm thử:** Kali Linux VM cô lập bằng Linux Network Namespaces (`ip netns`), Linux Software Bridge (`br0`) và Scapy  

---

## 1. TỔNG QUAN DỰ ÁN

Dự án triển khai và kiểm chứng toàn diện **7 bài thực hành an toàn mạng chuyên sâu** về các lỗ hổng kinh điển và cơ chế phòng thủ cốt lõi của bộ giao thức TCP/IP. Toàn bộ các kịch bản được thực thi trên môi trường mạng ảo cô lập cục bộ, đảm bảo tính an toàn tuyệt đối, khả năng tái lập 100% và bám sát các tiêu chuẩn RFC của Internet.

### Ma Trận 7 Bài Thực Hành

| Mã Lab | Tên Bài Thực Hành | Mục Tiêu & Cơ Chế Trọng Tâm | Hướng Dẫn Nhanh | Trạng Thái |
| :---: | :--- | :--- | :---: | :---: |
| **LAB 01** | **TCP ISN Prediction & Blind Spoofing** | Dự đoán ISN, giả mạo bắt tay 3 bước TCP (RFC 6528). | [Xem Lab 01](docs/progress/LAB01/lab1_GET_STARTED.md) | `[x] Verified` |
| **LAB 02** | **IP Source Routing Vulnerability** | Ép định tuyến bằng IP SSRR/LSRR, lọc gói IHL > 5. | [Xem Lab 02](docs/progress/LAB02/lab2_GET_STARTED.md) | `[x] Verified` |
| **LAB 03** | **ICMP Tunneling (Covert Channel)** | Tạo kênh truyền ngầm tuồn dữ liệu qua ICMP payload, vượt firewall L4. | [Xem Lab 03](docs/progress/LAB03/lab3_GET_STARTED.md) | `[x] Verified` |
| **LAB 04** | **Smurf Attack (Broadcast Amplification)** | Khuếch đại DoS directed broadcast ($K = \times 3$), chặn bằng sysctl. | [Xem Lab 04](docs/progress/LAB04/lab4_GET_STARTED.md) | `[x] Verified` |
| **LAB 05** | **ICMP Redirect Attack (Route Hijacking)** | Bẻ lái định tuyến bằng ICMP Type 5 (FIB Nexthop Exception / MITM). | [Xem Lab 05](docs/progress/LAB05/lab5_GET_STARTED.md) | `[x] Verified` |
| **LAB 06** | **Teardrop Attack (Fragment Overlap)** | Phân đoạn IP chồng lấn (CVE-1999-0015), kiểm tra SNMP `ReasmFails`. | [Xem Lab 06](docs/progress/LAB06/lab6_GET_STARTED.md) | `[x] Verified` |
| **LAB 07** | **DNS Security Extensions (DNSSEC)** | BIND9 tự động ký ECDSA P-256, Unbound xác thực cờ `ad`, chặn bằng `SERVFAIL`. | [Xem Lab 07](docs/progress/LAB07/lab7_GET_STARTED.md) | `[x] Verified` |

---

## 2. HƯỚNG DẪN CÀI ĐẶT CÔNG CỤ TRÊN KALI LINUX

Để tự thực hành đầy đủ cả 7 bài lab, môi trường máy ảo Kali Linux (hoặc Ubuntu/Debian) cần được trang bị các gói công cụ mạng, biên dịch và các dịch vụ DNS.

### 2.1. Lệnh Cài Đặt Tất Cả Các Tool (One-liner)

Chạy câu lệnh duy nhất sau trong terminal của Kali Linux:

```bash
sudo apt update && sudo apt install -y \
    python3 \
    python3-pip \
    python3-scapy \
    tcpdump \
    iproute2 \
    net-tools \
    ncat \
    iptables \
    bind9 \
    bind9-utils \
    bind9-dnsutils \
    unbound \
    apparmor-utils
```

### 2.2. Danh Mục & Vai Trò Của Từng Công Cụ

| Công Cụ / Gói | Vai Trò Trong Bài Lab | Các Lab Sử Dụng |
| :--- | :--- | :---: |
| **`python3-scapy`** | Thư viện chế tạo, thao tác và gửi/bắt gói tin cấp thấp (Raw Packets). | Lab 1, 2, 3, 4, 5, 6 |
| **`tcpdump`** | Công cụ bắt và phân tích gói tin mạng chuyên sâu từ dòng lệnh. | Tất cả 7 Labs |
| **`iproute2` (`ip netns`, `ip link`, `ip route`)** | Quản lý mạng Linux, tạo Network Namespaces, veth pairs và cấu hình định tuyến. | Tất cả 7 Labs |
| **`ncat` (netcat)** | Thiết lập máy chủ TCP lắng nghe kiểm thử bắt tay giả mạo mù. | Lab 1, Lab 3 |
| **`iptables`** | Thiết lập luật lọc gói tầng 4 (chặn TCP để kiểm chứng vượt firewall). | Lab 1, Lab 3 |
| **`bind9` & `bind9-dnsutils` (`dig`)** | Máy chủ DNS Authoritative Server hỗ trợ ký DNSSEC và công cụ truy vấn DNS. | Lab 7 |
| **`unbound`** | Máy chủ DNS Recursive Resolver thực hiện kiểm chứng mật mã DNSSEC (Validating Resolver). | Lab 7 |
| **`apparmor-utils` (`aa-disable`)** | Quản lý chính sách bảo mật AppArmor cho phép BIND9 & Unbound nạp cấu hình tùy biến. | Lab 7 |

---

## 3. KIỂM TRA CÀI ĐẶT CÔNG CỤ THÀNH CÔNG

Chạy đoạn script bash kiểm tra nhanh sau đây để xác nhận 100% công cụ đã sẵn sàng:

```bash
cat << 'EOF' > /tmp/check_tools.sh
#!/usr/bin/env bash
echo "=== KIỂM TRA CÁC CÔNG CỤ YÊU CẦU CHO LAB TCP/IP ==="
TOOLS=("python3" "scapy" "tcpdump" "ip" "nc" "iptables" "named" "unbound" "dig" "aa-disable")

for tool in "${TOOLS[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "[OK] Đã cài đặt: $tool ($(which $tool))"
    else
        echo "[MISSING] Chưa tìm thấy: $tool"
    fi
done

# Kiểm tra thư viện Scapy trong Python3
if python3 -c "import scapy" >/dev/null 2>&1; then
    echo "[OK] Python3 module Scapy: Sẵn sàng ($(python3 -c 'import scapy; print(scapy.__version__)'))"
else
    echo "[MISSING] Python3 module Scapy: Chưa cài đặt"
fi
EOF
chmod +x /tmp/check_tools.sh
/tmp/check_tools.sh
```

**Kết quả mong đợi:** Tất cả các mục đều hiển thị nhãn `[OK]`.

---

## 4. CẤU TRÚC THƯ MỤC DỰ ÁN

```
LabLoHongBaoMatTCPIP/
├── README.md                          # Tài liệu tổng quan & hướng dẫn cài đặt môi trường
├── PLAN.md                            # Lộ trình master & ma trận tiến độ kiểm chứng 7 bài lab
├── rules.md                           # Các quy tắc và tiêu chuẩn kỹ thuật
├── docs/
│   ├── Lab/                           # 7 tài liệu đề bài chính thức (PDF)
│   │   ├── Lab01_TCP_Sequence_Number_Prediction.pdf
│   │   ├── Lab02_Source_Routing.pdf
│   │   ├── Lab03_ICMP_Tunneling.pdf
│   │   ├── Lab04_Smurf_Attack.pdf
│   │   ├── Lab05_ICMP_Redirect_Attack.pdf
│   │   ├── Lab06_Teardrop_Attack.pdf
│   │   └── Lab07_DNSSEC.pdf
│   ├── theory/                        # 7 tài liệu lý thuyết chuẩn RFC & giải đáp câu hỏi
│   │   ├── 01_LAB1_TCP_ISN_Prediction.md
│   │   ├── 02_LAB2_Source_Routing.md
│   │   ├── 03_LAB3_ICMP_Tunneling.md
│   │   ├── 04_LAB4_Smurf_Attack.md
│   │   ├── 05_LAB5_ICMP_Redirect_Attack.md
│   │   ├── 06_LAB6_Teardrop_Attack.md
│   │   └── 07_LAB7_DNSSEC.md
│   ├── GET START/                     # Chiến lược triển khai từng bài lab
│   │   ├── 00_init_theory_and_plan.md
│   │   ├── 01_lab1_strategy.md
│   │   ├── 02_lab2_strategy.md
│   │   ├── 03_lab3_strategy.md
│   │   ├── 04_lab4_strategy.md
│   │   ├── 05_lab5_strategy.md
│   │   ├── 06_lab6_strategy.md
│   │   └── 07_lab7_strategy.md
│   └── progress/                      # Mã nguồn, log thực nghiệm & hướng dẫn chạy từng bài
│       ├── LAB01/ -> lab1_GET_STARTED.md, lab1_IMPLEMENTATION.md, lab1_result.md, scripts/
│       ├── LAB02/ -> lab2_GET_STARTED.md, lab2_IMPLEMENTATION.md, lab2_result.md, scripts/
│       ├── LAB03/ -> lab3_GET_STARTED.md, lab3_IMPLEMENTATION.md, lab3_result.md, scripts/
│       ├── LAB04/ -> lab4_GET_STARTED.md, lab4_IMPLEMENTATION.md, lab4_result.md, scripts/
│       ├── LAB05/ -> lab5_GET_STARTED.md, lab5_IMPLEMENTATION.md, lab5_result.md, scripts/
│       ├── LAB06/ -> lab6_GET_STARTED.md, lab6_IMPLEMENTATION.md, lab6_result.md, scripts/
│       └── LAB07/ -> lab7_GET_STARTED.md, lab7_IMPLEMENTATION.md, lab7_result.md, scripts/
```

---

## 5. HƯỚNG DẪN THỰC HÀNH TỪNG BÀI LAB

Mỗi thư mục trong `docs/progress/LAB0X/` đều chứa 2 tài liệu hoàn chỉnh phục vụ tự học và thực hành:
- **`labX_GET_STARTED.md`**: Bản hướng dẫn nhanh, ngắn gọn với các lệnh copy-paste trực tiếp (`cat << 'EOF'`, `tcpdump`, `python3`), chú thích rõ từng vai trò (`[VICTIM]`, `[ATTACKER]`, `[HOST]`).
- **`labX_IMPLEMENTATION.md`**: Bản hướng dẫn chuyên sâu phân tích kỹ thuật, bám sát cấu trúc của `labX_GET_STARTED.md`, giải thích chi tiết ý nghĩa đặt tên script, mục đích, cú pháp và các cờ lệnh quan trọng, đồng thời móc nối chặt chẽ với lý thuyết (RFC standards).

Truy cập nhanh tài liệu từng bài:
- **Lab 01:** [Hướng Dẫn Thực Hành (Quick Start)](docs/progress/LAB01/lab1_GET_STARTED.md) | [Phân Tích Kỹ Thuật Chi Tiết](docs/progress/LAB01/lab1_IMPLEMENTATION.md)
- **Lab 02:** [Hướng Dẫn Thực Hành (Quick Start)](docs/progress/LAB02/lab2_GET_STARTED.md) | [Phân Tích Kỹ Thuật Chi Tiết](docs/progress/LAB02/lab2_IMPLEMENTATION.md)
- **Lab 03:** [Hướng Dẫn Thực Hành (Quick Start)](docs/progress/LAB03/lab3_GET_STARTED.md) | [Phân Tích Kỹ Thuật Chi Tiết](docs/progress/LAB03/lab3_IMPLEMENTATION.md)
- **Lab 04:** [Hướng Dẫn Thực Hành (Quick Start)](docs/progress/LAB04/lab4_GET_STARTED.md) | [Phân Tích Kỹ Thuật Chi Tiết](docs/progress/LAB04/lab4_IMPLEMENTATION.md)
- **Lab 05:** [Hướng Dẫn Thực Hành (Quick Start)](docs/progress/LAB05/lab5_GET_STARTED.md) | [Phân Tích Kỹ Thuật Chi Tiết](docs/progress/LAB05/lab5_IMPLEMENTATION.md)
- **Lab 06:** [Hướng Dẫn Thực Hành (Quick Start)](docs/progress/LAB06/lab6_GET_STARTED.md) | [Phân Tích Kỹ Thuật Chi Tiết](docs/progress/LAB06/lab6_IMPLEMENTATION.md)
- **Lab 07:** [Hướng Dẫn Thực Hành (Quick Start)](docs/progress/LAB07/lab7_GET_STARTED.md) | [Phân Tích Kỹ Thuật Chi Tiết](docs/progress/LAB07/lab7_IMPLEMENTATION.md)

