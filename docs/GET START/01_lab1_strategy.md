# WORKFLOW EXECUTION: LAB 01 - TCP ISN PREDICTION & BLIND SPOOFING

Bạn hãy đóng vai trò là một **Network Penetration Tester, Scapy Specialist và Linux Systems Engineer**.

## 1. MỤC TIÊU NHIỆM VỤ
Thực thi trọn vẹn Bài thực hành 01 trên máy ảo Kali Linux thông qua tool MCP `kali-vm:ssh_execute`, thu thập đầy đủ minh chứng thực nghiệm và giải thích cơ chế kỹ thuật.

## 2. CÁC BƯỚC THỰC THI (STEP-BY-STEP)

### BƯỚC 1: Chuẩn bị Script cục bộ
Tạo thư mục `docs/progress/LAB01/scripts/` trên workspace host và sinh 3 file:
1. `setup_pair.sh`: Dựng namespace `h1` (.1), `h2` (.2), link `veth1-veth2`, chặn RST output trên h1. Có cơ chế tự động xóa namespace cũ nếu đã tồn tại.
2. `isn_sampler.py`: Thu thập 30 ISN từ h2 qua port 9000, tính độ chênh lệch delta giữa các ISN liên tiếp.
3. `spoof_sniff.py`: Giả mạo IP nguồn 10.0.0.77, sniff SYN/ACK trên veth1, trích xuất ISN và hoàn tất bắt tay 3 bước gửi payload data.

### BƯỚC 2: Triển khai và Kiểm tra Topology trên Kali VM
Sử dụng `ssh_execute` để:
1. Tạo thư mục làm việc `/tmp/lab01` trên Kali Linux.
2. Đẩy và phân quyền thực thi cho `setup_pair.sh`.
3. Chạy setup và ghi nhận kết quả ping kiểm tra giữa `h1` và `h2`.

### BƯỚC 3: Mở dịch vụ và Thu thập ISN
1. Chạy dịch vụ nền trên `h2`: `ip netns exec h2 ncat -lk 10.0.0.2 9000 &`
2. Chạy `isn_sampler.py` từ namespace `h1`. 
3. Thu nhận toàn bộ 30 giá trị ISN và độ chênh lệch delta. Đánh giá xem delta có tuân theo quy luật ngẫu nhiên RFC 6528 không.

### BƯỚC 4: Tấn công Giả mạo nguồn (Blind Spoofing Simulation)
1. Mở tcpdump lắng nghe trên `h2` và ghi ra file log tạm thời:
   `ip netns exec h2 timeout 6 tcpdump -i veth2 -nn -A tcp port 9000 > /tmp/lab01/tcpdump_h2.log 2>&1 &`
2. Thực thi `spoof_sniff.py` từ namespace `h1`.
3. Đọc nội dung `/tmp/lab01/tcpdump_h2.log` để xác nhận gói tin mang IP giả `10.0.0.77` và payload `hello-from-spoofed-source` đã được victim tiếp nhận.

### BƯỚC 5: Tổng hợp Tài liệu Báo cáo & Dọn dẹp
1. Tạo file `docs/progress/LAB01/lab1_result.md`: Chứa nguyên văn log output từ terminal (kết quả ping, danh sách 30 ISN kèm delta, log tcpdump bắt được IP giả mạo).
2. Tạo file `docs/progress/LAB01/IMPLEMENTATION.md`: Giải thích mục đích từng câu lệnh, ý nghĩa tham số Scapy, cơ chế tại sao phải drop RST và kết luận phòng thủ.
3. Dọn dẹp môi trường: Xóa tiến trình `ncat` và xóa 2 namespace `h1`, `h2`.
4. Đánh dấu tick `[x]` cho Lab 01 trong file `PLAN.md`.

## 3. STRICT RULES
- Mọi lệnh thực thi trên Kali BẮT BUỘC gọi qua `kali-vm:ssh_execute`.
- TUYỆT ĐỐI KHÔNG để các lệnh lắng nghe (`tcpdump`, `ncat`) chạy vô hạn; phải có cờ `timeout` hoặc quản lý kill PID.
- Không bịa đặt kết quả; toàn bộ dữ liệu ISN và log tcpdump trong `lab1_result.md` phải lấy từ output thực tế của máy ảo.