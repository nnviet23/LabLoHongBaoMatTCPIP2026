# Antigravity Execution Rules for TCP/IP Security Labs

## 1. Remote Execution Constraint
- MỌI lệnh kiểm tra mạng, cấu hình namespace, cài đặt gói và chạy script Scapy BẮT BUỘC phải thực thi qua tool `kali-vm:ssh_execute`.
- Thông số SSH mặc định: Host: `192.168.208.132`, Username: `tainbow`, Port: 22.
- TUYỆT ĐỐI KHÔNG tự ý thực thi các lệnh Linux (`ip`, `iptables`, `sysctl`, `tcpdump`) trên Windows PowerShell của máy host.

## 2. Execution & Logging Protocol
- Trước khi thực thi bất kỳ lab nào, phải kiểm tra và xóa sạch namespace/bridge còn sót từ lab trước để tránh lỗi tài nguyên.
- Với mỗi lệnh chạy có output (kết quả ping, tcpdump, chênh lệch ISN, dig cờ AD...), phải trích xuất nguyên văn stdout/stderr để ghi vào file `labX_result.md`.

## 3. Directory & Artifact Convention
- Lý thuyết tổng hợp từ PDF: lưu vào `docs/theory/0X_LABX_<TênLab>.md`.
- Kế hoạch và hướng dẫn triển khai: lưu vào `docs/progress/LAB0X/IMPLEMENTATION.md`.
- Mã nguồn và script: lưu vào `docs/progress/LAB0X/scripts/`.
- Nhật ký kết quả thực nghiệm: lưu vào `docs/progress/LAB0X/labX_result.md`.