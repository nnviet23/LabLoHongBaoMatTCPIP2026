# GIAI ĐOẠN 0: ĐỌC TÀI LIỆU LAB, XÂY DỰNG PLAN.MD VÀ TRÍCH XUẤT LÝ THUYẾT

Bạn hãy đóng vai trò là một **Senior Network Security Engineer và Protocol Researcher**.

## 1. MỤC TIÊU & PHẠM VI
1. Đọc và phân tích toàn bộ 7 tệp PDF đề bài trong thư mục `docs/Lab/`.
2. Tạo tệp `PLAN.md` ở thư mục gốc của dự án để quản lý tiến độ thực thi từng bài.
3. Trích xuất kiến thức lý thuyết, nguyên lý tấn công, cơ chế phòng thủ và lời giải gợi ý cho toàn bộ các "Câu hỏi ôn tập" của từng lab vào thư mục `docs/theory/`.

## 2. NHIỆM VỤ CỤ THỂ

### NHIỆM VỤ 1: Khởi tạo `PLAN.md`
Tạo file `PLAN.md` tại thư mục gốc với cấu trúc checklist chi tiết:
- Thông tin tổng quan môi trường (Kali VM, NAT, SSH MCP).
- Ma trận 7 bài Lab: Mục tiêu, Kỹ thuật (Spoofing, DoS, Tunneling, MITM, DNSSEC), Công cụ sử dụng và Trạng thái hoàn thành (`[ ] Not Started`, `[ ] In Progress`, `[x] Verified`).

### NHIỆM VỤ 2: Tạo 7 file tài liệu lý thuyết trong `docs/theory/`
Tạo lần lượt 7 file từ `01_LAB1_TCP_ISN_Prediction.md` đến `07_LAB7_DNSSEC.md`. Mỗi file bắt buộc có 4 phần:
1. **Mục tiêu & Chuẩn RFC liên quan:** (RFC 793, RFC 6528, RFC 791, RFC 792, RFC 2644, RFC 4033-4035...).
2. **Nguyên lý Tấn công & Điểm yếu Giao thức:** Phân tích chi tiết tại sao giao thức lại tồn tại điểm yếu đó (về tính ngẫu nhiên, định tuyến nguồn, khuếch đại, phân mảnh hoặc thiếu tính xác thực).
3. **Cơ chế Phòng thủ (Mitigation):** Giải thích chi tiết các tham số kernel `sysctl`, cấu hình firewall `iptables` và các tiêu chuẩn bảo mật mạng hiện đại (BCP 38, DNSSEC validation).
4. **Giải đáp Câu hỏi ôn tập:** Trả lời chi tiết, có lập luận khoa học cho từng câu hỏi ở cuối tệp PDF tương ứng.

## 3. STRICT RULES
- CHỈ ĐƯỢC đọc file PDF trong `docs/Lab/` và tạo các file `.md` trong `docs/theory/` cùng `PLAN.md`.
- KHÔNG gọi tool SSH để thực thi lệnh trên Kali trong giai đoạn này.
- Phân biệt rõ ràng kiến thức trích từ tài liệu gốc với phân tích kỹ thuật của bạn.