# Cấp Key Kích Hoạt (capkeydo)

Hệ thống web tạo key kích hoạt bản quyền offline bằng chữ ký số RSA-256 (tương thích trực tiếp với module xác thực của ứng dụng).

## Cấu trúc dự án
- `api/sign.js`: Serverless Function ký số SHA256withRSA.
- `public/index.html`: Giao diện Admin tạo và sao chép key.

## Hướng dẫn triển khai lên Vercel
1. Import repository này vào [Vercel](https://vercel.com).
2. Thiết lập 2 biến môi trường (**Environment Variables**) trong Project Settings của Vercel:
   - `ADMIN_PASSWORD`: Mật khẩu bảo vệ trang cấp key.
   - `PRIVATE_KEY`: Khóa RSA Private Key (định dạng PEM gồm đầy đủ dòng `-----BEGIN RSA PRIVATE KEY-----` và `-----END RSA PRIVATE KEY-----`).
3. Deploy và truy cập domain do Vercel cấp.
