# Đóng góp cho AeroNet

AeroNet là dự án mã nguồn mở và chào đón developer cùng nghiên cứu, thử nghiệm
và xây dựng một lớp kết nối machine-first cho AI agent.

## Có thể đóng góp gì?

- Cải thiện giao thức identity, capability và signed envelope.
- Bổ sung mã hóa WSS/mTLS hoặc Noise transport.
- Xây dựng registry/DHT federated và multi-relay routing.
- Mở rộng persistent delivery với retry backoff, dead-letter queue và replication.
- Thiết kế web-of-attestation, reputation hoặc capability revocation.
- Viết model adapter, SDK, ví dụ tích hợp và tài liệu.
- Báo lỗi, đề xuất kiến trúc, bổ sung test hoặc cải thiện trải nghiệm CLI.

## Quy trình đề xuất

1. Tạo issue mô tả vấn đề hoặc ý tưởng trước khi thực hiện thay đổi kiến trúc lớn.
2. Fork repository và tạo một branch riêng cho thay đổi.
3. Giữ mỗi pull request tập trung vào một mục tiêu rõ ràng.
4. Thêm hoặc cập nhật test cho hành vi bị thay đổi.
5. Chạy các kiểm tra trước khi gửi pull request:

```bash
cargo fmt --all -- --check
cargo test
cargo clippy --all-targets -- -D warnings
```

6. Trong pull request, giải thích mục tiêu, lựa chọn thiết kế, giới hạn và cách
   kiểm chứng thay đổi.

## Nguyên tắc kỹ thuật

- Không làm suy yếu các bất biến về danh tính, chữ ký và capability.
- Không đưa secret, private key, capability thật hoặc dữ liệu cá nhân vào Git.
- Thay đổi wire format phải có schema version hoặc kế hoạch tương thích rõ ràng.
- Ưu tiên API nhỏ, có kiểu dữ liệu rõ ràng và lỗi có thể xử lý được.
- Các tính năng mạng phải có timeout, giới hạn tài nguyên và test cho đường lỗi.

## Giấy phép đóng góp

Bằng việc gửi đóng góp, bạn đồng ý cấp phép phần đóng góp đó theo
[MIT License](LICENSE) của dự án. Bạn xác nhận mình có quyền cung cấp phần mã và
tài liệu đã gửi theo giấy phép này.
