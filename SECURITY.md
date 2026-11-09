# Chính sách bảo mật

## Phiên bản được hỗ trợ

Chỉ nhánh `main` mới nhất được nhận bản vá bảo mật.

## Báo cáo lỗ hổng

**Vui lòng không mở issue công khai cho lỗ hổng bảo mật.**

Gửi báo cáo kín qua GitHub: vào tab **Security** của repo → **Report a vulnerability**
([Private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).

Báo cáo nên gồm:

- Thành phần bị ảnh hưởng (CLI, giao diện web, giải nén ZIP, xác thực, quy tắc…)
- Các bước tái hiện và mã/tệp mẫu tối thiểu, đã loại bỏ thông tin riêng
- Tác động dự kiến và phiên bản Node.js, Semgrep, hệ điều hành

Bạn sẽ nhận phản hồi xác nhận trong vòng 7 ngày. Sau khi bản vá được phát hành,
lỗ hổng sẽ được công bố kèm ghi nhận người báo cáo (nếu bạn đồng ý).

## Phạm vi

Trong phạm vi: lỗ hổng của chính SrcAudit, ví dụ vượt qua xác thực, truy cập báo cáo
của tài khoản khác, path traversal khi giải nén, thực thi mã khi quét, lộ dữ liệu
trong báo cáo.

Ngoài phạm vi: cảnh báo nhầm hoặc bỏ sót của quy tắc quét (hãy mở issue thường),
các tệp mẫu cố ý chứa lỗi trong `examples/`, `test/` và `scripts/`.

## Sử dụng hợp pháp

Chỉ dùng SrcAudit trên mã nguồn bạn sở hữu hoặc được phép kiểm tra.
