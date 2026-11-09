# Kiểm chứng tài khoản chủ

Luồng kiểm thử xuất phát từ yêu cầu đăng ký và đăng nhập. Bản cài có một tài khoản chủ, được tạo trực tiếp tại địa chỉ loopback trên máy chạy ứng dụng. Cấu hình HTTPS public có thể dùng tài khoản này để đăng nhập. Thông tin đăng nhập public cũ được hỗ trợ để tương thích.

| Luồng | Bằng chứng |
|---|---|
| Đăng ký và lưu tài khoản | `node --test test/accounts.test.mjs` ban đầu thất bại vì trang local thiếu biểu mẫu và cấu hình public yêu cầu mật khẩu cũ. Sau triển khai, các ca kiểm thử đạt. Hai yêu cầu đăng ký đồng thời tạo đúng một tài khoản. |
| Đăng nhập lại và đăng xuất | Kiểm thử xác nhận file chỉ lưu salt và băm, tài khoản dùng được sau khởi động lại, cookie cũ bị từ chối sau đăng xuất và mật khẩu sai trả HTTP 401. |
| Đăng nhập qua proxy | Mô phỏng origin public và header chuyển tiếp. Đăng ký bị từ chối qua proxy, tài khoản chủ đăng nhập được và cookie HTTPS có Secure. |
| Giới hạn đăng nhập | Kiểm thử xác nhận yêu cầu vượt ngân sách bị giới hạn và các ngân sách local/public tách riêng. |
| Giao diện | Preview loopback riêng trong trình duyệt Codex chạy qua đăng ký, đăng xuất, mật khẩu sai và đăng nhập lại bằng dữ liệu thử. Preview và tài khoản thử đã được dọn. |

`npm run test:coverage` đạt 97/97 và độ phủ dòng 97,04%. Mô-đun tài khoản đạt 95,71% dòng. `node --check ui.mjs` và `node --check web/app.js` đạt. Kiểm tra public dùng HTTP mô phỏng proxy. Không có baseline hình ảnh hay lượt kiểm tra khả năng tiếp cận đầy đủ.

Tự đánh giá 4,4/5. Độ chính xác và độ đầy đủ đạt 4/5 vì đã kiểm chứng luồng trên trình duyệt local và mô phỏng public, còn kết nối ngrok thực tế nằm ngoài lượt kiểm thử. Độ rõ ràng đạt 4/5 với hướng dẫn tạo tài khoản và tương thích cấu hình cũ. Khả năng sử dụng và độ súc tích đạt 5/5 vì luồng đăng ký nằm ngay trong ứng dụng và dùng cùng phiên đăng nhập.
