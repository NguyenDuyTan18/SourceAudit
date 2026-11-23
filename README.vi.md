# SrcAudit

[English](README.md)

SrcAudit là công cụ phân tích tĩnh bảo mật ứng dụng (SAST) chạy cục bộ. Công cụ quét mã nguồn và tệp khóa thư viện phụ thuộc, sau đó báo cáo vị trí phát hiện, bằng chứng đã che dữ liệu nhạy cảm và hướng khắc phục.

[Khởi động với Docker](#chạy-bằng-docker-compose) · [Cài bằng Node.js](#chạy-trực-tiếp-bằng-nodejs) · [Phạm vi quét](#chế-độ-quét) · [CLI và CI](#cli-và-ci) · [Đóng góp](#kiểm-thử-và-đóng-góp)

## Chạy bằng Docker Compose

Cài Docker và Compose v2. Docker Desktop cung cấp cả hai trên Windows, macOS và Linux. Image của SrcAudit có sẵn Node.js và Semgrep CE.

```sh
git clone https://github.com/NguyenDuyTan18/SourceAudit.git
cd SourceAudit
docker compose up --build -d
```

Mở [http://127.0.0.1:8787](http://127.0.0.1:8787). Trên giao diện tiếng Anh, chọn **Upload ZIP** hoặc **Upload folder**, chọn **Quick scan** hoặc **Deep scan with Semgrep**, rồi bấm **Start scan**. Bạn có thể thử với thư mục `examples/demo-src`. Trình duyệt gửi mã đã chọn đến container trên máy. Lần dựng image đầu tiên cần tải các gói phụ thuộc. Lượt quét dùng bộ quy tắc và dữ liệu cảnh báo đã đóng gói.

Dịch vụ chỉ mở trên địa chỉ loopback của máy và chạy không cần tài khoản. Volume `srcaudit-data` giữ báo cáo, lịch sử quét và chỉ mục ghi chú đã nhập sau khi dừng hoặc tạo lại container.

| Việc cần làm | Lệnh |
| --- | --- |
| Xem trạng thái | `docker compose ps` |
| Xem nhật ký | `docker compose logs srcaudit` |
| Dừng và giữ dữ liệu | `docker compose down` |
| Dựng lại sau khi cập nhật mã | `docker compose up --build -d` |

Nếu cổng 8787 đang được sử dụng, thêm `SRCAUDIT_PORT=8797` vào tệp `.env` cục bộ và mở [http://127.0.0.1:8797](http://127.0.0.1:8797) sau khi khởi động Compose. Lệnh `docker compose down --volumes` xóa vĩnh viễn volume dữ liệu, bao gồm báo cáo và ghi chú đã lưu.

### Dùng CLI trong Docker

Ví dụ sau quét mã mẫu bằng cùng image với ứng dụng web.

```sh
docker compose run --rm srcaudit node scan.mjs --src /app/examples/demo-src --deep --out /var/lib/srcaudit/demo-report
docker compose cp srcaudit:/var/lib/srcaudit/demo-report ./demo-report
```

Lệnh sao chép dùng container web đang chạy để đọc volume chung. Sau đó mở `demo-report/report.html`. Để quét một thư mục trên máy bằng CLI, gắn thư mục đó ở chế độ chỉ đọc. Chạy lệnh sau từ thư mục dự án trong PowerShell hoặc shell tương thích POSIX.

```sh
docker compose run --rm --volume "${PWD}/examples/demo-src:/input:ro" srcaudit node scan.mjs --src /input --deep
```

Thay `${PWD}/examples/demo-src` bằng đường dẫn tuyệt đối đến thư mục cần quét. Khi bỏ qua `--out`, CLI trong Docker lưu báo cáo tại `/var/lib/srcaudit/.scanner-reports/`.

## Chạy trực tiếp bằng Node.js

Cài Node.js từ phiên bản 22 trở lên. Trong thư mục dự án, chạy các lệnh sau.

```sh
npm ci --ignore-scripts
npm start
```

Mở địa chỉ cục bộ hiển thị trong terminal. Trên Windows, `Start-UI.cmd` có thể mở trình duyệt sau khi cài các gói phụ thuộc. Dùng `npm.cmd` nếu PowerShell chặn `npm.ps1`.

### Cài Semgrep CE để quét sâu khi chạy trực tiếp

Trên Windows, chạy:

```powershell
py -m venv .scanner-tools/semgrep
.\.scanner-tools\semgrep\Scripts\python.exe -m pip install semgrep==1.184.0
```

Trên Linux hoặc macOS, chạy:

```sh
python3 -m venv .scanner-tools/semgrep
./.scanner-tools/semgrep/bin/python -m pip install semgrep==1.184.0
```

SrcAudit tìm Semgrep theo thứ tự: biến `SECURITYSCANNER_SEMGREP_EXE`, đường dẫn môi trường ảo của dự án, rồi lệnh `semgrep` trên `PATH`. [Hướng dẫn cài Semgrep CE](https://semgrep.dev/docs/getting-started/quickstart-ce)

### Bật truy cập từ xa khi chạy trực tiếp

Ứng dụng mặc định chạy cục bộ. Chủ sở hữu đã có tài khoản có thể tiếp tục dùng lịch sử quét trên máy. Để bật truy cập từ xa khi chạy trực tiếp, đặt `SRCAUDIT_ENABLE_REMOTE=1`, tạo tệp `.ui-public.json` với nội dung `{"origin":"https://your-domain.example"}`, rồi khởi động lại ứng dụng. Tạo tài khoản chủ sở hữu qua địa chỉ cục bộ trước khi kết nối proxy HTTPS. Chủ sở hữu quản lý thành viên trong mục **Accounts**. Báo cáo, lượt quét trong hàng đợi và chỉ mục ghi chú được lưu theo tài khoản. Ứng dụng vẫn hỗ trợ cấu hình truy cập từ xa kiểu cũ có thông tin đăng nhập. Cấu hình Docker Compose dành cho sử dụng cục bộ.

## Chế độ quét

| Chế độ | Phạm vi |
| --- | --- |
| **Quick Scan** | Mẫu mã nguồn, luồng dữ liệu cục bộ, thông tin xác thực, cấu hình GitHub Actions và Docker Compose, cùng cảnh báo thư viện phụ thuộc. |
| **Deep scan with Semgrep** | Quy tắc Semgrep CE cho JS/TS, Python, PHP, Java, Go, C#, Ruby, GitHub Actions và Dockerfile, cùng cảnh báo về thư viện phụ thuộc. |

### Quick Scan kiểm tra những gì

- **Mã nguồn và luồng dữ liệu** gồm SQL injection, HTML không an toàn, thực thi lệnh, yêu cầu HTTP đi ra và đường dẫn tệp. Một số cảnh báo JS/TS được kiểm tra lại bằng cây cú pháp, bao gồm truy vấn PostgreSQL dùng câu SQL cố định và truyền giá trị qua tham số riêng.
- **Thông tin xác thực và cấu hình** gồm bí mật có thể bị ghi cứng, thiết lập TLS, quyền token quá rộng trong GitHub Actions và dịch vụ Docker Compose tắt cơ chế bảo vệ seccomp hoặc AppArmor. Tham chiếu bí mật rõ ràng được lọc, giá trị mẫu rõ ràng được đánh dấu thông tin và giá trị dự phòng ghi cứng vẫn được rà soát.
- **Thư viện phụ thuộc** gồm phiên bản cụ thể từ npm, Yarn, pnpm, tệp requirements có ghim phiên bản, Pipenv, Poetry và Composer. Cả hai chế độ đối chiếu các phiên bản này với dữ liệu cảnh báo đóng gói.

Chạy `node scan.mjs --list-rules` để xem mã quy tắc Quick Scan, mã CWE và mức độ mặc định. Hãy rà lại phát hiện trong ngữ cảnh sử dụng và triển khai thực tế. [Danh mục quy tắc và tệp khóa được hỗ trợ](docs/RULES.md#quick-scan) · [Dữ liệu và giấy phép](data/README.md) · [Nguồn tham khảo](SOURCES.md)

## CLI và CI

```sh
node scan.mjs --src ./examples/demo-src --out ./reports/demo
node scan.mjs --src ./app --deep --fail-on high
node scan.mjs --src . --diff origin/main --fail-on high
node scan.mjs --src . --baseline ./reports/demo/report.json --fail-on high
node scan.mjs --list-rules
node scan.mjs --knowledge CWE-89
node scan.mjs --help
```

| Tùy chọn | Công dụng |
| --- | --- |
| `--src PATH` | Quét một tệp hoặc thư mục trên máy. |
| `--out DIR` | Chọn thư mục báo cáo. Mặc định là thư mục theo thời điểm quét trong `.scanner-reports/`. |
| `--deep` | Chạy bộ quy tắc Semgrep có sẵn. |
| `--diff REF` | Quét các tệp thay đổi kể từ tổ tiên chung của REF và HEAD, kể cả tệp chưa được Git theo dõi. Cần Git và đủ lịch sử commit. |
| `--baseline FILE` | So sánh mã định danh của phát hiện với một tệp `report.json` trước đó. |
| `--no-gitignore`, `--include-tests` | Lần lượt thêm các tệp bị bỏ qua hoặc mã kiểm thử vào phạm vi quét. |
| `--max-bytes N`, `--max-files N` | Đặt giới hạn dung lượng mỗi tệp và số lượng tệp trong phạm vi được hỗ trợ. |
| `--rules FILE` | Nạp tối đa 100 quy tắc khớp chuỗi cố định cho chế độ quét nhanh. |
| `--import-writeup FILE` | Nhập ghi chú dạng văn bản hoặc Markdown tối đa 1 MiB. Dùng `--knowledge-dir DIR` để chọn nơi lưu hoặc đọc chỉ mục. |

Mã thoát `0` nghĩa là lượt quét đã hoàn tất. Mã `1` nghĩa là có phát hiện đạt ngưỡng `--fail-on`. Mã `2` báo đầu vào không hợp lệ hoặc lượt quét chưa hoàn tất. Dùng `report.sarif` với trình xem SARIF hoặc quy trình quét mã trong CI. [Ví dụ GitHub Actions](docs/ci/github-code-scanning.yml)

Khi chủ động bỏ qua một cảnh báo, ghi lý do sau `--` ngay trên dòng liên quan hoặc ở dòng liền trước. Phát hiện đã bỏ qua vẫn được lưu trong báo cáo để đối chiếu.

```js
db.query(sql); // srcaudit-ignore SRC-SQL -- SQL is a fixed internal query
```

Khi so sánh với báo cáo mốc, SrcAudit chỉ ghi nhận một phát hiện cũ đã được xử lý nếu tệp tương ứng đã được kiểm tra bằng cùng chế độ quét. Phát hiện trong tệp bị bỏ qua hoặc chưa quét được xếp vào nhóm chưa đánh giá. Hãy kiểm tra phạm vi trước khi diễn giải một báo cáo trống.

## Báo cáo, dữ liệu và giới hạn

Mỗi lượt quét tạo báo cáo HTML, JSON, văn bản và SARIF. Mỗi phát hiện ghi quy tắc, mã CWE, vị trí, bằng chứng, tác động và hướng khắc phục. Khi một thư viện khớp cảnh báo bảo mật, hãy kiểm tra cách triển khai và khả năng luồng thực thi đi qua mã bị ảnh hưởng. Xem lại các đoạn mã và đường dẫn trước khi chia sẻ báo cáo.

| Thiết lập | Mặc định |
| --- | --- |
| Số lượng và dung lượng tệp mã nguồn | 2.000 tệp, tối đa 10 MiB mỗi tệp |
| Tổng dung lượng mã nguồn | 50 MiB khi tải lên từ web hoặc quét sâu |
| Tệp ZIP | Tối đa 50 MiB sau khi nén và 10.000 mục |
| Thời gian tối đa để Semgrep quét | 90 giây |
| `SRCAUDIT_REPORT_RETENTION_DAYS` | 7 ngày. Đặt `0` để tắt tự động dọn báo cáo. |
| `SRCAUDIT_ACCOUNT_STORAGE_MIB` | 128 MiB cho mỗi không gian làm việc trên web, tính cả báo cáo và tệp tải lên đang chờ. |

Đặt tùy chọn Docker trong tệp `.env` cục bộ trước khi khởi động Compose. Khi chạy trực tiếp, đặt các biến môi trường tương ứng trước khi mở ứng dụng. Báo cáo mặc định được lưu trong `.scanner-reports/` và lịch sử trên web được lưu theo không gian làm việc. Tính năng dọn tự động áp dụng cho thư mục báo cáo do ứng dụng quản lý và báo cáo CLI có tên theo thời điểm quét trong thư mục đầu ra mặc định.

Mặc định SrcAudit bỏ qua liên kết tượng trưng, tệp nhị phân, thư mục phụ thuộc hoặc thư mục build phổ biến, và mã kiểm thử. CLI áp dụng cả các tệp `.gitignore` ở thư mục con. Bộ giải nén ZIP hỗ trợ `store` và `deflate`, đồng thời từ chối đường dẫn không an toàn. Chế độ quét sâu chủ yếu theo dõi luồng dữ liệu trong phạm vi từng hàm. Báo cáo ghi lại tệp vượt giới hạn và phần mã bị bỏ qua.

## Kiểm thử và đóng góp

```sh
npm test
npm run test:coverage
npm run benchmark:semgrep
npm run benchmark:check
```

[Kết quả benchmark](docs/testing/accuracy.md) ghi precision, recall và tỷ lệ báo nhầm theo bộ dữ liệu có nhãn và chế độ quét. Quy tắc mới nên có nguồn tham khảo, một ví dụ cần cảnh báo, một ví dụ đã sửa, mã CWE và vị trí dự kiến. Khi báo lỗi, ghi rõ chế độ quét, phiên bản công cụ và ví dụ tối thiểu đã loại thông tin nhạy cảm.

Phát hành theo giấy phép MIT. [Chính sách bảo mật](SECURITY.md) · [Thông báo về dữ liệu](data/NOTICE.md)
