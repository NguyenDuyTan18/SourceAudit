# SourceAudit

> Công cụ phân tích tĩnh mã nguồn (SAST) chạy cục bộ, xuất báo cáo có vị trí, bằng chứng và hướng khắc phục.

![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933?logo=node.js&logoColor=white)
![Semgrep CE](https://img.shields.io/badge/Semgrep%20CE-1.184.0-1B2F3A)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

## Mục lục

- [Giới thiệu](#giới-thiệu)
- [Tính năng](#tính-năng)
- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Cài đặt](#cài-đặt)
- [Sử dụng](#sử-dụng)
- [Cấu hình](#cấu-hình)
- [Đọc báo cáo](#đọc-báo-cáo)
- [Nguồn dữ liệu](#nguồn-dữ-liệu)
- [Giới hạn](#giới-hạn)
- [Cấu trúc dự án](#cấu-trúc-dự-án)
- [Phát triển](#phát-triển)
- [Lộ trình](#lộ-trình)
- [Đóng góp](#đóng-góp)
- [Giấy phép và nguồn tham khảo](#giấy-phép-và-nguồn-tham-khảo)

## Giới thiệu

SourceAudit quét mã nguồn để tìm điểm yếu bảo mật theo CWE, đối chiếu dependency với advisory đã biết và bổ sung ngữ cảnh từ OWASP, MITRE CWE, GitHub Advisory Database và CISA KEV. Toàn bộ quá trình chạy offline trên máy của bạn.

Có hai cách dùng:

- **Giao diện web**: tải lên một tệp ZIP hoặc chọn một thư mục từ máy.
- **CLI**: quét trực tiếp một file hoặc thư mục, phù hợp để tích hợp CI.

## Tính năng

| Tính năng | Mô tả |
|---|---|
| **Quét nhanh** | 82 quy tắc tích hợp (76 chữ ký + 6 quy tắc theo dõi biến) cho mã nguồn, cấu hình và credential |
| **Phân tích sâu** | 47 quy tắc Semgrep CE có phân tích luồng dữ liệu (taint) cho JS/TS, Python, PHP, Java, Go, C#, Ruby, GitHub Actions và Dockerfile |
| **CVE dependency** | Đối chiếu offline phiên bản npm và Python với 1.777 advisory, đánh dấu CVE từng bị khai thác (CISA KEV) |
| **Thư viện nhận dạng** | 5.004 bản ghi CWE, OWASP WSTG, ASVS, API Security để tra cứu và gắn vào báo cáo |
| **Báo cáo** | Xuất JSON, HTML và TXT, có `file:dòng:cột`, đoạn trích đã che dữ liệu nhạy cảm và hướng sửa |
| **Tự xóa báo cáo cũ** | Báo cáo quá hạn lưu giữ (mặc định 7 ngày) bị xóa khỏi đĩa và lịch sử |
| **Đa tài khoản** | Tài khoản chủ tạo thành viên; mỗi tài khoản chỉ thấy lượt kiểm tra của mình. Mật khẩu băm scrypt, phiên 8 giờ, cookie Secure/HttpOnly/SameSite=Strict, hỗ trợ truy cập qua ngrok |

Danh sách đầy đủ quy tắc: [docs/RULES.md](docs/RULES.md).

## Yêu cầu hệ thống

- **Node.js** 22 trở lên
- **Semgrep CE** (tùy chọn, chỉ cần cho phân tích sâu), đã kiểm thử với 1.184.0
- **Python** 3 (tùy chọn, để cài Semgrep vào venv cục bộ)

## Cài đặt

```powershell
npm ci --ignore-scripts
```

Để bật phân tích sâu, cài Semgrep CE vào thư mục cục bộ của dự án:

```powershell
py -m venv .scanner-tools/semgrep
.\.scanner-tools\semgrep\Scripts\python.exe -m pip install semgrep==1.184.0
```

SourceAudit tìm Semgrep theo thứ tự: biến môi trường `SECURITYSCANNER_SEMGREP_EXE` → `.scanner-tools/semgrep` → `semgrep` trên `PATH`. Xem thêm [tài liệu cài Semgrep CE](https://semgrep.dev/docs/getting-started/quickstart-ce).

## Sử dụng

### Giao diện web

```powershell
npm start
```

Trên Windows có thể nhấp đúp `Start-UI.cmd`.

1. Mở địa chỉ local in trên terminal (ưu tiên cổng `8787`, tự chọn cổng trống nếu bị chiếm).
2. Lần đầu, chọn **Đăng ký tài khoản** để tạo tài khoản chủ.
3. Chọn **Tải ZIP** hoặc **Tải thư mục**.
4. Chọn **Chế độ kiểm tra**: *Quét nhanh* hoặc *Phân tích sâu bằng Semgrep*.
5. Bấm **Bắt đầu kiểm tra** và xem **Kết quả kiểm tra**.

Để thử nhanh, chọn thư mục `examples/demo-src`, hoặc tạo ZIP mẫu:

```powershell
Compress-Archive -Path .\examples\demo-src\* -DestinationPath .\sourceaudit-demo.zip -Force
```

> Nếu giao diện báo **Cần khởi động lại**, chạy lại `Start-UI.cmd`. Launcher xác minh tiến trình SourceAudit đang giữ cổng trước khi thay thế.

### CLI

```powershell
node scan.mjs --src .\examples\research-demo --out .\.scanner-reports\sample
node scan.mjs --src "D:\projects\app" --deep
node scan.mjs --src "D:\projects\app" --fail-on high
node scan.mjs --list-rules
node scan.mjs --knowledge CWE-89
```

| Tùy chọn | Mô tả |
|---|---|
| `--src <path>` | File hoặc thư mục cần quét |
| `--out <dir>` | Thư mục báo cáo (mặc định: thư mục mới trong `.scanner-reports/`) |
| `--deep` | Bật phân tích sâu bằng Semgrep |
| `--fail-on <severity>` | Trả mã thoát `1` khi có phát hiện đạt ngưỡng |
| `--rules <file.json>` | Nạp thêm tối đa 100 quy tắc JSON tùy chỉnh |
| `--knowledge-dir <dir>` | Thư mục write-up đã nhập để gắn ngữ cảnh |
| `--import-writeup <file>` | Nhập write-up TXT/Markdown (≤ 1 MiB) |
| `--list-rules` | Liệt kê quy tắc tích hợp |
| `--knowledge <id>` | Tra cứu CWE, CVE, WSTG… |

**Mã thoát**

| Mã | Ý nghĩa |
|---|---|
| `0` | Quét xong |
| `1` | Quét xong và có phát hiện đạt ngưỡng `--fail-on` |
| `2` | Đầu vào không hợp lệ, lỗi đọc/ghi, hoặc còn phần chưa quét được |

## Cấu hình

### Tài khoản

Mỗi bản cài có **một tài khoản chủ** (quản trị), tạo qua địa chỉ local. Tài khoản chủ mở mục **Tài khoản** trong giao diện để tạo hoặc xóa **thành viên**.

| Vai trò | Lưu tại | Quyền |
|---|---|---|
| Tài khoản chủ | `.scanner-auth/owner.json` | Quét, xem lượt kiểm tra của mình, tạo/xóa thành viên |
| Thành viên | `.scanner-auth/users.json` | Quét, xem lượt kiểm tra của mình |

- Tên đăng nhập: 3–64 ký tự gồm chữ Latin, chữ số, `.`, `-`, `_`.
- Mật khẩu: tối thiểu 15 ký tự, tối đa 256 byte. Chỉ lưu salt và bản băm scrypt ([OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)).
- Phiên có hiệu lực 8 giờ, kết thúc khi **Đăng xuất** hoặc khởi động lại ứng dụng.

#### Lịch sử kiểm tra riêng theo tài khoản

- **Danh tính lấy từ phiên.** Máy chủ xác định tài khoản từ phiên đăng nhập, không nhận mã người dùng từ trình duyệt.
- **Lưu riêng.** Báo cáo nằm tại `.scanner-reports/user-<id>/<jobId>/` kèm `meta.json` ghi chủ sở hữu. Lịch sử được nạp lại từ đĩa sau khi khởi động lại; mỗi tài khoản giữ tối đa 20 lượt gần nhất.
- **Không lộ báo cáo của người khác.** Lịch sử chỉ liệt kê lượt kiểm tra của tài khoản đang đăng nhập. Mở hoặc tải báo cáo của tài khoản khác trả về **404** giống hệt báo cáo không tồn tại, nên không dò được ID (chống IDOR — [CWE-639](https://cwe.mitre.org/data/definitions/639.html)).
- **Hàng đợi.** Các lượt quét chạy lần lượt (hàng đợi tối đa 10). Mỗi tài khoản chỉ có một lượt đang chờ hoặc đang chạy.
- **Xóa thành viên** sẽ đăng xuất mọi phiên của thành viên đó và xóa toàn bộ báo cáo của họ.

Kiểm thử: [test/account-isolation.test.mjs](test/account-isolation.test.mjs).

### Truy cập từ xa qua ngrok

1. Tạo tài khoản chủ qua địa chỉ local trước.
2. Tạo `.ui-public.json` ở thư mục gốc:

   ```json
   { "origin": "https://your-domain.ngrok-free.dev" }
   ```

3. Khởi động lại ứng dụng, rồi trỏ ngrok tới cổng ghi trong `.ui-session.json`:

   ```powershell
   ngrok http http://127.0.0.1:8787 --inspect=false
   ```

Khi tên miền ngrok thay đổi, cập nhật `origin` và khởi động lại. File cấu hình cũ có `username` và `password` vẫn được hỗ trợ qua biểu mẫu và HTTP Basic Authentication.

### Thời hạn lưu báo cáo

Báo cáo không được giữ vô thời hạn. Thư mục báo cáo trong `.scanner-reports/` cũ hơn thời hạn lưu giữ sẽ bị xóa:

- **Giao diện web**: quét khi khởi động và mỗi giờ; lượt kiểm tra hết hạn cũng biến mất khỏi lịch sử và không tải lại được.
- **CLI**: quét trước khi ghi báo cáo mới, chỉ khi dùng thư mục mặc định (không truyền `--out`).

| Biến môi trường | Mặc định | Ý nghĩa |
|---|---|---|
| `SENTRY_REPORT_RETENTION_DAYS` | `7` | Số ngày giữ báo cáo (0–365, chấp nhận số thập phân). `0` tắt tự xóa. |

```powershell
$env:SENTRY_REPORT_RETENTION_DAYS = "3"; npm start
```

Chỉ thư mục do SourceAudit tạo (tên UUID của giao diện hoặc timestamp của CLI) mới bị xóa. Thư mục tự đặt tên qua `--out`, file lẻ và symlink được giữ nguyên. Tuổi tính theo thời điểm sửa đổi cuối của thư mục. Logic nằm trong [src/report-retention.mjs](src/report-retention.mjs).

### Các file cục bộ

| File / thư mục | Nội dung | Git |
|---|---|---|
| `.scanner-auth/` | Tài khoản chủ (`owner.json`) và thành viên (`users.json`) | Bỏ qua |
| `.scanner-reports/` | Báo cáo theo tài khoản (`user-<id>/`), tự xóa khi quá hạn | Bỏ qua |
| `.scanner-tools/` | Semgrep và công cụ cục bộ | Bỏ qua |
| `.ui-public.json` | Origin công khai (ngrok) | Bỏ qua |
| `.ui-session.json` | Cổng và phiên đang chạy | Bỏ qua |

## Đọc báo cáo

Mỗi lượt quét tạo `report.html`, `report.json` và `report.txt`. Trong giao diện, mở **Kết quả kiểm tra** và chọn một phát hiện:

- **Vị trí cần kiểm tra**: lời gọi hoặc đối số nhạy cảm.
- **Dòng liên quan**: điểm nhận đầu vào, các dòng truyền qua biến và điểm sử dụng.
- **Cách khắc phục**: thay API, tách tham số hoặc kiểm tra đầu vào ở đâu.

Các trường JSON chính:

| Trường | Ý nghĩa |
|---|---|
| `ruleId`, `relatedRuleIds` | Quy tắc chính và các chữ ký đã gộp |
| `location.line/column`, `endLine/endColumn` | Khoảng vị trí do engine trả về |
| `knowledge.cweContext` | Mô tả CWE, tác động, hướng giảm thiểu |
| `knowledge.verificationRequirements` | Yêu cầu ASVS cần kiểm chứng |
| `stats.sourceAnalysis.languages` | Số file đã phân tích / đã chọn theo ngôn ngữ |

**Ví dụ.** Với Express, một dòng đọc `incoming.body.id`, dòng sau ghép câu SQL, rồi `pool.query()` dùng câu đó. Cách sửa: câu SQL cố định với `$1` và mảng giá trị riêng. Xem [mẫu Express](scripts/semgrep-express-cases.mjs) và [truy vấn tham số hóa của node-postgres](https://node-postgres.com/features/queries).

> Mọi phát hiện cần kiểm chứng thủ công: nguồn dữ liệu, biện pháp bảo vệ và việc API thực sự được gọi khi triển khai. Kết quả `version-match` của dependency **chưa xác minh** reachability hay khả năng khai thác.

## Nguồn dữ liệu

Thư viện cục bộ có **5.004 bản ghi** (snapshot 05–06/11/2026):

| Nguồn | Bản ghi | Vai trò |
|---|---:|---|
| [MITRE CWE](https://cwe.mitre.org/) v5.0 | 984 | Mô tả điểm yếu, tác động, giảm thiểu |
| [OWASP WSTG](https://wstg.owasp.org/v4.2/) v4.2 | 97 | Hướng dẫn kiểm thử |
| [OWASP ASVS](https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release) v5.0.0 | 345 | Yêu cầu kiểm chứng |
| [OWASP API Security](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) 2023 | 33 | Rủi ro API |
| [GitHub Advisory Database](https://github.com/advisories) | 1.777 | Đối chiếu phiên bản dependency |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 1.768 | Trạng thái từng bị khai thác |

**Manifest dependency được hỗ trợ**

| Manifest | Phạm vi |
|---|---|
| `package-lock.json` v1/v2/v3, `npm-shrinkwrap.json` | Phiên bản cụ thể, so sánh SemVer |
| `requirements*.txt` | `name==version` không marker, so sánh PEP 440 |
| `Pipfile.lock` | default/develop có `==version`, không marker |
| `package.json` | Chỉ ghi nhận khai báo, không coi range là phiên bản đã cài |
| Composer, Maven, Go, NuGet, Ruby, Poetry, Yarn, pnpm | Chưa so phiên bản tự động |

Nguồn tải, phiên bản, thời điểm lấy và checksum: [data/manifest.json](data/manifest.json) · [data/extensions-manifest.json](data/extensions-manifest.json) · [data/README.md](data/README.md).

## Giới hạn

| Hạng mục | Giới hạn |
|---|---|
| Mã nguồn | 2.000 file, 1 MiB/file, 20 MiB tổng, 5.000 phát hiện |
| Dòng dài | Dòng > 8.192 ký tự bị bỏ qua với chữ ký và được ghi nhận |
| ZIP | 20 MiB nén, 10.000 entry; chỉ store/deflate; không hỗ trợ mã hóa, ZIP64, đa phần |
| Semgrep | Timeout 90 giây; phân tích luồng trong phạm vi từng hàm |
| Bỏ qua | Symlink, binary, thư mục dependency/build thông dụng; không đọc `.gitignore` |

- Chặn path traversal, tên trùng và tên file Windows không hợp lệ khi giải nén.
- Giao diện mặc định chỉ lắng nghe trên loopback; mã tải lên được xử lý trong thư mục tạm.
- Báo cáo có thể chứa đường dẫn, tên biến và bằng chứng đã che một phần — kiểm tra trước khi chia sẻ.
- Semgrep CE không theo dõi luồng qua nhiều hàm; một số mẫu dựa vào tên biến như `req`, `request`, `db`.

## Cấu trúc dự án

```text
.
├── scan.mjs              # Điểm vào CLI
├── ui.mjs                # Điểm vào máy chủ giao diện
├── web/                  # Giao diện web (HTML, CSS, JS)
├── src/
│   ├── source.mjs        # Chọn file, quét nhanh, gộp phát hiện
│   ├── flow.mjs          # Theo dõi biến bằng văn bản (FLOW-*)
│   ├── extended-rules.mjs, scenario-rules.mjs
│   ├── semgrep.mjs       # Chạy Semgrep và chuyển đổi kết quả
│   ├── dependencies.mjs  # Đối chiếu CVE dependency
│   ├── knowledge.mjs     # Gắn ngữ cảnh CWE/OWASP
│   ├── report.mjs        # Xuất JSON/HTML/TXT
│   ├── report-retention.mjs # Tự xóa báo cáo quá hạn
│   ├── owner-account.mjs # Tài khoản chủ và thành viên
│   ├── ui-server.mjs     # API và phiên đăng nhập
│   └── uploads.mjs       # Giải nén ZIP an toàn
├── rules/                # Quy tắc Semgrep YAML
├── data/                 # Snapshot CWE, OWASP, advisory, KEV
├── scripts/              # Benchmark và đồng bộ dữ liệu
├── test/                 # Kiểm thử
├── examples/             # Mã mẫu và quy tắc tùy chỉnh
└── docs/                 # Tài liệu chi tiết
```

## Phát triển

```powershell
npm test                    # Chạy toàn bộ kiểm thử
npm run test:coverage       # Kiểm thử với ngưỡng coverage 80%
npm run benchmark:semgrep   # Benchmark bằng Semgrep thật
npm run knowledge:sync      # Cập nhật snapshot dữ liệu gốc
npm run knowledge:expand    # Cập nhật dữ liệu mở rộng
```

**Benchmark** trên 85 cặp mã mẫu (có lỗi / đã sửa):

| Chế độ | Phát hiện mẫu có lỗi | Cảnh báo nhầm mẫu đã sửa |
|---|---:|---:|
| Phân tích sâu | 85/85 | 0/85 |
| Quét nhanh | 27/85 | 9/85 |

Chi tiết: [docs/testing/semgrep.tdd.md](docs/testing/semgrep.tdd.md).

**Thêm quy tắc Semgrep**

1. Chọn API cần kiểm tra và CWE tương ứng.
2. Khai báo mẫu trong file YAML phù hợp ở `rules/`.
3. Đăng ký cùng ID kèm tiêu đề, CWE, mức độ, cách sửa trong `src/semgrep.mjs`.
4. Thêm một cặp mã có lỗi / đã sửa và chạy `npm run benchmark:semgrep`.

## Lộ trình

- [x] Đa tài khoản, mỗi tài khoản chỉ thấy lượt kiểm tra của mình
- [x] Tự xóa báo cáo quá thời hạn lưu giữ (`SENTRY_REPORT_RETENTION_DAYS`)
- [ ] Thời hạn lưu giữ và hạn mức dung lượng riêng cho từng tài khoản
- [ ] Đổi mật khẩu cho thành viên
- [ ] So phiên bản tự động cho Composer, Maven, Go, NuGet, Poetry, Yarn, pnpm
- [ ] Phân tích luồng liên hàm

## Đóng góp

- **Quy tắc mới**: mô tả API, nguồn dữ liệu, đối số cần đánh dấu và cách sửa; kèm ca có lỗi và ca đã sửa; đối chiếu ID, CWE, file, dòng scanner trả về.
- **Báo lỗi**: gửi lệnh chạy, chế độ, phiên bản Node/Semgrep và mẫu mã tối thiểu đã loại thông tin riêng.

## Giấy phép và nguồn tham khảo

- Mã nguồn phát hành theo giấy phép [MIT](LICENSE)
- Báo cáo lỗ hổng: [SECURITY.md](SECURITY.md)
- Nguồn tham khảo: [SOURCES.md](SOURCES.md)
- Nguồn và giấy phép dữ liệu: [data/README.md](data/README.md), [data/NOTICE.md](data/NOTICE.md)
- Danh mục quy tắc: [docs/RULES.md](docs/RULES.md)
