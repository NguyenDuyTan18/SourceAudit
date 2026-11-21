# SrcAudit

> Công cụ phân tích tĩnh mã nguồn (SAST) chạy cục bộ, xuất báo cáo có vị trí, bằng chứng và hướng khắc phục.

[English quickstart](docs/quickstart-en.md) · [Kết quả benchmark](docs/testing/accuracy.md)

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

SrcAudit quét mã nguồn để tìm điểm yếu bảo mật theo CWE, đối chiếu dependency với advisory đã biết và bổ sung ngữ cảnh từ OWASP, MITRE CWE, GitHub Advisory Database và CISA KEV. Quá trình quét chạy offline trên máy của bạn.

Có hai cách dùng:

- **Giao diện web**: tải lên một tệp ZIP hoặc chọn một thư mục từ máy.
- **CLI**: quét trực tiếp một file hoặc thư mục, phù hợp để tích hợp CI.

## Tính năng

| Tính năng | Mô tả |
|---|---|
| **Quét nhanh** | Quy tắc tích hợp cho mã nguồn, cấu hình và credential; chạy bằng Node.js |
| **Phân tích sâu** | Quy tắc Semgrep CE cho JS/TS, Python, PHP, Java, Go, C#, Ruby, GitHub Actions và các tên Dockerfile phổ biến như `Dockerfile.prod` |
| **CVE dependency** | Cả hai chế độ quét đều đối chiếu phiên bản npm, PyPI và Composer với snapshot advisory cục bộ và ghi chú CISA KEV |
| **Thư viện nhận dạng** | CWE, OWASP WSTG, ASVS, API Security, GitHub Advisory Database và CISA KEV để tra cứu và gắn ngữ cảnh vào báo cáo |
| **Báo cáo** | Xuất JSON, HTML, TXT và SARIF 2.1.0, có `file:dòng:cột`, đoạn trích đã che dữ liệu nhạy cảm và hướng sửa |
| **Tích hợp CI** | SARIF cho GitHub Code Scanning, `--diff` chỉ quét file thay đổi trong PR, `--baseline` chỉ báo phát hiện mới, chú thích `srcaudit-ignore` có lý do, tôn trọng `.gitignore` |
| **Tự xóa báo cáo cũ** | Báo cáo quá hạn lưu giữ (mặc định 7 ngày) bị xóa khỏi đĩa và lịch sử |
| **Mở trực tiếp trên máy** | Mặc định chạy ở loopback và mở giao diện ngay. Chế độ truy cập từ xa dùng tài khoản và chỉ bật khi cấu hình rõ ràng. |

Danh sách đầy đủ quy tắc: [docs/RULES.md](docs/RULES.md).

## Yêu cầu hệ thống

- **Node.js** 22 trở lên
- **Semgrep CE** (tùy chọn, chỉ cần cho phân tích sâu), đã kiểm thử với 1.184.0
- **Python** 3 (tùy chọn, để cài Semgrep vào venv cục bộ)

## Cài đặt

Chạy từ thư mục dự án:

```sh
git clone https://github.com/NguyenDuyTan18/SourceAudit.git
cd SourceAudit
npm ci --ignore-scripts
npm start
```

Mở địa chỉ loopback mà terminal in ra. Nếu đã cài dependency trên Windows, có thể mở bằng `Start-UI.cmd`. Trong PowerShell chặn `npm.ps1`, dùng `npm.cmd` với cùng đối số.

Để thử từ CLI và xem báo cáo HTML, dùng thư mục mẫu đi kèm:

```sh
node scan.mjs --src ./examples/demo-src --out ./.scanner-reports/first-scan
```

### Cài Semgrep CE tùy chọn

Trên Windows:

```powershell
py -m venv .scanner-tools/semgrep
.\.scanner-tools\semgrep\Scripts\python.exe -m pip install semgrep==1.184.0
```

Trên Linux hoặc macOS:

```sh
python3 -m venv .scanner-tools/semgrep
./.scanner-tools/semgrep/bin/python -m pip install semgrep==1.184.0
```

SrcAudit tìm Semgrep theo thứ tự: biến môi trường `SECURITYSCANNER_SEMGREP_EXE` → `.scanner-tools/semgrep` → `semgrep` trên `PATH`. Xem thêm [tài liệu cài Semgrep CE](https://semgrep.dev/docs/getting-started/quickstart-ce).

## Sử dụng

### Giao diện web

```powershell
npm start
```

Trên Windows có thể nhấp đúp `Start-UI.cmd`.

1. Mở địa chỉ local in trên terminal (ưu tiên cổng `8787`, tự chọn cổng trống nếu bị chiếm).
2. Chọn **Tải ZIP** hoặc **Tải thư mục**. Chế độ cục bộ mở trực tiếp, không cần tài khoản.
3. Chọn **Chế độ kiểm tra**: *Quét nhanh* hoặc *Phân tích sâu bằng Semgrep*.
4. Bấm **Bắt đầu kiểm tra** và xem **Kết quả kiểm tra**. Mỗi phát hiện cho biết cách phát hiện, bằng chứng, điều kiện cần kiểm tra và hướng sửa.

Để thử nhanh, chọn thư mục `examples/demo-src`, hoặc tạo ZIP mẫu:

```powershell
Compress-Archive -Path .\examples\demo-src\* -DestinationPath .\srcaudit-demo.zip -Force
```

> Nếu giao diện báo **Cần khởi động lại**, chạy lại `Start-UI.cmd`. Launcher xác minh tiến trình SrcAudit đang giữ cổng trước khi thay thế.

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
| `--baseline <report.json>` | Ẩn phát hiện đã có trong báo cáo trước, chỉ báo phát hiện mới |
| `--diff <ref>` | Chỉ quét file thay đổi so với merge-base của `<ref>` và `HEAD` (gồm file chưa commit và chưa track); cần git |
| `--no-gitignore` | Quét cả file bị `.gitignore` loại trừ |
| `--include-tests` | Quét cả file kiểm thử. Mặc định bỏ qua. |
| `--list-rules` | Liệt kê quy tắc tích hợp |
| `--knowledge <id>` | Tra cứu CWE, CVE, WSTG… |

**Mã thoát**

| Mã | Ý nghĩa |
|---|---|
| `0` | Quét xong |
| `1` | Quét xong và có phát hiện đạt ngưỡng `--fail-on` |
| `2` | Đầu vào không hợp lệ, lỗi đọc/ghi, hoặc còn phần chưa quét được |

## Cấu hình

### Dữ liệu cục bộ và tài khoản từ xa

Chế độ cục bộ chỉ nhận kết nối trực tiếp từ máy đang chạy. Nếu bản cài đã có tài khoản chủ, giao diện cục bộ tiếp tục dùng lịch sử quét và write-up trong không gian của tài khoản chủ. Bản cài mới lưu lịch sử tại `.scanner-reports/user-local/`.

Khi bật chế độ truy cập từ xa, tạo **tài khoản chủ** từ địa chỉ local. Tài khoản chủ mở mục **Tài khoản** trong giao diện để tạo hoặc xóa **thành viên**.

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
- **Hàng đợi.** Máy chủ lưu ZIP vào đĩa trước khi trả mã lượt quét. Một tiến trình con giải nén và quét từng lượt. Khi khởi động lại, ứng dụng nạp lại các lượt chưa hoàn tất và chạy lại từ đầu. Hàng đợi tối đa 10 và mỗi tài khoản có tối đa một lượt đang chờ hoặc đang chạy.
- **Dữ liệu riêng theo tài khoản.** Write-up nhập từ web được lưu riêng, tối đa 100 mục mỗi tài khoản. Báo cáo có thể trích tối đa ba write-up, mỗi mục tối đa ba liên kết. Write-up dùng chung từ bản cũ vẫn nằm trong thư mục cũ và có thể dùng qua CLI.
- **Xóa dữ liệu.** Dùng nút **Xóa** cạnh lượt quét đã kết thúc để giải phóng dung lượng. Xóa thành viên thu hồi phiên đăng nhập và xóa báo cáo, lượt quét còn chờ và write-up của họ.

Chạy một phiên máy chủ web cho mỗi thư mục dữ liệu. Trong lúc quét, ZIP và mã giải nén nằm trong thư mục báo cáo của tài khoản. Ứng dụng dọn mã tạm và ZIP sau khi kết thúc, kể cả khi engine báo lỗi. Nếu tiến trình bị dừng đột ngột, lượt quét được khôi phục ở lần khởi động kế tiếp.

Kiểm thử: [test/account-isolation.test.mjs](test/account-isolation.test.mjs).

### Truy cập từ xa qua ngrok

1. Tạo `.ui-public.json` ở thư mục gốc:

   ```json
   { "origin": "https://your-domain.ngrok-free.dev" }
   ```

2. Bật chế độ từ xa, khởi động ứng dụng, rồi tạo tài khoản chủ qua địa chỉ local nếu chưa có:

   ```powershell
   $env:SRCAUDIT_ENABLE_REMOTE = '1'
   npm start
   ```

3. Trỏ ngrok tới cổng ghi trong `.ui-session.json`:

   ```powershell
   ngrok http http://127.0.0.1:8787 --inspect=false
   ```

Khi tên miền ngrok thay đổi, cập nhật `origin` và khởi động lại. File cấu hình cũ có `username` và `password` vẫn được hỗ trợ qua biểu mẫu và HTTP Basic Authentication.

### Tích hợp CI

Mỗi lượt quét CLI ghi thêm `report.sarif` (SARIF 2.1.0) để tải lên GitHub Code Scanning, GitLab hoặc mở bằng SARIF Viewer trong VS Code. Mẫu workflow GitHub Actions: [docs/ci/github-code-scanning.yml](docs/ci/github-code-scanning.yml). Với pull request, workflow chỉ quét file thay đổi; với push lên `main`, workflow quét toàn bộ repo.

```powershell
# Chỉ quét file thay đổi so với main, dừng CI khi có phát hiện high trở lên
node scan.mjs --src . --diff origin/main --fail-on high

# Ghi nhận hiện trạng một lần, sau đó chỉ báo phát hiện mới
node scan.mjs --src . --out ./baseline
node scan.mjs --src . --baseline ./baseline/report.json --fail-on high
```

**Baseline.** Mỗi phát hiện có `fingerprint` tính từ quy tắc, file và nội dung dòng đã che literal. `baseline.fixed` chỉ đếm phát hiện cũ vắng mặt trên các tệp được kiểm tra bằng cùng chế độ. `baseline.unassessed` đếm mục chưa xác nhận lại, ví dụ tệp nằm ngoài diff hoặc lượt quét bị gián đoạn. Diff không có tệp đủ điều kiện trả về lượt quét hoàn tất với 0 tệp.

**Bỏ qua cảnh báo trong mã.** Đặt chú thích ở cuối dòng bị báo, hoặc một mình ở dòng ngay trên. Bắt buộc có lý do sau `--`; danh sách mã quy tắc hoặc CWE là tùy chọn (bỏ trống nghĩa là mọi phát hiện trên dòng đó):

```js
db.query(sql); // srcaudit-ignore SRC-SQL -- sql là hằng số nội bộ
# srcaudit-ignore CWE-798 -- khóa giả dùng cho test
```

Phát hiện bị bỏ qua chuyển sang `report.suppressed` (kèm lý do), được liệt kê trong báo cáo TXT/HTML và xuất vào SARIF với `suppressions`, nên vẫn kiểm tra lại được. Chú thích thiếu lý do hoặc sai định dạng không có tác dụng và được đếm trong `stats.suppressions.invalidDirectives`.

**`.gitignore`.** Trình quét đọc `.gitignore` ở thư mục gốc và mọi thư mục con (hỗ trợ `*`, `**`, `?`, `[...]`, `!`, `/` neo và `/` cuối). Số file bị loại nằm ở `stats.gitignore.ignored`. Lưu ý `.env` thường bị `.gitignore` loại trừ; dùng `--no-gitignore` khi muốn tìm secret trong cả các file đó.

### Thời hạn lưu báo cáo

Báo cáo không được giữ vô thời hạn. Thư mục báo cáo trong `.scanner-reports/` cũ hơn thời hạn lưu giữ sẽ bị xóa:

- **Giao diện web**: quét khi khởi động và mỗi giờ; lượt kiểm tra hết hạn cũng biến mất khỏi lịch sử và không tải lại được.
- **CLI**: quét trước khi ghi báo cáo mới, chỉ khi dùng thư mục mặc định (không truyền `--out`).

| Biến môi trường | Mặc định | Ý nghĩa |
|---|---|---|
| `SRCAUDIT_REPORT_RETENTION_DAYS` | `7` | Số ngày giữ báo cáo (0–365, chấp nhận số thập phân). `0` tắt tự xóa. |
| `SRCAUDIT_ACCOUNT_STORAGE_MIB` | `128` | Hạn mức MiB áp dụng riêng cho mỗi tài khoản web. Tính dung lượng báo cáo và ZIP lưu trong hàng đợi. |

```powershell
$env:SRCAUDIT_REPORT_RETENTION_DAYS = "3"; npm start
```

Chỉ thư mục do SrcAudit tạo (tên UUID của giao diện hoặc timestamp của CLI) mới bị xóa. Thư mục tự đặt tên qua `--out`, file lẻ và symlink được giữ nguyên. Tuổi tính theo thời điểm sửa đổi cuối của thư mục. Logic nằm trong [src/report-retention.mjs](src/report-retention.mjs).

### Các file cục bộ

| File / thư mục | Nội dung | Git |
|---|---|---|
| `.scanner-auth/` | Tài khoản chủ (`owner.json`) và thành viên (`users.json`) | Bỏ qua |
| `.scanner-reports/` | Báo cáo và dữ liệu lượt quét đang chờ theo tài khoản (`user-<id>/`) | Bỏ qua |
| `knowledge-local/` | Chỉ mục write-up cục bộ và các thư mục riêng của tài khoản | Bỏ qua |
| `.scanner-tools/` | Semgrep và công cụ cục bộ | Bỏ qua |
| `.ui-public.json` | Origin công khai (ngrok) | Bỏ qua |
| `.ui-session.json` | Cổng và phiên đang chạy | Bỏ qua |

## Đọc báo cáo

Mỗi lượt quét tạo `report.html`, `report.json`, `report.txt` và `report.sarif`. Trong giao diện, mở **Kết quả kiểm tra** và chọn một phát hiện:

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
| `stats.dependencyAnalysis` | Số manifest, phiên bản, cảnh báo và trường hợp chưa so sánh được |

**Ví dụ.** Với Express, một dòng đọc `incoming.body.id`, dòng sau ghép câu SQL, rồi `pool.query()` dùng câu đó. Cách sửa: câu SQL cố định với `$1` và mảng giá trị riêng. Xem [mẫu Express](scripts/semgrep-express-cases.mjs) và [truy vấn tham số hóa của node-postgres](https://node-postgres.com/features/queries).

> Mọi phát hiện cần kiểm chứng thủ công: nguồn dữ liệu, biện pháp bảo vệ và việc API thực sự được gọi khi triển khai. Kết quả `version-match` của dependency **chưa xác minh** reachability hay khả năng khai thác.

## Nguồn dữ liệu

Thư viện cục bộ có **6.129 bản ghi** (snapshot cập nhật ngày 21/11/2026):

| Nguồn | Bản ghi | Vai trò |
|---|---:|---|
| [MITRE CWE](https://cwe.mitre.org/) v5.0 | 984 | Mô tả điểm yếu, tác động, giảm thiểu |
| [OWASP WSTG](https://wstg.owasp.org/v4.2/) v4.2 | 97 | Hướng dẫn kiểm thử |
| [OWASP ASVS](https://github.com/OWASP/ASVS/releases/tag/v5.0.0_release) v5.0.0 | 345 | Yêu cầu kiểm chứng |
| [OWASP API Security](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) 2023 | 33 | Rủi ro API |
| [GitHub Advisory Database](https://github.com/advisories) | 2.867 | Đối chiếu phiên bản dependency |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 1.790 | Trạng thái từng bị khai thác |
| [Nghiên cứu phân tích tĩnh](data/research.json) | 6 | Phương pháp đo độ chính xác, phân tích báo nhầm và giới hạn các kết quả đánh giá |
| [Tài liệu kỹ thuật](data/references.json) | 7 | SSDF, OSPS, SAMM, OWASP Benchmark, OSV, SARIF và OpenSSF Scorecard |

**Manifest dependency được hỗ trợ**

| Manifest | Phạm vi |
|---|---|
| `package-lock.json` v1/v2/v3, `npm-shrinkwrap.json` | Phiên bản cụ thể, so sánh SemVer |
| `yarn.lock` v1 và Yarn Berry (v2+) | Phiên bản đã resolve, bỏ qua workspace/link/file |
| `pnpm-lock.yaml` v5/v6/v9 | Phiên bản đã resolve, bỏ hậu tố peer dependency |
| `requirements*.txt` | `name==version` không marker, so sánh PEP 440 |
| `Pipfile.lock` | default/develop có `==version`, không marker |
| `package.json` | Chỉ ghi nhận khai báo, không coi range là phiên bản đã cài |
| `composer.lock` | `packages` và `packages-dev`. So phiên bản ổn định từ 1 đến 4 thành phần số với các điều kiện so sánh đơn giản trong advisory. Báo riêng phiên bản dev, prerelease hoặc khoảng phiên bản chưa hỗ trợ. |
| Maven, Go, NuGet, Ruby, Poetry | Chưa so phiên bản tự động |

Nguồn tải, phiên bản, thời điểm lấy và checksum: [data/manifest.json](data/manifest.json) · [data/extensions-manifest.json](data/extensions-manifest.json) · [data/README.md](data/README.md).

## Giới hạn

| Hạng mục | Giới hạn |
|---|---|
| Mã nguồn | Mặc định 2.000 file, 10 MiB/file, 50 MiB tổng khi tải lên hoặc quét sâu, 5.000 phát hiện |
| Dòng dài | Dòng > 8.192 ký tự bị bỏ qua với chữ ký và được ghi nhận |
| ZIP | 50 MiB nén, 10.000 entry; chỉ store/deflate; không hỗ trợ mã hóa, ZIP64, đa phần |
| Semgrep | Timeout 90 giây; phân tích luồng trong phạm vi từng hàm |
| Bỏ qua | Symlink, binary, thư mục dependency/build thông dụng, file bị `.gitignore` loại trừ (giao diện web không nhận `.gitignore` khi tải lên) và file kiểm thử như `*.test.*`, `*.spec.*`, `test_*.py`, `*_test.go` hoặc file nằm trong `test/`, `tests/`, `__tests__/` |

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
│   ├── sarif.mjs         # Xuất SARIF 2.1.0
│   ├── triage.mjs        # Fingerprint, baseline, srcaudit-ignore
│   ├── gitignore.mjs     # Đọc mẫu .gitignore
│   ├── git-diff.mjs      # Danh sách file thay đổi cho --diff
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
npm run benchmark:check     # Đo độ chính xác trên OWASP Benchmark + mã sạch, so với baseline
npm run knowledge:sync      # Cập nhật snapshot dữ liệu gốc
npm run knowledge:expand    # Cập nhật dữ liệu mở rộng
```

**Độ chính xác** (chi tiết và cách đọc: [docs/testing/accuracy.md](docs/testing/accuracy.md)):

| Bộ dữ liệu | Quét nhanh | Phân tích sâu |
|---|---|---|
| 91 cặp mẫu nội bộ (có lỗi / đã sửa) | phát hiện 28/91 · báo nhầm 1/91 | phát hiện 91/91 · báo nhầm 0/91 |
| OWASP Benchmark Python (1.230 ca) | TPR 18,1% · FPR 6,7% | TPR 25,7% · FPR 3,5% |
| OWASP Benchmark Java (2.740 ca) | TPR 17,0% · FPR 15,6% | TPR 17,0% · FPR 13,6% |
| Mã sạch Python (flask, requests) | 0,25 cảnh báo / 1.000 dòng | 0 |
| Mã sạch JS (express, koa, axios) | 0 | 0 |

Bộ mẫu nội bộ được viết cùng quy tắc nên không đại diện cho mã thật; hãy dựa vào các dòng OWASP. Quét nhanh lọc cảnh báo nhầm bằng AST cho JS/TS (hằng số, dữ liệu đã làm sạch, `execFile` không qua shell, `sendFile` có `root`) và theo ngữ cảnh (tham chiếu biến môi trường, giá trị giữ chỗ, mã test/ví dụ, docstring Python).

Quét sâu Python dùng AST để kiểm tra lại cảnh báo trong một số ngữ cảnh. Sau khi bổ sung các rule HTML và cookie Flask, thực thể ngoài của SAX và mở rộng rule LDAP, quét sâu phát hiện đúng 116 trong 452 ca có lỗi trên OWASP Python, với 27 báo nhầm trên 778 ca an toàn. [Số liệu theo nhóm và cách chạy lại](docs/testing/accuracy.md#mở-rộng-nhận-diện-kết-nối-ldap-trong-python)

Chi tiết: [docs/testing/semgrep.tdd.md](docs/testing/semgrep.tdd.md).

**Thêm quy tắc Semgrep**

1. Chọn API cần kiểm tra và CWE tương ứng.
2. Khai báo mẫu trong file YAML phù hợp ở `rules/`.
3. Đăng ký cùng ID kèm tiêu đề, CWE, mức độ, cách sửa trong `src/semgrep.mjs`.
4. Thêm một cặp mã có lỗi / đã sửa và chạy `npm run benchmark:semgrep`.

## Lộ trình

- [x] Đa tài khoản, mỗi tài khoản chỉ thấy lượt kiểm tra của mình
- [x] Tự xóa báo cáo quá thời hạn lưu giữ (`SRCAUDIT_REPORT_RETENTION_DAYS`)
- [x] Hàng đợi phục hồi sau khởi động lại, hạn mức lưu trữ và write-up riêng cho mỗi tài khoản
- [ ] Cấu hình thời hạn lưu giữ riêng cho từng tài khoản
- [ ] Đổi mật khẩu cho thành viên
- [x] Xuất SARIF, `--diff`, `--baseline`, `srcaudit-ignore`, tôn trọng `.gitignore`
- [x] So phiên bản cho `yarn.lock` và `pnpm-lock.yaml`
- [x] So phiên bản ổn định trong `composer.lock`
- [ ] So phiên bản tự động cho Maven, Go, NuGet, Poetry
- [x] Benchmark độ chính xác trên OWASP Benchmark và mã sạch, chặn hồi quy trong CI
- [x] Lọc cảnh báo nhầm bằng AST (JS/TS) và theo ngữ cảnh
- [ ] Lọc AST cho Python/Java (tree-sitter) và mở rộng nguồn/điểm nguy hiểm theo kết quả OWASP
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
