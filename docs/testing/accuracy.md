# Đo độ chính xác

`scripts/benchmark.mjs` đo SrcAudit trên các cặp đối chứng, các bộ OWASP có nhãn và mã nguồn dự án. CI so sánh kết quả với [benchmarks/baseline.json](../../benchmarks/baseline.json).

```powershell
npm run benchmark:check                                   # tải dữ liệu (lần đầu) và so với baseline
node scripts/benchmark.mjs --suite owasp-python            # một bộ, chế độ quét nhanh
node scripts/benchmark.mjs --mode deep --suite internal,owasp-python
node scripts/benchmark.mjs --json out.json                 # xuất chi tiết theo nhóm lỗi và quy tắc
node scripts/benchmark.mjs --update-baseline benchmarks/baseline.json   # sau khi cải thiện có chủ đích
```

## Bộ dữ liệu

| Suite | Nguồn | Nhãn | Ý nghĩa |
|---|---|---|---|
| `internal` | 91 cặp có lỗi / đã sửa trong [scripts/benchmark-cases.mjs](../../scripts/benchmark-cases.mjs) | Có | Kiểm tra hồi quy cho quy tắc đã viết |
| `owasp-java` | [OWASP Benchmark Java 1.2](https://github.com/OWASP-Benchmark/BenchmarkJava), 2.740 ca | Có (`expectedresults-1.2.csv`) | Recall và tỷ lệ báo nhầm trên Java |
| `owasp-python` | [OWASP Benchmark Python 0.1](https://github.com/OWASP-Benchmark/BenchmarkPython), 1.230 ca | Có (`expectedresults-0.1.csv`) | Recall và tỷ lệ báo nhầm trên Python |
| `python-precision` | 8 cặp Python trong [scripts/semgrep-python-precision-cases.mjs](../../scripts/semgrep-python-precision-cases.mjs) | Có | Kiểm tra guard, hằng số và các ca mất hiệu lực |
| `python-holdout` | 3 cặp Python riêng trong cùng tệp | Có | Đối chiếu trên template XPath, tên biến, nguồn dữ liệu và nhánh khác |
| `python-coverage` | 35 cặp trong [scripts/semgrep-python-coverage-cases.mjs](../../scripts/semgrep-python-coverage-cases.mjs) | Có | Kiểm tra HTML, cookie và chuyển hướng Flask, SAX, LDAP, hàm băm, tệp tạm, TLS và bộ sinh ngẫu nhiên của Python. |
| `clean-js` | express, koa, axios (`lib/`) | Không | Mọi phát hiện là ứng viên báo nhầm |
| `clean-py` | flask, requests (`src/`) | Không | Mọi phát hiện là ứng viên báo nhầm |
| `workflow-reference` | Workflow công khai từ `actions/setup-node`, `actions/setup-python`, `actions/checkout`, ghim commit trong [benchmark.mjs](../../scripts/benchmark.mjs) | Không | Kiểm tra cảnh báo cấu hình trên workflow thật. Chỉ đọc YAML và giấy phép; workflow không được chạy. |

Mỗi bộ dữ liệu bên ngoài được cố định commit trong `DATASETS` của script, tải bằng sparse checkout vào `.scanner-tools/benchmarks/` (bị git bỏ qua) và chỉ được đọc như văn bản. OWASP Benchmark dùng giấy phép GPL-2.0 nên không được đưa vào repo.

Chạy `node scripts/benchmark.mjs --fetch --mode deep --suite workflow-reference` để cập nhật bản sao cục bộ về đúng commit và quét. Các ca đối chứng tự viết trong `scripts/semgrep-framework-config-cases.mjs` kiểm tra `permissions: write-all` ở cấp workflow và job, đối chiếu với quyền chỉ đọc hoặc giá trị cùng tên trong `env`.

Ngày 21/11/2026, Semgrep phát hiện đúng 110/110 ca có nhãn trong bộ đối chứng và không báo ca đã sửa nào trong bộ đó. Lượt quét tham chiếu hoàn tất trên 31 workflow, 86 tệp JavaScript và 43 tệp Python; không ghi nhận cảnh báo trong các tệp này. Các mẫu tham chiếu chưa có nhãn lỗ hổng nên số liệu này chỉ mô tả lượt quét đó.

### Hàm băm, tệp tạm và TLS của Python

Trên 1.230 ca OWASP Python, bộ quy tắc mới phát hiện 116/452 ca có lỗi khi quét nhanh (recall 25,66%, precision 69,05%) và 184/452 khi quét sâu (recall 40,71%, precision 87,20%). Riêng nhóm hàm băm, quét nhanh phát hiện 71/71 và Semgrep phát hiện 68/71, với 0 cảnh báo trên 80 ca đối chứng. Đây là số liệu của bộ có nhãn OWASP Python.

Bộ `benchmark:semgrep` phân biệt 125/125 cặp, gồm trường hợp SHA-1 dùng riêng trong HMAC và trường hợp cùng hàm còn được gọi để tạo digest trực tiếp. Quét sâu không ghi nhận cảnh báo trên 43 tệp tham chiếu Flask và Requests. Nguồn tham khảo cho ngoại lệ HMAC là [tài liệu ItsDangerous](https://itsdangerous.palletsprojects.com/en/stable/concepts/#digest-method-security).

### Mốc precision và recall trên 50%

Trên 1.230 ca OWASP Python, bản đo ngày 21/11/2026 cho kết quả sau:

| Chế độ | Phát hiện đúng | Báo nhầm | Precision | Recall | Tỷ lệ báo nhầm |
|---|---:|---:|---:|---:|---:|
| Quét nhanh | 239/452 | 52/778 | 82,13% | 52,88% | 6,68% |
| Quét sâu | 283/452 | 27/778 | 91,29% | 62,61% | 3,47% |

Phần tăng đến từ việc nhận diện bộ sinh `random` mặc định ở cả hai chế độ và đối số `secure=False` của cookie Flask nhiều dòng trong quét nhanh. Một lời gọi bộ sinh mặc định được báo để rà soát mục đích bảo mật. Các tỷ lệ trên được đo theo nhãn của bộ OWASP Python.

Baseline `internal:quick` dùng 93 cặp trong đợt công bố này. Hai cặp bổ sung kiểm tra quyền token GitHub Actions bằng Semgrep. Quét nhanh ghi nhận 28 phát hiện đúng và 1 ca đối chứng bị báo nhầm, nên recall tính trên 93 cặp là 30,11%.

### Xác minh bản công bố

Hai chế độ được chạy lại trên 1.230 ca OWASP Python và 2.740 ca OWASP Java. Số liệu Java được báo riêng để người dùng thấy khác biệt về độ bao phủ giữa các bộ và ngôn ngữ.

| Bộ dữ liệu | Chế độ | Precision | Recall | Tỷ lệ báo nhầm |
|---|---|---:|---:|---:|
| OWASP Python v0.1 | Quét nhanh | 82,13% | 52,88% | 6,68% |
| OWASP Python v0.1 | Quét sâu | 91,29% | 62,61% | 3,47% |
| OWASP Java v1.2 | Quét nhanh | 53,91% | 17,03% | 15,55% |
| OWASP Java v1.2 | Quét sâu | 57,14% | 16,96% | 13,58% |

Hai lượt đạt đối chiếu với [baseline lưu trong repo](../../benchmarks/baseline.json). Trên 86 tệp JavaScript và 43 tệp Python tham chiếu, quét sâu hoàn tất và ghi nhận 0 cảnh báo. Bộ tham chiếu hữu ích để rà cảnh báo trên mã công khai; các số precision và recall ở bảng trên lấy từ bộ có nhãn.

## Chỉ số

- **TPR** (recall) = TP / (TP + FN): tỷ lệ lỗ hổng thật được báo.
- **FPR** = FP / (FP + TN): tỷ lệ ca an toàn bị báo nhầm.
- **Score** = TPR − FPR (chỉ số Youden, như scorecard OWASP). `0` nghĩa là không tốt hơn đoán ngẫu nhiên.
- **findings/KLOC**, **actionable/KLOC** trên mã sạch: số phát hiện trên 1.000 dòng; *actionable* không tính mức `info` (giá trị giữ chỗ, cấu hình dev).

Với OWASP, một ca được tính là "có báo" khi file đó có phát hiện cùng CWE với nhóm lỗi (chấp nhận CWE gần, ví dụ 327 cho nhóm hash 328, 338 cho weakrand 330 — xem `CWE_ALIASES` trong [scripts/benchmark-metrics.mjs](../../scripts/benchmark-metrics.mjs)). Phát hiện khác CWE được đếm là `offCategory` theo quy tắc.

## Kết quả lọc AST và ngữ cảnh (11/11/2026)

**Quét nhanh**

| Suite | Trước | Sau lọc AST và ngữ cảnh |
|---|---|---|
| internal | TPR 0,318 · FPR 0,106 (9 ca nhầm) | TPR 0,318 · FPR **0,012** (1 ca nhầm, PHP) |
| owasp-java | TPR 0,170 · FPR 0,156 · score −0,000 | không đổi |
| owasp-python | TPR 0,181 · FPR 0,067 · score 0,052 | không đổi |
| clean-js | 0 phát hiện / 14,6 KLOC | 0 |
| clean-py | 0,687 / KLOC (11 phát hiện) | **0,25 / KLOC** (4 phát hiện, 3 cần xử lý) |

**Phân tích sâu (Semgrep)**

| Suite | TPR | FPR | Precision |
|---|---:|---:|---:|
| internal | 1,000 | 0,000 | – |
| owasp-python | **0,029** | 0,001 | 0,93 |
| clean-js / clean-py | 0 phát hiện | | |

**Đọc kết quả.** Bộ `internal` đạt 85/85 ở chế độ sâu nhưng OWASP Python chỉ đạt 2,9% recall: quy tắc khớp tốt với mẫu tự viết, chưa phủ các nguồn/điểm nguy hiểm của Flask trong OWASP (`request.cookies`, `request.headers`, `subprocess` với chuỗi đã biến đổi, `lxml`, `ldap3`…). Quét nhanh trên Java chỉ có quy tắc SQL, và quy tắc đó báo nhầm 89% ca an toàn vì không phân biệt được giá trị hằng. Đây là những chỗ cần đầu tư tiếp theo; lọc AST hiện chỉ áp dụng cho JS/TS.

## Mở rộng Flask, Python và Servlet (12/11/2026)

| Bộ mẫu | Chế độ | Phát hiện đúng | Báo nhầm |
|---|---|---:|---:|
| Nội bộ | Nhanh | 28/91 | 1/91 |
| Nội bộ | Sâu | 91/91 | 0/91 |
| OWASP Python | Sâu, trước thay đổi | 13/452 | 1/778 |
| OWASP Python | Sâu, sau thay đổi | 68/452 | 64/778 |
| OWASP Java | Sâu, phép đo đầu tiên | 240/1.415 | 180/1.325 |

Bốn rule Python mới kiểm tra chuyển hướng, đường dẫn file, thực thi mã động và XPath. Hai rule Java mới kiểm tra đường dẫn đọc file và phản hồi Servlet có MIME HTML. Python phát hiện thêm 55 mẫu lỗi trong OWASP, đồng thời phát sinh thêm 63 cảnh báo trên mẫu an toàn theo nhãn của bộ dữ liệu. Kết quả này phản ánh phạm vi mở rộng. Quét nhanh trên hai bộ OWASP và số cảnh báo trên các bộ mã sạch giữ nguyên so với phép đo trước.

Benchmark quét sâu chia các bộ OWASP lớn thành lô 450 tệp. Nếu một lô chưa được quét đầy đủ, lệnh báo lỗi thay vì tính các tệp chưa quét là kết quả âm tính. GitHub Actions so sánh cả hai bộ OWASP với mốc đã đo. Mốc quét nhanh nội bộ đổi từ 27/85 thành 28/91 vì bộ mẫu có thêm sáu cặp.

## Giảm báo nhầm khi quét sâu Python (12/11/2026)

Đo trước và sau trên cùng commit OWASP Python `f1291485808b`, với Semgrep CE 1.184.0. Bảng đếm theo ca và chỉ tính phát hiện có CWE tương ứng với nhãn của ca.

| Rule | Phát hiện đúng trước và sau | Báo nhầm trước | Báo nhầm sau |
|---|---:|---:|---:|
| `srcaudit-python-request-file-path` | 22 | 20 | 7 |
| `srcaudit-python-lxml-xpath-injection` | 17 | 20 | 8 |
| `srcaudit-python-request-dynamic-code` | 9 | 15 | 9 |
| `srcaudit-python-flask-open-redirect` | 7 | 8 | 2 |
| `srcaudit-python-unsafe-deserialization` | 7 | 1 | 1 |
| `srcaudit-python-command-injection` | 5 | 0 | 0 |
| `srcaudit-python-sql-injection` | 1 | 0 | 0 |
| **Tổng** | **68** | **64** | **27** |

FPR giảm từ **8,23% xuống 3,47%** trên 778 ca an toàn. Precision tăng từ **51,52% lên 71,58%**. Recall đạt **15,04%** trên 452 ca có lỗi. Đạt mục tiêu tối đa 32 báo nhầm và ít nhất 68 phát hiện đúng.

Bộ quét đọc AST để xác minh giá trị hằng, điều kiện kiểm tra đường dẫn sau `.resolve()`, ngữ cảnh literal trong XPath và allowlist HTTPS của chuyển hướng Flask. Khi một thành phần trong f-string đường dẫn là hằng đã xác minh, SrcAudit thay đúng thành phần đó trong bản sao tạm và chạy lại Semgrep. Chỉ bỏ cảnh báo ở vị trí đã được kiểm tra lại và Semgrep không còn báo đường dẫn tại đó. Chi tiết nhận diện và giới hạn nằm trong [danh mục rule](../RULES.md#kiểm-tra-lại-cảnh-báo-python).

Quét sâu phát hiện đúng **8/8** ở bộ đối chứng và **3/3** ở bộ kiểm tra riêng, mỗi bộ có **0** báo nhầm theo CWE của cặp. Kết quả giữ **91/91** trên bộ nội bộ và **0** phát hiện trên Flask và Requests. Dùng OWASP Python để phân loại lỗi giúp cải thiện độ chính xác trên bộ này. Ba cặp kiểm tra riêng vẫn là mã tổng hợp, nên cần đo thêm trên dự án Python có nhãn để ước lượng hiệu quả ngoài benchmark.

```powershell
node scripts/benchmark.mjs --mode deep --suite owasp-python,python-precision,python-holdout,clean-py --check benchmarks/baseline.json --json python-benchmark.json
```

Tệp JSON của OWASP liệt kê từng ca báo nhầm trong `falsePositiveCases`, gồm tên ca, nhóm, CWE và các ID rule. Mục `stats.pythonPrecision` ghi số cảnh báo được lọc theo lý do.

## Bổ sung HTML, cookie và XML cho quét sâu Python

| Nhóm OWASP Python | Phát hiện đúng trước → sau | Báo nhầm sau |
|---|---:|---:|
| Cookie thiếu Secure (CWE-614) | 0 → 24/24 | 0/15 |
| XSS (CWE-79) | 0 → 11/31 | 0/58 |
| Thực thể ngoài trong XML (CWE-611) | 0 → 4/8 | 0/20 |

Trên toàn bộ 1.230 ca, số phát hiện đúng tăng từ **68 lên 107/452**, recall từ **15,04% lên 23,67%**. Số báo nhầm giữ ở **27/778** (3,47%) và số phát hiện trên bộ Flask và Requests giữ ở **0**. Baseline của CI ghi kết quả mới cho OWASP Python và bộ `python-coverage`.

Mười một cặp trong `python-coverage` kiểm tra cả vị trí báo và các bản đã sửa. Các mẫu bao gồm HTML đã escape, MIME văn bản, `secure=True`, parser khác, tắt lại thực thể ngoài và đầu vào đã trở thành hằng. Bước AST loại 9 cảnh báo trên các ca OWASP đã gắn nhãn an toàn trong ba nhóm. Một mẫu có cả phần cố định và phần lấy từ request vẫn được báo.

Phép đo trên cùng commit OWASP được dùng để chọn phạm vi rule. Kết quả trên ba nhóm chưa đại diện cho ứng dụng Python ngoài bộ mẫu. Tại mốc này, LDAP bỏ sót cả 16 ca có lỗi trong OWASP.

```powershell
npm run benchmark:semgrep
node scripts/benchmark.mjs --mode deep --suite owasp-python,python-coverage,clean-py --check benchmarks/baseline.json --json python-benchmark.json
```

## Mở rộng nhận diện kết nối LDAP trong Python

Rule CWE-90 nhận diện kết nối tạo bằng `ldap3.Connection()`, kể cả import có tên khác và khối `with`. Lời gọi `search()` trên biến do hàm khác trả về cũng được kiểm tra khi truyền hằng thuộc tính của ldap3. Báo cáo chỉ vị trí của bộ lọc. Bước AST loại cảnh báo khi xác minh được bộ lọc là hằng.

Trên 29 ca LDAP của OWASP Python, số phát hiện đúng tăng từ **0 lên 9/16**, với **0/13** ca an toàn bị báo nhầm theo CWE-90. Sáu cặp đối chứng mới kiểm tra các dạng kết nối, hàm escape, lời gọi LDAP lồng trong đối số và nhánh có giá trị hằng. Một số ca còn bỏ sót nhận dữ liệu qua hàm bọc request.

Trên toàn bộ 1.230 ca, số phát hiện đúng tăng từ **107 lên 116/452** và số báo nhầm là **27/778**. Recall đạt **25,66%** và FPR đạt **3,47%**. Bộ mã Flask và Requests có **0** phát hiện. Baseline CI ghi mốc mới cho `owasp-python` và 17 cặp trong `python-coverage`.

## Lọc cảnh báo nhầm

**AST cho JS/TS** ([src/ast-filter.mjs](../../src/ast-filter.mjs)) chỉ *loại bỏ* phát hiện của quét nhanh khi mọi lời gọi nhạy cảm trên dòng đều vô hại: đối số là hằng (literal, ghép hằng, `const` gán một lần), đã qua hàm làm sạch (`escapeHtml`, `Number`, `path.basename`…), hoặc dùng dạng không chèn được (`execFile`/`spawn` không qua shell, `res.sendFile` có `root` và không spread). File không parse được hoặc dòng không tìm thấy lời gọi thì giữ nguyên. Danh sách ở `report.filtered`, thống kê ở `stats.astFilter`. Tắt bằng tùy chọn `astFilter: false`.

**Ngữ cảnh** ([src/context.mjs](../../src/context.mjs)):

| Trường hợp | Xử lý |
|---|---|
| Secret là tham chiếu (`${VAR}`, `{{ }}`, `<your-key>`, `process.env`) | Loại |
| `hashlib.*(..., usedforsecurity=False)` | Loại |
| Docstring Python, `platform.system()` | Không còn khớp quy tắc |
| Secret giống giá trị mẫu (`changeme`, `xxxx`, `development key`, entropy < 2 bit/ký tự) | Hạ xuống `info`, `context: placeholder` |
| File test / example / bundle `.min.js` | Hạ một mức, `confidence: low`, `context: test|example|generated`; secret giữ nguyên mức |
| `DEBUG = True` trong file `*.dev.*`, `*.local.*`, `.env.development` | Hạ xuống `info` |

Từ chối có chủ đích: không dùng checksum CRC32 của token GitHub để hạ mức token, vì chưa có token thật để xác minh thuật toán; cài sai sẽ hạ mức token thật.

## Khi thay đổi quy tắc

1. Chạy `npm run benchmark:check`. CI cũng chạy bước này (job *Accuracy benchmark*, và bước *Accuracy check (deep mode)* trong job Semgrep).
2. Nếu chỉ số tốt lên, cập nhật baseline bằng `--update-baseline` và ghi lại trong bảng trên.
3. Không hạ baseline để CI qua; hồi quy cần được giải thích trong PR.
