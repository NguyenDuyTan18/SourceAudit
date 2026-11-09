# Danh mục quy tắc SourceAudit

Tài liệu này liệt kê chi tiết các quy tắc của hai chế độ phân tích. Xem [README](../README.md) để cài đặt và sử dụng.

- [Phân tích sâu bằng Semgrep (47 quy tắc)](#phân-tích-sâu-bằng-semgrep)
- [Quét nhanh (82 quy tắc)](#quét-nhanh)

## Phân tích sâu bằng Semgrep

### Luồng hoạt động của quét sâu

1. **Nhận và chọn file.** Trình duyệt gửi ZIP đã chọn hoặc tự nén các file mã nguồn trong thư mục được chọn. Máy chủ giải nén trong thư mục tạm và chỉ quét nội dung tải lên. CLI nhận đường dẫn cục bộ qua `--src … --deep`. Báo cáo giữ đường dẫn tương đối. [Điểm vào CLI](../scan.mjs) · [Điểm vào giao diện](../src/ui-server.mjs) · [Bộ giải nén](../src/uploads.mjs)
2. **Chạy Semgrep CE trên bản sao tạm.** Ứng dụng đổi tên bản sao theo số và lưu bảng ánh xạ về file gốc. Workflow và Dockerfile được đặt vào các đường dẫn do ứng dụng tạo để Semgrep nhận diện đúng loại tệp. Lệnh `semgrep scan` nạp ba file YAML cục bộ, tắt gửi số liệu sử dụng và lấy kết quả JSON. Ứng dụng dọn thư mục tạm sau lượt quét. [Bộ chạy Semgrep](../src/semgrep.mjs)
3. **Phân tích luồng hoặc so khớp mẫu.** `pattern-sources` nhận diện đầu vào như `req.query` hoặc `request.args`. Semgrep theo dõi giá trị qua biến và biểu thức để tìm `pattern-sinks`, tức đối số nhạy cảm như URL, câu SQL hoặc đường dẫn. `pattern-sanitizers` mô tả biện pháp bảo vệ đã nhận diện. Rule cấu hình so khớp trực tiếp khối YAML hoặc chỉ thị Dockerfile. Báo cáo phân biệt hai phương pháp bằng `semgrep-taint` và `semgrep-pattern`. [Tài liệu Semgrep về phân tích luồng](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview)
4. **Đổi kết quả engine thành phát hiện.** Ứng dụng nhận các ID rule đã đăng ký, đối chiếu với file được engine ghi nhận đã quét, loại kết quả trùng và khôi phục `file:dòng:cột`. Bảng metadata theo ID cung cấp tiêu đề, CWE, mức độ và hướng sửa. Số file do ứng dụng chọn và số file Semgrep đã quét được thống kê riêng theo ngôn ngữ. [Bộ chuyển đổi kết quả](../src/semgrep.mjs)
5. **Gắn tài liệu kiểm chứng và xuất báo cáo.** Sau khi có phát hiện, UI và CLI bổ sung ngữ cảnh theo CWE, ví dụ mô tả điểm yếu, liên kết OWASP và write-up đã nhập có chủ đề phù hợp. Kết quả được xuất ra JSON, HTML và TXT. [Bổ sung ngữ cảnh](../src/knowledge.mjs) · [Xuất báo cáo](../src/report.mjs)

Ví dụ, quy tắc `sentry-python-requests-ssrf` theo dõi `request.args["url"]` qua biến `target` đến đối số URL của `requests.get(target)`. Phát hiện CWE-918 trỏ vào `target`. Bản đối chứng dùng URL cố định và đưa dữ liệu từ request vào `params=` để kiểm tra quy tắc chỉ đánh dấu đích gửi yêu cầu. [Cặp mã mẫu](../scripts/semgrep-multilang-cases.mjs) · [Tài liệu Requests](https://docs.python-requests.org/en/latest/api/)

### Quy tắc lấy từ đâu?

| Thành phần | Nguồn và vai trò |
|---|---|
| Quy tắc Semgrep | SourceAudit tự viết các rule YAML dựa trên tài liệu chính thức của từng API và dùng CWE để phân loại. [JS/TS](../rules/semgrep-js-ts.yml) · [Đa ngôn ngữ](../rules/semgrep-multilang.yml) · [Framework và cấu hình](../rules/semgrep-framework-config.yml) · [Danh mục CWE](https://cwe.mitre.org/) |
| Metadata của phát hiện | ID `sentry-…` trong YAML được ánh xạ sang tiêu đề tiếng Việt, CWE, mức độ và cách sửa. Liên kết CWE trong báo cáo được dựng từ mã này. [Bảng metadata](../src/semgrep.mjs) |
| Quy tắc quét nhanh | Các mẫu chữ ký, quy tắc theo kịch bản và phân tích luồng văn bản nằm trong mã nguồn dự án. Quét nhanh đối chiếu dependency npm hoặc pip với snapshot advisory. CLI có tùy chọn bổ sung rule JSON. [Quét nhanh](../src/source.mjs) · [Chữ ký mở rộng](../src/extended-rules.mjs) · [Quy tắc theo kịch bản](../src/scenario-rules.mjs) · [Luồng văn bản](../src/flow.mjs) |
| Dữ liệu tra cứu và write-up | CWE, OWASP WSTG, ASVS, API Security, GitHub Advisory Database và CISA KEV được ghi nguồn trong manifest của kho dữ liệu. Write-up nhập qua ứng dụng cung cấp chủ đề và URL liên quan cho báo cáo. Ở chế độ quét sâu, YAML quyết định cách phát hiện và dữ liệu tra cứu bổ sung ngữ cảnh sau đó. [Nguồn và giấy phép](../data/README.md) · [Manifest gốc](../data/manifest.json) · [Manifest mở rộng](../data/extensions-manifest.json) |

Khi thêm rule quét sâu, chọn API cần kiểm tra và CWE tương ứng, khai báo mẫu trong YAML phù hợp, rồi đăng ký cùng ID trong `src/semgrep.mjs`. Thêm một cặp mã có lỗi và đã sửa, kiểm tra vị trí đối số được báo và chạy `npm run benchmark:semgrep`. Liên kết tài liệu API của các rule mới được ghi trong bảng bên dưới.

### Các nhóm lỗi theo ngôn ngữ

Bộ quét dùng **47 quy tắc cục bộ**. Có 45 quy tắc cho 8 ngôn ngữ lập trình và 2 quy tắc cho tệp cấu hình. Có thể quét một ZIP chứa nhiều ngôn ngữ và cả cấu hình trong cùng lượt.

| Ngôn ngữ | Nguồn đầu vào mẫu | Điểm nhạy cảm và nhóm lỗi |
|---|---|---|
| Python (`.py`) | `request.args`, `request.POST`, `request.get_data()` | SQL injection qua `cursor.execute()` (CWE-89); command injection qua `os.system()` hoặc `subprocess` với `shell=True` (CWE-78); giải tuần tự qua `pickle.loads()` (CWE-502) |
| PHP (`.php`) | `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` | SQL injection qua PDO hoặc `mysqli_query()` (CWE-89); command injection qua `shell_exec()` (CWE-78); nạp file từ đường dẫn do request điều khiển qua `include` hoặc `require` (CWE-98) |
| Java (`.java`) | Servlet `request.getParameter()`, `request.getInputStream()` | SQL injection qua JDBC (CWE-89); command injection qua `Runtime.exec()` và một số lời gọi shell bằng `ProcessBuilder` (CWE-78); đầu vào không tin cậy vào `ObjectInputStream` (CWE-502, kiểm tra thêm điểm đọc object) |
| Go (`.go`) | `r.FormValue()`, `r.URL.Query().Get()` | SQL injection qua `database/sql` (CWE-89); dữ liệu điều khiển executable hoặc lệnh shell qua `exec.Command()` (CWE-78); SSRF qua `net/http` (CWE-918, kiểm tra thêm yêu cầu có thực sự được gửi) |
| C# (`.cs`) | ASP.NET Core `Request.Query`, `Request.Form`, `Request.Headers` | SQL injection qua `SqlCommand` hoặc `FromSqlRaw()` (CWE-89); path traversal qua `File.ReadAllText()` (CWE-22); chuyển hướng mở qua `Redirect()` (CWE-601) |

| Quy tắc bổ sung | Phạm vi |
|---|---|
| LDAP injection trong Python (CWE-90) | Bộ lọc truyền vào `ldap_conn.search()` theo vị trí hoặc qua `search_filter=`. Dùng `escape_filter_chars()` cho giá trị trước khi ghép vào cấu trúc bộ lọc cố định. [Tài liệu ldap3](https://ldap3.readthedocs.io/en/latest/searches.html) |
| Giải tuần tự không an toàn trong PHP (CWE-502) | Dữ liệu đi vào `unserialize()`, kể cả khi đặt `allowed_classes` thành `false`. Dùng JSON và kiểm tra cấu trúc dữ liệu. [Tài liệu PHP](https://www.php.net/unserialize) |
| XPath injection trong Java (CWE-643) | Biểu thức trong `XPath.evaluate()`, `evaluateExpression()` và `compile()` khi Semgrep nhận diện được kiểu JAXP. Giữ biểu thức cố định và dùng `XPathVariableResolver` để truyền giá trị. [Tài liệu JAXP](https://docs.oracle.com/en/java/javase/11/docs/api/java.xml/javax/xml/xpath/XPath.html) |
| Chèn nội dung vào log trong Go (CWE-117) | Đối số của `log.Print()`, `log.Println()` và chuỗi định dạng của `log.Printf()`. Mã hóa ký tự điều khiển bằng `strconv.Quote()` hoặc dùng trường dữ liệu trong logger có cấu trúc. [Tài liệu Go về strconv](https://pkg.go.dev/strconv#Quote) |
| SSRF trong C# (CWE-918) | URL trong một số lời gọi như `GetAsync()`, `GetStringAsync()` và `PostAsync()` trên biến tên `httpClient`, `_httpClient` hoặc `client`. Kiểm chứng đích mạng và việc xử lý chuyển hướng. [Tài liệu HttpClient](https://learn.microsoft.com/en-us/dotnet/framework/network-programming/how-to-request-data-using-the-webrequest-class) |
| Chèn mã template trong Flask (CWE-1336) | Mã template vào `render_template_string()` qua đối số đầu tiên hoặc `source=`. Mẫu đã sửa giữ template cố định và truyền dữ liệu qua biến ngữ cảnh. [Tài liệu Flask](https://flask.palletsprojects.com/en/stable/api/#flask.render_template_string) |
| SSRF trong PHP (CWE-918) | URL đưa vào `curl_init()` hoặc `curl_setopt()` với `CURLOPT_URL`. Kiểm tra lại URL tại thời điểm handle được dùng để gửi yêu cầu. [Tài liệu cURL cho PHP](https://www.php.net/manual/en/function.curl-setopt.php) |
| Path traversal trong Go (CWE-22) | Đường dẫn đưa vào `os.ReadFile()` hoặc `os.Open()`. Mẫu đã sửa ánh xạ tên do request chọn sang đường dẫn cố định. [Tài liệu Go về os](https://pkg.go.dev/os#ReadFile) |
| Chọn chương trình từ request trong C# (CWE-78) | Tên chương trình trong `Process.Start(fileName, arguments)`, constructor `ProcessStartInfo` và thuộc tính `FileName` trong khối khởi tạo. Với `ProcessStartInfo`, kiểm tra cấu hình thực tế tại thời điểm khởi chạy. [Tài liệu .NET về Process.Start](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.start) |
| SSRF qua Python Requests (CWE-918) | URL truyền theo vị trí hoặc qua `url=` trong `requests.get()`, `post()` và `request()`. [Tài liệu Requests](https://docs.python-requests.org/en/latest/api/) · [CWE-918](https://cwe.mitre.org/data/definitions/918.html) |
| Chuyển hướng mở trong PHP (CWE-601) | Đích nối trực tiếp với tiền tố `Location:` trong `header()`. [Tài liệu PHP về header](https://www.php.net/manual/en/function.header.php) · [CWE-601](https://cwe.mitre.org/data/definitions/601.html) |
| SSRF trong Java (CWE-918) | URI trong `HttpRequest.newBuilder(uri)` và đầu vào trong `URI.create(url).toURL().openStream()`. Với builder, kiểm chứng request được gửi và đích tại thời điểm gửi. [Tài liệu HttpRequest](https://docs.oracle.com/en/java/javase/21/docs/api/java.net.http/java/net/http/HttpRequest.html) · [Tài liệu URL.openStream](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/URL.html#openStream()) |

JavaScript và TypeScript (`.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`) có các quy tắc sau:

| CWE | Nhóm | Ví dụ vị trí rule kiểm tra |
|---|---|---|
| CWE-89 | SQL injection | Đối số câu SQL của `db.query()`, `pool.query({ text })` và API SQL đã định nghĩa |
| CWE-78 | Command injection | `exec()`, `execSync()` và một số dạng `spawn()` hoặc `execFile()` có `shell: true` |
| CWE-918 | SSRF | Đích của `fetch()`, Axios và HTTP client đã định nghĩa |
| CWE-22 | Path traversal | Tên file hoặc `root` của `res.sendFile()` và `res.download()` |
| CWE-22 | Ghi file theo đường dẫn do request điều khiển | Đối số đường dẫn của `fs.writeFile()`, `fs.writeFileSync()` và dạng promises với các mẫu import đã định nghĩa. [Tài liệu Node.js về fs](https://nodejs.org/api/fs.html) |
| CWE-79 | XSS | Phản hồi HTML của Express, `innerHTML` và `insertAdjacentHTML()` |
| CWE-601 | Chuyển hướng mở | Đích trong `res.redirect()` |
| CWE-943 | NoSQL injection | Filter của `findOne()` và các API tương tự, pipeline của `aggregate()` |
| CWE-1321 | Prototype pollution | Object nguồn đi vào merge sâu hoặc khóa đi vào `lodash.set()` |
| CWE-1336 | Chèn mẫu phía máy chủ | Mã mẫu đưa vào `ejs.render()`, `handlebars.compile()` và API biên dịch mẫu đã định nghĩa |
| CWE-95 | Thực thi mã động | `eval()`, `Function()` và API `vm` đã định nghĩa |
| CWE-502 | Giải tuần tự không an toàn | Dữ liệu vào `unserialize()` của `node-serialize` |
| CWE-915 | Gán hàng loạt thuộc tính | Payload đi vào `User.create()`, `updateOne()`, `findByIdAndUpdate()` và API model đã định nghĩa |
| CWE-470 | Nạp module theo dữ liệu request | Tên hoặc đường dẫn module trong `require()` và `import()` |

Các rule nhận dữ liệu từ query, body, params, header và cookie của biến request theo mẫu đã định nghĩa. Rule SQL cũng nhận tham số request đổi tên trong callback đăng ký trực tiếp với Express hoặc Router được khởi tạo theo các mẫu hỗ trợ. Quy tắc model theo dõi payload qua biến, object spread và một số dạng khóa tính trực tiếp từ request. Mẫu DTO với trường cố định và giá trị scalar được dùng làm đối chứng. Cần kiểm tra quyền ghi các trường nhạy cảm trong ứng dụng thực tế. [OWASP Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)

### Kiểm tra theo framework và cấu hình

| Tệp hoặc thư viện | Phát hiện | Đối chứng và nguồn |
|---|---|---|
| GitHub Actions (`.github/workflows/*.yml` hoặc `*.yaml`) | CWE-78 khi một số biểu thức sự kiện do người dùng điều khiển, như tiêu đề PR hoặc `github.head_ref`, được chèn trực tiếp vào khối `run:`. Báo cáo giữ vị trí đầu và cuối của khối nhiều dòng. | Truyền qua `env:` và trích dẫn biến trong shell. [GitHub Docs](https://docs.github.com/en/actions/concepts/security/script-injections) |
| `Dockerfile` | CWE-250 khi `USER` cuối của stage cuối là `root` hoặc `0`, hoặc stage cuối dùng `scratch`, `alpine` hay `busybox` theo các mẫu tên hỗ trợ mà thiếu `USER`. | Đặt user không phải root ở stage cuối. Kiểm tra user thực tế và cấu hình override khi chạy. [Dockerfile reference](https://docs.docker.com/reference/dockerfile/#user) |
| Node.js `jsonwebtoken` | CWE-321 khi `verify()` dùng chuỗi khóa viết cứng và `algorithms` chỉ định một thuật toán HS256, HS384 hoặc HS512. | Nạp khóa từ secret manager. Báo cáo che literal khóa. [API jsonwebtoken](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback) |
| Spring JDBC | CWE-89 khi tham số `@RequestParam` đi vào đối số SQL của một số phương thức `JdbcTemplate`, như `queryForObject()` hoặc `update()`. | Dùng SQL cố định với placeholder và đối số bind riêng. [API JdbcTemplate](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/jdbc/core/JdbcTemplate.html) |
| Laravel | CWE-89 khi giá trị từ `->input()` hoặc `->query()` đi vào đối số SQL của `DB::select()`, `selectOne()`, `statement()` hoặc `unprepared()`. Mẫu dùng tên facade `DB`. | Bind giá trị riêng với các API hỗ trợ binding. [Laravel Database](https://laravel.com/docs/12.x/database#running-a-select-query) |
| Ruby on Rails | CWE-918 khi `params[...]` hoặc `params.fetch(...)` trong controller kế thừa `ApplicationController` điều khiển đích của `Net::HTTP.get()` hoặc `get_response()`. | Ánh xạ lựa chọn sang URL cố định. [Rails Controller](https://guides.rubyonrails.org/action_controller_overview.html#parameters) · [Ruby Net::HTTP](https://docs.ruby-lang.org/en/master/Net/HTTP.html) |

### Phạm vi và cách kiểm chứng

Semgrep CE phân tích luồng trong từng hàm. Một số mẫu dựa trên tên biến như `req`, `request`, `db` và `stmt`. Dữ liệu qua nhiều hàm, API ngoài mẫu, kiểm tra đầu vào tự viết và điều kiện phân quyền cần xem xét riêng. Rule Dockerfile kiểm tra các chỉ thị viết trên một dòng và dùng tên base image để nhận diện một số mặc định. Lượt quét mặc định giới hạn 2.000 file, 1 MiB mỗi file, 20 MiB mã nguồn đã chọn và 90 giây cho Semgrep. Xem số **đã phân tích / đã chọn** theo ngôn ngữ hoặc loại cấu hình và thông báo lỗi để biết phần nào chưa được kiểm tra. JSON lưu thống kê này trong `stats.sourceAnalysis.languages`. [Phạm vi phân tích luồng của Semgrep](https://semgrep.dev/docs/writing-rules/glossary)

Dùng quét nhanh để rà soát manifest dependency, secret và chữ ký cấu hình như TLS, cookie hoặc debug. Với cảnh báo Semgrep, kiểm tra nguồn dữ liệu, cách bảo vệ và việc API thực sự được gọi trong môi trường triển khai trước khi xác nhận lỗ hổng.

```powershell
npm run benchmark:semgrep
npm run test:coverage
```

Benchmark đo 85 cặp mã mẫu theo CWE tương ứng. Quét sâu phát hiện 85/85 mẫu có lỗi và cảnh báo 0/85 mẫu đã sửa. Quét nhanh lần lượt là 27/85 và 9/85. Trong 8 cặp mới, quét sâu phát hiện cả 8 mẫu lỗi, gồm 6 mẫu quét nhanh bỏ sót. Số đo áp dụng cho bộ mẫu này. [Kết quả benchmark](testing/semgrep.tdd.md)

## Quét nhanh

Các quy tắc tích hợp nằm trong bốn nhóm mã dưới đây. Mỗi dòng ghi ID xuất hiện trong báo cáo, CWE dùng để phân loại và ngữ cảnh cần đối chiếu. Chữ ký tìm mẫu ngay trên dòng mã hoặc cấu hình. Cùng một CWE có thể có nhiều quy tắc vì API và dấu hiệu khác nhau theo ngôn ngữ.

- `SRC-*` gồm 16 chữ ký nền, `EXT-*` gồm 48 chữ ký theo ngôn ngữ hoặc cấu hình, và `SC-*` gồm 12 chữ ký theo kịch bản. Quy tắc `SC-*` có ID ASVS trong bảng sẽ gắn yêu cầu tương ứng vào báo cáo.
- `FLOW-*` gồm 6 phép theo dõi biến bằng văn bản trên JS/TS, Python và PHP. Chúng theo dõi phép gán và biến trung gian, giữ tối đa 50 biến, hết hạn sau 12 dòng kể từ lần gán gần nhất và cung cấp các dòng cần kiểm chứng. Semgrep dùng bộ phân tích cú pháp riêng cho quét sâu.
- Chạy `node scan.mjs --list-rules` để xem danh sách tích hợp theo mã đang chạy. Rule JSON người dùng chọn và kết quả đối chiếu advisory được tính riêng.

Ví dụ, khi gặp `Sequelize.literal(req.query.sort)`, chữ ký `SC-JS-SQL-LITERAL` đánh dấu dòng gọi API và phân loại **CWE-89**. Báo cáo gắn thêm yêu cầu **ASVS-v5.0.0-1.2.4** để đối chiếu cách tạo truy vấn. Người rà soát cần xem `sort` có được ánh xạ sang danh sách cột cố định trước khi vào phần SQL hay không. Trong JSON, xem `ruleId`, `location`, `knowledge.cweContext` và `knowledge.verificationRequirements`. [Mã quy tắc](../src/scenario-rules.mjs) · [Mẫu kiểm thử](../test/more-scenarios.test.mjs)

<details>
<summary>16 chữ ký nền (SRC)</summary>

Mã định nghĩa nằm trong [src/source.mjs](../src/source.mjs).

| Mã rule | Phân loại | Dấu hiệu và ngữ cảnh cần kiểm chứng |
|---|---|---|
| `SRC-SSRF` | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | HTTP client như `fetch`, Axios hoặc Requests nhận biểu thức từ request trên dòng gọi. Kiểm tra đích, DNS và redirect. |
| `SRC-PATH` | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | API như `readFile`, `sendFile` hoặc `file_get_contents` nhận đầu vào. Kiểm tra thư mục gốc, chuẩn hóa và symlink. |
| `SRC-SSTI` | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | API biên dịch template như `render_template_string` nhận biểu thức request. Kiểm tra đầu vào là mã template hay dữ liệu hiển thị. |
| `SRC-PROTOTYPE` | [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) | Merge body hoặc gán khóa object từ request. Kiểm tra hàm merge, khóa động và schema. |
| `SRC-XXE` | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | Cấu hình như `resolve_entities=True`, `LIBXML_NOENT` hoặc `XmlUrlResolver`. Kiểm tra nguồn XML, DTD và quyền mạng/file. |
| `SRC-JWT` | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | Cấu hình JWT tắt xác minh chữ ký. Kiểm tra token có được dùng để xác thực hoặc phân quyền. |
| `SRC-EVAL` | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | Các lời gọi `eval` và một số lời gọi `exec` trong mã được hỗ trợ. Kiểm tra chuỗi thực thi đến từ đâu. |
| `SRC-SHELL` | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | API gọi lệnh hoặc cấu hình `shell=True`. Kiểm tra executable, đối số và dữ liệu đầu vào. |
| `SRC-SQL` | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | Dấu hiệu ghép chuỗi câu SQL hoặc dùng f-string tại `execute/query`. Kiểm tra phần câu lệnh và parameter binding. |
| `SRC-XSS` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Điểm xuất HTML như `innerHTML`, `document.write` hoặc phản hồi có request. Kiểm tra vị trí chèn và encoding theo ngữ cảnh. |
| `SRC-DESERIALIZE` | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | Lời gọi `pickle.load(s)`, `unserialize` hoặc một số dạng `yaml.load`. Kiểm tra nguồn dữ liệu và loader. |
| `SRC-TLS-VERIFY` | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | Tùy chọn tắt xác minh chứng chỉ trong Node, Python hoặc cURL. Kiểm tra cấu hình được dùng lúc kết nối. |
| `SRC-DEBUG` | [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | Cờ debug bật. Kiểm tra môi trường triển khai và chi tiết có thể lộ. |
| `SRC-HASH` | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | MD5 hoặc SHA-1. Kiểm tra mục đích bảo mật của giá trị hash. |
| `SRC-SECRET` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Literal, biến cấu hình hoặc token có dạng credential. Xác minh trên máy và kiểm tra giá trị còn hiệu lực. |
| `SRC-PRIVATE-KEY` | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Dấu đầu PEM của private key. Xác minh key thuộc fixture hay môi trường đang dùng. |

</details>

<details>
<summary>48 chữ ký mở rộng (EXT)</summary>

Mã định nghĩa nằm trong [src/extended-rules.mjs](../src/extended-rules.mjs).

| Mã rule | Phân loại | Dấu hiệu và ngữ cảnh cần kiểm chứng |
|---|---|---|
| `EXT-JS-REDIRECT` | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | Express `res.redirect` nhận đích từ query, body hoặc params. Kiểm tra allowlist đích. |
| `EXT-PY-REDIRECT` | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | `HttpResponseRedirect` hoặc `redirect` nhận đầu vào request. Kiểm tra URL nội bộ và ngoại lệ. |
| `EXT-PHP-REDIRECT` | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | `header` tạo `Location` từ superglobal. Kiểm tra đích trình duyệt thực sự nhận. |
| `EXT-JAVA-REDIRECT` | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | `sendRedirect` nhận tham số request. Kiểm tra kiểm soát origin. |
| `EXT-CS-REDIRECT` | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | ASP.NET `Redirect` lấy URL từ `Request.Query` hoặc `Request.Form`. Kiểm tra đích có giới hạn nội bộ. |
| `EXT-JS-NOSQL` | [CWE-943](https://cwe.mitre.org/data/definitions/943.html) | `find`, `findOne` hoặc `aggregate` nhận trực tiếp object request. Kiểm tra kiểu và toán tử truy vấn. |
| `EXT-JS-MASS` | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) | Model JS nhận nguyên `req.body` khi ghi. Kiểm tra danh sách field và quyền ghi. |
| `EXT-JS-VM` | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | `vm.runInContext` và API tương tự dùng dữ liệu request. Kiểm tra chuỗi chạy và quyền ngữ cảnh. |
| `EXT-JS-TEMPLATE` | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | Handlebars hoặc Pug nhận request khi compile hoặc render. Kiểm tra mã template được kiểm soát thế nào. |
| `EXT-JS-COOKIE-HTTPONLY` | [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html) | Cấu hình cookie hoặc session đặt `httpOnly:false`. Kiểm tra cookie có mang thông tin xác thực. |
| `EXT-JS-COOKIE-SECURE` | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | Cấu hình cookie hoặc session đặt `secure:false`. Kiểm tra môi trường HTTPS. |
| `EXT-JS-WEAK-RANDOM` | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | `Math.random` dùng trên dòng tạo token, mật khẩu, secret, nonce hoặc session ID. Kiểm tra yêu cầu entropy. |
| `EXT-JS-JWT-KEY` | [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | `jwt.sign` dùng key literal. Xác minh key thực tế và nơi lưu. |
| `EXT-JS-REGEX` | [CWE-1333](https://cwe.mitre.org/data/definitions/1333.html) | `new RegExp` nhận tham số request. Kiểm tra cấu trúc, kích thước đầu vào và cách regex được dùng. |
| `EXT-VUE-HTML` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Điểm xuất HTML `v-html` trong Vue hoặc HTML. Kiểm tra dữ liệu và sanitizer. |
| `EXT-SVELTE-HTML` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Điểm xuất HTML `@html` trong Svelte. Kiểm tra dữ liệu và sanitizer. |
| `EXT-ANGULAR-TRUST` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Lời gọi `bypassSecurityTrust*`. Kiểm tra giá trị được đánh dấu tin cậy đến từ đâu. |
| `EXT-PY-CSRF` | [CWE-352](https://cwe.mitre.org/data/definitions/352.html) | Django dùng `@csrf_exempt`. Kiểm tra thao tác thay đổi trạng thái và kiểu xác thực. |
| `EXT-PY-AUTOESCAPE` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Template Python đặt `autoescape=False`. Kiểm tra nội dung động và ngữ cảnh đầu ra. |
| `EXT-PY-MARKSAFE` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Django `mark_safe` nhận biểu thức request. Kiểm tra dữ liệu đã được xử lý. |
| `EXT-PY-TEMP` | [CWE-377](https://cwe.mitre.org/data/definitions/377.html) | `tempfile.mktemp` chọn tên file tạm. Kiểm tra thời điểm và cách tạo file. |
| `EXT-PY-TAR` | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | `extractall` chưa ghi `filter=` rõ ràng trên dòng gọi. Kiểm tra phiên bản Python, filter mặc định và nguồn archive. |
| `EXT-PY-POPEN` | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | `os.popen` nhận đầu vào request. Kiểm tra phần lệnh và quyền tiến trình. |
| `EXT-PY-HOSTS` | [CWE-346](https://cwe.mitre.org/data/definitions/346.html) | Django `ALLOWED_HOSTS` chứa wildcard. Kiểm tra proxy và nơi dùng header Host. |
| `EXT-PY-COOKIE` | [CWE-614](https://cwe.mitre.org/data/definitions/614.html) | Django tắt cờ Secure của cookie session hoặc CSRF. Kiểm tra cấu hình production. |
| `EXT-PHP-INCLUDE` | [CWE-98](https://cwe.mitre.org/data/definitions/98.html) | `include` hoặc `require` lấy đường dẫn từ superglobal. Kiểm tra file được phép nạp. |
| `EXT-PHP-DISPLAY` | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | PHP bật `display_errors`. Kiểm tra lỗi có lộ trong phản hồi triển khai. |
| `EXT-PHP-EXTRACT` | [CWE-473](https://cwe.mitre.org/data/definitions/473.html) | `extract` nhận superglobal. Kiểm tra khả năng ghi đè biến ứng dụng. |
| `EXT-PHP-ASSERT` | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | `assert` nhận dữ liệu request. Kiểm tra hành vi của phiên bản PHP triển khai. |
| `EXT-JAVA-EXEC` | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | `Runtime.exec` nhận dữ liệu request. Kiểm tra executable và cách xử lý đối số. |
| `EXT-JAVA-SQL` | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | `executeQuery` hoặc `executeUpdate` nhận biểu thức request. Kiểm tra câu SQL và tham số. |
| `EXT-JAVA-DESER` | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | `ObjectInputStream` nhận đầu vào request. Kiểm tra điểm đọc object và cấu hình bộ lọc. |
| `EXT-JAVA-XXE` | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) | Java XML parser bật external entities. Kiểm tra nguồn XML và các tùy chọn DTD. |
| `EXT-JAVA-TRUST` | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | `checkServerTrusted` có thân rỗng. Kiểm tra trust manager có được dùng khi kết nối. |
| `EXT-CS-PATH` | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | ASP.NET đưa request vào `File.ReadAllText`, `ReadAllBytes` hoặc `OpenRead`. Kiểm tra đích file. |
| `EXT-CS-HTML` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | `Html.Raw` nhận biểu thức request. Kiểm tra HTML được trả về. |
| `EXT-CS-DESER` | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | `Deserialize` đọc body hoặc input stream của request. Kiểm tra thư viện, kiểu và cài đặt deserialize. |
| `EXT-CS-TLS` | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | `ServerCertificateValidationCallback` trả `true`. Kiểm tra phạm vi áp dụng. |
| `EXT-GO-TLS` | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | Go đặt `InsecureSkipVerify:true`. Kiểm tra cấu hình và xác minh thay thế nếu có. |
| `EXT-GO-SHELL` | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | Go gọi `exec.Command` với `sh/bash -c` và dữ liệu request. Kiểm tra nội dung lệnh. |
| `EXT-GO-SQL` | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | API SQL nhận câu lệnh dựng bằng `fmt.Sprintf`. Kiểm tra dữ liệu nội suy. |
| `EXT-RUBY-HTML` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | Ruby đánh dấu `params` là `html_safe`. Kiểm tra ngữ cảnh xuất HTML. |
| `EXT-RUBY-DESER` | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | `Marshal.load` nhận `params`. Kiểm tra khả năng tạo đối tượng từ dữ liệu ngoài. |
| `EXT-RUBY-MASS` | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) | `params.permit!` cho phép mọi trường. Kiểm tra các thao tác ghi model. |
| `EXT-CONFIG-PRIVILEGED` | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) | YAML đặt `privileged:true`. Kiểm tra container có cần các quyền đó. |
| `EXT-CONFIG-PERMISSIONS` | [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | `chmod` đặt quyền `0777`. Kiểm tra ai có thể ghi file hoặc thư mục. |
| `EXT-CONFIG-ECB` | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | Cấu hình mã hóa ECB trong Python, Node hoặc Java. Kiểm tra thuật toán dùng thực tế. |
| `EXT-CONFIG-DIRECTORY` | [CWE-548](https://cwe.mitre.org/data/definitions/548.html) | ASP.NET config bật `directoryBrowse`. Kiểm tra thư mục và dữ liệu được liệt kê. |

</details>

<details>
<summary>12 chữ ký theo kịch bản (SC)</summary>

Mã định nghĩa nằm trong [src/scenario-rules.mjs](../src/scenario-rules.mjs).

| Mã rule | Phân loại | Dấu hiệu và ngữ cảnh cần kiểm chứng |
|---|---|---|
| `SC-JS-INSERT-HTML` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | `insertAdjacentHTML` nhận request hoặc đầu vào từ URL. Kiểm chứng theo `ASVS-v5.0.0-1.2.1`. |
| `SC-JS-FRAGMENT` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | `createContextualFragment` nhận request hoặc URL input. Kiểm chứng theo `ASVS-v5.0.0-1.2.1`. |
| `SC-JS-SQL-LITERAL` | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | `Sequelize.literal` nhận đầu vào request. Kiểm chứng theo `ASVS-v5.0.0-1.2.4`. |
| `SC-PHP-SQL-RAW` | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | Laravel `DB::raw` nhận trực tiếp dữ liệu request. Kiểm chứng theo `ASVS-v5.0.0-1.2.4`. |
| `SC-PY-SQL-RAW` | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | Django `raw` nhận SQL dạng f-string. Kiểm chứng theo `ASVS-v5.0.0-1.2.4`. |
| `SC-PHP-PRINT` | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | PHP `print` xuất trực tiếp superglobal. Kiểm chứng theo `ASVS-v5.0.0-1.2.1`. |
| `SC-PY-XPATH` | [CWE-643](https://cwe.mitre.org/data/definitions/643.html) | `xpath` nhận tham số request làm biểu thức. Kiểm tra việc bind giá trị. |
| `SC-JS-LDAP` | [CWE-90](https://cwe.mitre.org/data/definitions/90.html) | Bộ lọc `filter` của `search` nhận request. Kiểm tra cấu trúc bộ lọc và escape giá trị. |
| `SC-CS-TEMPLATE` | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | `Razor.Parse` nhận request làm mã template. Kiểm tra cách truyền model. |
| `SC-JAVA-SSRF` | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | `new URL` dựng từ `request.getParameter`. Kiểm tra URL có được truy xuất và đích có bị giới hạn. |
| `SC-GO-SSRF` | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | `http.Get/Post/Head` nhận `FormValue` hoặc query. Kiểm tra URL, DNS và redirect. |
| `SC-RUST-TLS` | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | `danger_accept_invalid_certs(true)`. Kiểm tra HTTP client nào dùng cấu hình. |

</details>

<details>
<summary>6 quy tắc theo dõi biến (FLOW)</summary>

Mã định nghĩa nằm trong [src/flow.mjs](../src/flow.mjs).

| Mã rule | Phân loại | Dấu hiệu và ngữ cảnh cần kiểm chứng |
|---|---|---|
| `FLOW-SQL` | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | Biến từ request đi vào đối số câu lệnh của API như `db.query` hoặc `cursor.execute`. |
| `FLOW-EVAL` | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | Biến từ request đi vào đối số `eval`. |
| `FLOW-SHELL` | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | Biến từ request đi vào đối số lệnh của API như `exec`, `os.system` hoặc `shell_exec`. |
| `FLOW-SSRF` | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | Biến từ request đi vào URL của `fetch`, `requests.get` hoặc `axios.get`. |
| `FLOW-PATH` | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | Biến từ request đi vào đường dẫn của `readFile`, `sendFile` hoặc `file_get_contents`. |
| `FLOW-REDIRECT` | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | Biến từ request đi vào `res.redirect` hoặc `HttpResponseRedirect`. |

</details>
