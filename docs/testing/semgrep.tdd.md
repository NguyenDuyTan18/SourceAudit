# Đối chứng chế độ quét sâu Semgrep

Yêu cầu xuất phát từ luồng người dùng chọn quét nhanh hoặc quét sâu trong tab Mã nguồn. Quét sâu nhận đường dẫn và upload qua cùng hàm quét, dùng Semgrep CE cục bộ với ba quy tắc JS/TS.

`node --test --test-name-pattern='deep source|missing Semgrep' test/ui.test.mjs` ban đầu thất bại ở cả hai ca. API chưa đưa trạng thái phân tích sâu vào báo cáo và lượt quét vẫn được đánh dấu hoàn tất khi bộ phân tích sâu thiếu. Hai ca đều đạt sau khi thêm chế độ. Kiểm thử upload cũng phát hiện cửa sổ trả kết quả trước khi dọn thư mục tạm. Công việc thành công chuyển sang trạng thái hoàn tất sau khi dọn thư mục.

## Kết quả trên mã mẫu

`npm run benchmark:semgrep` chạy cả hai chế độ với Semgrep CE 1.184.0 trên Windows. Mỗi ô gồm số mẫu có lỗi được phát hiện và số mẫu đã sửa vẫn bị cảnh báo theo CWE của cặp đó.

| Nhóm | Có lỗi / đã sửa | Quét nhanh phát hiện / báo nhầm | Quét sâu phát hiện / báo nhầm |
|---|---:|---:|---:|
| SQL injection | 2 / 2 | 1 / 0 | 2 / 0 |
| Command injection | 2 / 2 | 1 / 2 | 2 / 0 |
| SSRF | 2 / 2 | 1 / 2 | 2 / 0 |
| Tổng | 6 / 6 | 3 / 4 | 6 / 0 |

Ba mẫu bắt thêm dùng `pool.query({ text })`, `exec` nhập với bí danh và `axios.request({ url })`. Các mẫu đối chứng dùng truy vấn tham số hóa, lệnh cố định hoặc `execFile` với đối số riêng, và URL cố định có dữ liệu request trong header hoặc query params.

Đây là kết quả trên 12 file tổng hợp. Bộ mẫu kiểm tra các API đã chọn và khả năng phân biệt mã có lỗi với mã đã sửa. Semgrep CE ở chế độ này có phạm vi trong từng hàm. Kết quả vẫn cần đối chiếu với dữ liệu và cấu hình chạy thực tế.

## Kiểm chứng tích hợp

| Kiểm tra | Kết quả |
|---|---|
| `npm run test:coverage` | 94/94 đạt, không bỏ qua. Tổng độ phủ dòng 97,02%. Bộ chuyển đổi Semgrep đạt 100% dòng và 81,82% nhánh. |
| `node --check` | Đạt với bộ chuyển đổi, JavaScript giao diện, CLI và script benchmark. |
| Semgrep thật qua HTTP | Upload một file TS qua API loopback, nhận CWE-89 tại `src/route.ts` và tải báo cáo TXT có trạng thái Semgrep. |
| Semgrep thật qua CLI | `scan.mjs --src … --deep` cho kết quả CWE-89 trong báo cáo JSON và ghi nhận một file đã phân tích. |
| Phạm vi và dữ liệu đầu ra | Kiểm thử xác nhận loại bỏ kết quả ngoài danh sách file, lỗi engine hiện đúng trạng thái, đoạn mã thô không đi vào báo cáo và file tạm được dọn. |

Các lượt dùng Semgrep thật chạy trong môi trường Windows cho phép đọc Certificate Store. Bộ kiểm thử tự động dùng đầu ra engine mô phỏng cho lỗi và trường hợp biên. Dự án hiện không có Git checkout để ghi checkpoint.

Tự đánh giá 4,4/5. Độ chính xác 4/5 vì mẫu tổng hợp tập trung vào sáu cặp. Độ đầy đủ 4/5 vì đã chạy API và CLI thật, phần giao diện được kiểm tra cú pháp và HTML phục vụ. Độ rõ ràng 4/5 vì thống kê tách file đọc được khỏi file Semgrep đã quét. Khả năng sử dụng 5/5 nhờ có lựa chọn trong UI và lệnh chạy lại. Độ súc tích 5/5 vì tích hợp giữ chung luồng quét và định dạng báo cáo.

## Mở rộng từ mẫu Express và DOM có sẵn

Lượt quét sâu có thêm hai quy tắc CWE-22 và CWE-79. Benchmark xác nhận cả hai xuất hiện trên `examples/demo-src/app.js` và quy tắc CWE-79 xuất hiện trên `examples/research-demo/app.js`. Tệp mẫu được đọc tĩnh.

Đối chứng trước khi thêm rule báo 0/6 mẫu có lỗi mới. Sau khi thêm rule, kiểm tra riêng phát hiện trường hợp spread ghi đè `root` bị bỏ sót. Bộ quét chỉ công nhận một số dạng tùy chọn literal có `root` cố định. Đối chứng XSS xác nhận `escape-html` dùng cho toàn bộ phần thân HTML được phân biệt với trường hợp đưa giá trị đã escape vào ngữ cảnh JavaScript. [Tài liệu Express](https://expressjs.com/en/5x/api/response/) · [Phạm vi của escape-html](https://github.com/component/escape-html#escapehtmlstring)

Kết quả `npm run benchmark:semgrep` trên Semgrep CE 1.184.0:

| Nhóm | Cặp mẫu | Quét nhanh phát hiện / báo nhầm | Quét sâu phát hiện / báo nhầm |
|---|---:|---:|---:|
| Path traversal Express | 4 | 2 / 2 | 4 / 0 |
| XSS Express và DOM | 3 | 2 / 1 | 3 / 0 |
| Tổng gồm cả các nhóm trước | 13 | 7 / 7 | 13 / 0 |

`npm run test:coverage` đạt 94/94 với 97,03% độ phủ dòng. Số báo nhầm được tính theo mẫu đã sửa và CWE tương ứng. Các quy tắc tập trung vào biến request/response và điểm sử dụng đã định nghĩa trong JS/TS. Mã có cấu hình qua middleware, tên biến ngoài mẫu hoặc luồng qua nhiều hàm cần kiểm tra riêng.

Tự đánh giá 4,4/5. Độ chính xác và độ đầy đủ đạt 4/5 vì benchmark thật bao gồm cả ghi đè root và sai ngữ cảnh escape nhưng phạm vi mới được đo trên mẫu tổng hợp. Độ rõ ràng đạt 4/5 với số đo riêng theo nhóm. Khả năng sử dụng và độ súc tích đạt 5/5 vì dùng chung chế độ quét sâu và lệnh benchmark hiện có.

## Mở rộng luồng dữ liệu và điểm sử dụng JS/TS

Chế độ quét sâu có thêm CWE-601 cho `res.redirect()`, CWE-943 cho bộ lọc và pipeline NoSQL, CWE-1321 cho merge hoặc gán khóa động và CWE-1336 cho mã template. Các quy tắc nhận thêm dữ liệu từ header và cookie qua các biến request đã định nghĩa. Đối chứng quét lại `examples/demo-src/app.js` và `examples/research-demo/app.js`, xác nhận thêm chuyển hướng mở, prototype pollution và NoSQL injection tại các vị trí mẫu. [API request Express](https://expressjs.com/en/5x/api/request/) · [OWASP Prototype Pollution](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/22-Prototype_Pollution)

`npm run benchmark:semgrep` trước khi triển khai bỏ sót cả chín mẫu có lỗi mới. Lượt sau phát hiện đủ 22 mẫu. Hai mẫu NoSQL bổ sung tái hiện lỗi bỏ sót khi giá trị ép chuỗi được parse lại hoặc đưa vào `$where`. Sau khi giới hạn ngoại lệ ép kiểu vào giá trị trực tiếp của trường bộ lọc thông thường, benchmark đạt 24/24 mẫu có lỗi và 0/24 mẫu đã sửa bị cảnh báo theo CWE được đo. Quét nhanh phát hiện 9/24 và cảnh báo 8/24 mẫu đã sửa.

`npm run test:coverage` đạt 94/94, tổng độ phủ dòng 97,06%. Kiểm tra cú pháp giao diện và benchmark đều đạt. Phạm vi kiểm chứng gồm các API đã chọn, trong từng hàm, trên mã tổng hợp và hai file mẫu cục bộ.

Tự đánh giá 4,4/5. Độ chính xác và độ đầy đủ đạt 4/5 vì đã kiểm chứng hai ngữ cảnh ép kiểu và đọc lại mã mẫu, còn phạm vi qua nhiều hàm nằm ngoài bộ đo. Độ rõ ràng đạt 4/5 nhờ kết quả tách theo CWE và tác động riêng của từng quy tắc. Khả năng sử dụng và độ súc tích đạt 5/5 vì dùng cùng chế độ và lệnh benchmark.

## Vị trí mã nguồn và ba quy tắc bổ sung

Luồng kiểm thử xuất phát từ yêu cầu nhìn được dòng mã cần kiểm chứng trong giao diện và báo cáo. Kiểm thử mới trong `test/semgrep.test.mjs` thất bại trước khi quy tắc CWE-95 và đoạn trích được thêm. Sau triển khai, cùng ca xác nhận vị trí file/dòng/cột, dấu dòng cần xem, HTML escape và loại bỏ chuỗi, regex, template nhiều dòng, chú thích, nội dung JSX và đoạn mã thô trong đầu ra engine.

`npm run benchmark:semgrep` trước triển khai bỏ sót bảy mẫu mới. Sau lượt đầu, mẫu model ghi dữ liệu qua biến chứa khóa tính từ request vẫn bị bỏ sót. Rule bổ sung nguồn taint tại object chứa dạng khóa đó. Lượt cuối đạt 31/31 mẫu có lỗi và 0/31 mẫu đã sửa bị cảnh báo theo CWE đo. Quét nhanh đạt 12/31 và 8/31 tương ứng. Semgrep thật cũng xác nhận đoạn mã CWE-95 từ `examples/demo-src/app.js` và vị trí tương ứng trên hai file mẫu.

Preview giao diện quét `examples/demo-src` bằng Semgrep CE, báo 8 phát hiện và hiển thị `app.js:3:6` cùng `> 3 | eval(req.query.code);`. Literal ở dòng lân cận được che. Preview dùng dữ liệu mẫu và máy chủ loopback tạm thời.

`npm run test:coverage` đạt 98/98 với 97,14% độ phủ dòng. `node --check web/app.js` và `node --check scan.mjs` đạt. Đoạn trích được giới hạn theo kích thước file và dòng. Các ca benchmark đánh giá theo CWE đã định và phạm vi API trong từng hàm.

Tự đánh giá 4,4/5. Độ chính xác và độ đầy đủ đạt 4/5 vì có đối chứng engine thật và giao diện cho mã tổng hợp. Độ rõ ràng đạt 5/5 với file/dòng/cột và đoạn mã được đánh dấu. Khả năng sử dụng đạt 5/5 nhờ có cả UI và báo cáo xuất. Độ súc tích đạt 4/5 vì thêm bộ tách token để kiểm soát dữ liệu trong đoạn trích.

## Python, PHP, Java, Go và C#

Ba ca kiểm thử đích thất bại trước khi tích hợp: Python chưa được chọn, báo cáo thiếu thống kê theo ngôn ngữ, và bộ chuyển đổi chưa nhận quy tắc PHP. Sau triển khai, cả ba ca đạt. Bộ kiểm thử còn xác nhận upload trộn TypeScript, PHP, Java, Go và C# được chọn, Ruby nằm ngoài phạm vi phân tích sâu và định dạng không dùng bộ tách token JS/TS chỉ xuất vị trí.

Kết quả `npm run benchmark:semgrep` với Semgrep CE 1.184.0. Mỗi cặp có một mẫu có lỗi và một mẫu đã sửa. Báo nhầm được tính theo CWE của cặp:

| Ngôn ngữ | Cặp | Quét nhanh: phát hiện / báo nhầm | Quét sâu: phát hiện / báo nhầm |
|---|---:|---:|---:|
| Python | 3 | 3 / 0 | 3 / 0 |
| PHP | 3 | 2 / 1 | 3 / 0 |
| Java | 3 | 1 / 0 | 3 / 0 |
| Go | 3 | 1 / 0 | 3 / 0 |
| C# | 3 | 1 / 0 | 3 / 0 |
| JavaScript và TypeScript | 31 | 12 / 8 | 31 / 0 |
| Tổng | 46 | 20 / 9 | 46 / 0 |

Bảy mẫu mới chỉ quét sâu phát hiện: PHP include, Java chạy lệnh và object stream, Go chạy lệnh và SSRF, C# path traversal và chuyển hướng mở. Benchmark đối chiếu cột của 15 phát hiện với đúng đối số trong mã, kiểm tra tất cả 92 file theo ngôn ngữ và quét lại hai file JS mẫu trước đó. Một lượt upload HTTP qua loopback với engine thật xử lý 10 file của năm ngôn ngữ mới, báo đúng 5 phát hiện, và giữ vị trí `src/php-include.php:5:11` trong cả TXT và HTML.

`npm run test:coverage` đạt 99/99 với 97,21% độ phủ dòng. Kiểm tra cú pháp UI, CLI và các script benchmark đều đạt.

Tự đánh giá **4,6/5**:

| Tiêu chí | Điểm | Bằng chứng và điểm có thể cải thiện |
|---|---:|---|
| Chính xác | 4/5 | Engine thật khớp 46 cặp và 15 vị trí đối số. Mỗi quy tắc mới hiện có một cặp; nên bổ sung nhiều cách gọi API và tên biến thực tế. |
| Đầy đủ | 4/5 | Đã xác minh upload, báo cáo và quét thư mục. Năm ngôn ngữ mới trả vị trí; cần bộ tách token phù hợp nếu muốn hiện đoạn trích đã che cho chúng. |
| Rõ ràng | 5/5 | README liệt kê đuôi file, nguồn, điểm nhạy cảm, cách mở vị trí và giới hạn. |
| Áp dụng | 5/5 | Dùng lựa chọn Semgrep hiện có hoặc `--deep`; benchmark có lệnh chạy lại. |
| Súc tích | 5/5 | Các ngôn ngữ mới dùng chung một lượt chạy, cùng giao diện và định dạng báo cáo. |

Ưu tiên tiếp theo là bổ sung đối chứng lấy từ framework thực tế, sau đó mở rộng đoạn trích nếu có cơ chế che dữ liệu theo cú pháp. Tự kiểm: tính năng có thể kiểm tra ngay bằng upload hỗn hợp và cột thống kê theo ngôn ngữ; phần chưa hỗ trợ đã ghi trong README.

## Sáu quy tắc bổ sung

Semgrep CE 1.184.0 phát hiện 46 cặp cũ và bỏ sót cả 11 mẫu mới ở lượt đo ban đầu. Khi bật quy tắc, benchmark phát hiện một báo nhầm với giá trị LDAP đã escape và gán vào biến. Quy tắc chỉ mở rộng phạm vi nhận diện escape cho tên biến hoặc truy cập request bằng khóa literal. Cặp thứ 12 xác nhận việc escape kết quả sau khi gọi `search()` vẫn bị báo tại đối số bộ lọc.

| Phạm vi | Cặp | Quét nhanh phát hiện / báo nhầm | Quét sâu phát hiện / báo nhầm |
|---|---:|---:|---:|
| Sáu quy tắc bổ sung | 12 | 2 / 0 | 12 / 0 |
| Toàn bộ benchmark | 58 | 22 / 9 | 58 / 0 |

Benchmark đối chiếu cột của các phát hiện mới với đối số trong mã nguồn. Lượt upload cục bộ bằng engine thật quét 12 file, trả đúng sáu ID quy tắc dự kiến và giữ file, dòng và cột trong báo cáo TXT. `npm run test:coverage` đạt 99/99 với 97,22% độ phủ dòng.

Tự đánh giá **4,6/5**. Chính xác 4/5 vì một số mẫu vẫn dựa trên quy ước tên biến. Đầy đủ 4/5 vì các ca đối chứng tập trung vào những API được ghi trong README. Rõ ràng, áp dụng và súc tích đều 5/5 nhờ danh sách phạm vi, mẫu chạy lại được và cùng một đường upload. Khi mở rộng, ưu tiên bổ sung ca receiver có kiểu rõ ràng và tên ngoài quy ước.

## Mẫu cho Flask, PHP cURL, Go và C#

Lượt đo trước khi thêm quy tắc bỏ sót cả tám mẫu mới ban đầu. Lượt chạy sau phát hiện bảy mẫu và chỉ ra trường hợp C# có khối khởi tạo object còn thiếu. Sau khi bổ sung mẫu đối sánh, ca thứ chín kiểm tra thêm thuộc tính `FileName` trong khối đó.

| Phạm vi | Cặp | Quét nhanh phát hiện / báo nhầm | Quét sâu phát hiện / báo nhầm |
|---|---:|---:|---:|
| Bốn quy tắc mới | 9 | 0 / 0 | 9 / 0 |
| Toàn bộ benchmark | 67 | 22 / 9 | 67 / 0 |

Semgrep CE 1.184.0 trỏ đúng đối số trong cả chín mẫu. Lượt upload cục bộ xử lý 18 file, trả chín phát hiện từ đúng bốn quy tắc và giữ file, dòng và cột khi xuất TXT. `npm run test:coverage` đạt 99/99 với 97,23% độ phủ dòng.

Tự đánh giá **4,6/5**. Chính xác 4/5 vì phát hiện cấu hình cURL và `ProcessStartInfo` vẫn cần đối chiếu lúc sử dụng. Đầy đủ 4/5 vì ca đối chứng tập trung vào API được liệt kê. Rõ ràng, áp dụng và súc tích đều 5/5 nhờ phạm vi ghi trong README, lệnh tái lập và cùng đường upload. Điểm cải thiện là bổ sung đối chứng ghi đè cấu hình trước khi dùng.

## Mẫu Node.js, Python Requests, PHP và Java

Windows Defender cách ly file tạm của ca PHP `eval()` khi Semgrep đọc bản sao. Bộ mẫu cuối dùng chuyển hướng PHP để kiểm chứng với cấu hình bảo vệ hiện tại. Trên bộ mẫu cuối, lượt đo trước khi thêm rule bỏ sót cả tám mẫu mới.

| Phạm vi | Cặp | Quét nhanh phát hiện / báo nhầm | Quét sâu phát hiện / báo nhầm |
|---|---:|---:|---:|
| Bốn quy tắc mới | 8 | 1 / 0 | 8 / 0 |
| Toàn bộ benchmark | 75 | 23 / 9 | 75 / 0 |

Benchmark trỏ đúng đối số trong tám mẫu. Lượt upload local quét 16 file, trả đúng tám phát hiện từ bốn ID mới và có ngữ cảnh CWE cho cả tám. Báo cáo TXT giữ vị trí file, dòng và cột. `npm run test:coverage` đạt 99/99 với 97,24% độ phủ dòng.

Tự đánh giá **4,6/5**. Chính xác 4/5 vì rule Java báo URI ở bước dựng request và cần kiểm chứng đích lúc gửi. Đầy đủ 4/5 vì các ca kiểm tra tập trung vào API và kiểu import đã liệt kê. Rõ ràng, áp dụng và súc tích đều 5/5 nhờ luồng trong README, liên kết nguồn và cùng lệnh benchmark. Ưu tiên tiếp theo là bổ sung ca thay đổi URI giữa bước dựng và gửi.

## Express và báo cáo nhiều dòng

Hai ca Express mới kiểm tra tên tham số request thay đổi, middleware đứng trước callback và query config có đối số nhiều dòng. Trước khi cập nhật rule, Semgrep phát hiện 75/77 mẫu. Sau cập nhật, Semgrep phát hiện 77/77 mẫu có lỗi và cảnh báo 0/77 mẫu đã sửa theo CWE tương ứng. Quét nhanh phát hiện 25/77 mẫu có lỗi và cảnh báo 9/77 mẫu đã sửa.

Kiểm thử quét nhanh xác nhận chữ ký ghép SQL được gắn vào luồng dẫn tới mỗi lời gọi. Hai lời gọi ở hai dòng khác nhau vẫn có hai phát hiện. Kiểm thử Semgrep xác nhận vị trí đầu/cuối, che literal và hiển thị khoảng nhiều dòng trong TXT và HTML.

Trên giao diện local, mẫu query config hiện một phát hiện tại `route.js:7:11–8:21`, đánh dấu cả dòng 7 và 8, kèm cách khắc phục. `npm run test:coverage` đạt 82/82 sau khi gỡ các ca dành cho quét URL. Độ phủ dòng của mã nguồn là 98,51%.

## Framework và cấu hình

Các ca kiểm thử đi từ nhu cầu tải một ZIP dự án có mã nguồn, workflow và Dockerfile rồi nhận vị trí lỗi và hướng sửa. Trước khi thay đổi bộ quét, kiểm thử upload chỉ thấy 6 trong 9 tệp cần quét và kiểm thử staging không tìm thấy các bản sao cấu hình theo đường dẫn dự kiến. Sau thay đổi, cả hai kiểm thử đều đạt. YAML thông thường ngoài `.github/workflows` được loại khỏi lượt quét cấu hình GitHub Actions.

| Phạm vi | Cặp mẫu | Quét nhanh phát hiện / báo trên mẫu đã sửa | Quét sâu phát hiện / báo trên mẫu đã sửa |
|---|---:|---:|---:|
| Sáu quy tắc mới | 8 | 2 / 0 | 8 / 0 |
| Toàn bộ benchmark | 85 | 27 / 9 | 85 / 0 |

`npm run benchmark:semgrep` chạy bằng Semgrep CE 1.184.0. Mỗi mẫu mới phải trả đúng một phát hiện của rule tương ứng, đúng vị trí và có hướng sửa. Một lượt upload ZIP qua API cục bộ với Semgrep thật quét 16 tệp mục tiêu và trả 8 phát hiện. Workflow nhiều dòng được báo một lần tại `check.yml:6:9–8:56`. Báo cáo JSON, HTML và TXT giữ đường dẫn gốc và che khóa JWT tổng hợp. `npm run test:coverage` đạt 84/84 với 98,54% độ phủ dòng.

Tự đánh giá **4,6/5**. Chính xác 4/5 vì benchmark xác nhận các cặp mẫu và chưa đo trên dự án thực tế. Đầy đủ 4/5 vì Dockerfile chỉ kiểm tra các dạng chỉ thị một dòng được mô tả trong README. Rõ ràng 5/5 nhờ vị trí đầu và cuối cùng hướng sửa. Áp dụng 5/5 vì đã xác nhận luồng ZIP và ba định dạng xuất. Súc tích 5/5 vì mỗi mẫu mới trả đúng một phát hiện. Ưu tiên cải thiện là bổ sung đối chứng Dockerfile có heredoc và đối chiếu trên các dự án thực tế được phép quét.
