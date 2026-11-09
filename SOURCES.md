# Nguồn tham khảo cho thư viện nhận dạng

Đối chiếu ngày 2026-11-05. Tóm tắt và rule trong tool được viết mới, không sao chép nguyên bài hay bộ rule có sẵn. Những mẫu source là heuristic riêng dựa trên nhóm nguyên nhân và API liên quan; chưa có kiểm định precision/recall trên benchmark thực tế.

| Nguồn | Phần dùng trong tool |
|---|---|
| [OWASP SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | Phân biệt SQL ghép chuỗi với parameter binding; hướng sửa |
| [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | Sink HTML và encoding theo ngữ cảnh |
| [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | Hướng rà soát đích, DNS và redirect trong mã nguồn được phân tích |
| [PortSwigger SSRF](https://portswigger.net/web-security/ssrf) | Hướng rà soát URL đầu vào server |
| [PortSwigger Path Traversal](https://portswigger.net/web-security/file-path-traversal) | Kiểm tra đường dẫn file và boundary thư mục |
| [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection) | Phân biệt nội dung template với dữ liệu template |
| [PortSwigger Prototype Pollution Research, Gareth Heyes, 2023](https://portswigger.net/research/server-side-prototype-pollution) | Ngữ cảnh merge/key động và hạn chế của phát hiện black-box; không tích hợp probe từ bài |
| [PortSwigger XXE](https://portswigger.net/web-security/xxe) | Rà soát XML parser và external entity |
| [PortSwigger JWT](https://portswigger.net/web-security/jwt) | Rà soát verify chữ ký và sử dụng claim |
| [Semgrep taint analysis](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview) | Phân tích luồng trong chế độ sâu và khai báo source, sink, sanitizer trong YAML |
| [Định tuyến Express](https://expressjs.com/en/guide/routing.html) và [truy vấn node-postgres](https://node-postgres.com/features/queries) | Nhận diện tham số request trong callback và phân biệt câu SQL với các giá trị truyền riêng |
| [GitHub Actions script injection](https://docs.github.com/en/actions/concepts/security/script-injections) và [Dockerfile USER](https://docs.docker.com/reference/dockerfile/#user) | So khớp dữ liệu sự kiện trong lệnh của workflow và kiểm tra user của stage cuối |
| [Spring JDBC](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/jdbc/core/JdbcTemplate.html) và [Laravel Database](https://laravel.com/docs/12.x/database#running-a-select-query) | Xác định đối số SQL và cách truyền giá trị qua binding |
| [jsonwebtoken verify](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback), [Rails params](https://guides.rubyonrails.org/action_controller_overview.html#parameters) và [Ruby Net::HTTP](https://docs.ruby-lang.org/en/master/Net/HTTP.html) | Xác định đối số khóa HMAC, dữ liệu từ request Rails và điểm gửi yêu cầu HTTP |
| [Node.js coverage](https://nodejs.org/learn/test-runner/collecting-code-coverage) | Chạy kiểm thử và đo coverage bằng test runner tích hợp |

Mỗi phát hiện có CWE reference. Thư viện kiến thức kèm thêm các trang OWASP/PortSwigger theo chủ đề để người dùng kiểm chứng; đây không phải chứng nhận phát hiện hay cơ sở dữ liệu CVE.

UI/upload revision: ZIP streaming API được đối chiếu với [fflate README](https://github.com/101arrowz/fflate#readme) qua Context7; thư viện được cài từ npm với install scripts tắt. Mã thư viện và giấy phép đi kèm trong bản bàn giao.

## Kho ngữ cảnh thu thập ngày 2026-11-05

- [MITRE CWE downloads](https://cwe.mitre.org/data/downloads.html): XML CWE v5.0, 984 weakness, giữ ID, mô tả, tác động và mitigation. [CWE Terms](https://cwe.mitre.org/about/termsofuse.html) được lưu kèm data/.
- [OWASP WSTG v4.2](https://github.com/OWASP/wstg/tree/v4.2): 97 scenario ID, tóm tắt/mục tiêu; tham chiếu URL versioned. CC BY-SA 4.0; metadata được chuẩn hóa/cắt ngắn.
- [GitHub global advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories): 936 GHSA duy nhất đã review, không withdrawn, dữ liệu được chọn theo số trang có giới hạn và 5 reference CVE. [Advisory database license](https://github.com/github/advisory-database/blob/main/LICENSE.md) CC-BY 4.0 được lưu kèm.
- [node-semver](https://github.com/npm/node-semver) và [PEP 440 implementation](https://github.com/renovatebot/pep440): so affected ranges cho npm/PyPI đã chốt phiên bản. Không dùng comparator này để suy diễn Maven/Composer/NuGet.

`data/manifest.json` ghi URL tải thực tế, thời gian, checksum, phiên bản và ranh giới lựa chọn. Rule quét nhanh nằm trong `src/` và rule Semgrep nằm trong `rules/`. Corpus cung cấp ngữ cảnh và dữ liệu để đối chiếu phiên bản dependency.

## Đợt mở rộng ngày 2026-11-06

- [OWASP ASVS v5.0.0 release](https://github.com/OWASP/ASVS/tree/v5.0.0_release): 345 yêu cầu xác minh, giữ ID và mức L. [JSON nguồn](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0_release/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json); giấy phép được lưu kèm.
- [OWASP API Security 2023](https://github.com/OWASP/API-Security/tree/33cea37b2ffde3e2e62f6b5d79a029a22a846633/editions/2023/en): 10 nhóm rủi ro + 23 tình huống, tổng 33 bản ghi. Bỏ code block trong mô tả nhập; giữ bước phòng vệ, nguồn theo commit và giấy phép CC BY-SA 4.0.
- [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json): 1768 CVE trong catalog 2026.11.04. Nhãn KEV chỉ nói về lịch sử khai thác công khai, không về việc máy/mục tiêu hiện tại bị tấn công. Không sao chép deadline của cơ quan liên bang thành deadline của người dùng.
- Advisory cho allowlist package công khai: 891 bản ghi tải ở đợt mở rộng, 841 ID mới sau khi gộp với 936 bản ghi cũ; tổng 1777 advisory duy nhất. Danh sách được chọn có giới hạn, không phải toàn bộ CVE.

Provenance và SHA-256 ở data/extensions-manifest.json. Dữ liệu mới được chuẩn hóa/cắt ngắn từ nguồn; attribution ở data/NOTICE.md, giấy phép ASVS/API Security trong data/. 12 signature mới được viết và kiểm thử riêng; tổng hiện tại là 82 rule, không phải 5004 detector.
