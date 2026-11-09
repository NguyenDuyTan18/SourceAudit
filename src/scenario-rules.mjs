const js = ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'];
const rule = (id, cwe, title, match, exts, remediation, requirement) => ({
  id: 'SC-' + id, cwe, severity: 'medium', title, match, exts,
  condition: 'Kiểm chứng đầu vào không tin cậy có tới API này, biện pháp bảo vệ trước đó và môi trường triển khai. Signature không xác nhận khai thác.',
  impact: `Dấu hiệu thuộc CWE-${cwe}; nếu đầu vào không được bảo vệ đúng ngữ cảnh, có thể dẫn tới thao tác ngoài ý muốn.`,
  fix: remediation, asvs: requirement ? ['ASVS-v5.0.0-' + requirement] : []
});
export const SCENARIO_RULES = [
  rule('JS-INSERT-HTML', 79, 'insertAdjacentHTML nhận dữ liệu request', /\.insertAdjacentHTML\s*\([^\n]*(?:req\.|request\.|location\.(?:hash|search))/, js, 'Ưu tiên insertAdjacentText/textContent; nếu cần HTML, dùng sanitizer đúng ngữ cảnh.', '1.2.1'),
  rule('JS-FRAGMENT', 79, 'createContextualFragment nhận URL input', /\.createContextualFragment\s*\(\s*(?:location\.(?:hash|search)|req\.|request\.)/, js, 'Giữ markup cố định hoặc sanitize HTML trước khi tạo fragment.', '1.2.1'),
  rule('JS-SQL-LITERAL', 89, 'Sequelize literal nhận tham số request', /\b(?:Sequelize|sequelize)\.literal\s*\(\s*(?:req\.|request\.)/, js, 'Dùng bind/replacements hoặc ánh xạ tên trường vào allowlist cố định.', '1.2.4'),
  rule('PHP-SQL-RAW', 89, 'Laravel SQL raw nhận request', /\bDB::raw\s*\(\s*\$request(?:->|\[)/, ['.php'], 'Dùng query binding và allowlist cấu trúc SQL động.', '1.2.4'),
  rule('PY-SQL-RAW', 89, 'Django raw query dùng chuỗi nội suy', /\.raw\s*\(\s*f["']/, ['.py'], 'Giữ SQL cố định và truyền tham số qua danh sách params.', '1.2.4'),
  rule('PHP-PRINT', 79, 'PHP print xuất trực tiếp request', /\bprint\s+\$_(?:GET|POST|REQUEST)\b/, ['.php'], 'Encode output theo ngữ cảnh HTML/attribute/JavaScript tương ứng.', '1.2.1'),
  rule('PY-XPATH', 643, 'XPath expression nhận đầu vào request', /\.xpath\s*\(\s*request\.(?:args|GET|POST|form)/, ['.py'], 'Dùng biểu thức XPath cố định và bind giá trị biến; không cho đầu vào thành cú pháp.'),
  rule('JS-LDAP', 90, 'LDAP filter nhận nguyên giá trị request', /\.search\s*\([^\n]*\bfilter\s*:\s*(?:req\.|request\.)/, js, 'Giữ cấu trúc filter cố định, dùng API escape/bind phù hợp với LDAP filter.'),
  rule('CS-TEMPLATE', 1336, 'Razor template được tạo từ request', /\bRazor\.Parse\s*\(\s*Request\./, ['.cs', '.cshtml'], 'Dùng template đã kiểm soát, truyền request như dữ liệu vào model.'),
  rule('JAVA-SSRF', 918, 'Java URL được dựng từ request', /\bnew\s+URL\s*\(\s*request\.getParameter\s*\(/, ['.java', '.kt'], 'Kiểm tra URL này có được truy xuất; áp dụng allowlist đích, DNS/IP và redirect.'),
  rule('GO-SSRF', 918, 'Go HTTP client nhận URL từ request', /\bhttp\.(?:Get|Post|Head)\s*\(\s*(?:r|request)\.(?:FormValue|URL\.Query)/, ['.go'], 'Allowlist đích và kiểm tra IP/redirect tại mỗi lần kết nối; giới hạn outbound network.'),
  rule('RUST-TLS', 295, 'Rust HTTP client chấp nhận chứng chỉ không hợp lệ', /\.danger_accept_invalid_certs\s*\(\s*true\s*\)/, ['.rs'], 'Bật xác minh TLS và cấu hình CA tin cậy thay vì bỏ xác minh.')
];
