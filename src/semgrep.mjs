import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { redactedSourceLines, sourceExcerptAt } from './source-excerpt.mjs';

const execute = promisify(execFile);
const rulePaths = ['semgrep-js-ts.yml', 'semgrep-multilang.yml', 'semgrep-framework-config.yml'].map((name) =>
  fileURLToPath(new URL('../rules/' + name, import.meta.url)));
const bundled = fileURLToPath(new URL(process.platform === 'win32'
  ? '../.scanner-tools/semgrep/Scripts/semgrep.exe'
  : '../.scanner-tools/semgrep/bin/semgrep', import.meta.url));

const rules = new Map([
  ['srcaudit-js-sql-injection', {
    cwe: 'CWE-89', title: 'Dữ liệu request đi vào câu lệnh SQL', severity: 'high',
    remediation: 'Giữ câu SQL cố định và truyền giá trị qua parameter binding. Dùng allowlist riêng cho tên cột hoặc bảng.',
  }],
  ['srcaudit-js-command-injection', {
    cwe: 'CWE-78', title: 'Dữ liệu request đi vào lệnh shell', severity: 'high',
    remediation: 'Chọn executable cố định và dùng execFile hoặc spawn với danh sách đối số và shell tắt. Kiểm tra đối số theo allowlist.',
  }],
  ['srcaudit-js-ssrf', {
    cwe: 'CWE-918', title: 'Dữ liệu request điều khiển URL gọi ra ngoài', severity: 'medium',
    remediation: 'Dùng đích cố định hoặc allowlist đích, xác minh scheme và IP sau DNS, kiểm tra từng redirect và giới hạn mạng đi ra.',
  }],
  ['srcaudit-express-path-traversal', {
    cwe: 'CWE-22', title: 'Dữ liệu request điều khiển đường dẫn tải file Express', severity: 'high',
    remediation: 'Ánh xạ đầu vào sang danh sách file cho phép hoặc dùng root cố định với tên tương đối. Kiểm tra symlink và quyền truy cập file.',
  }],
  ['srcaudit-js-xss', {
    cwe: 'CWE-79', title: 'Dữ liệu request đi vào HTML', severity: 'high',
    remediation: 'Dùng JSON nếu trả dữ liệu, textContent nếu ghi văn bản vào DOM, hoặc mã hóa đầu ra đúng ngữ cảnh khi tạo HTML.',
  }],
  ['srcaudit-express-open-redirect', {
    cwe: 'CWE-601', title: 'Dữ liệu request điều khiển đích chuyển hướng', severity: 'medium',
    impact: 'Có thể dẫn người dùng từ một URL tin cậy sang đích do người khác chọn.',
    remediation: 'Ánh xạ mã trang sang danh sách đích cố định. Nếu cho nhập URL, phân tích URL và kiểm tra origin cùng đường dẫn theo allowlist.',
  }],
  ['srcaudit-js-nosql-injection', {
    cwe: 'CWE-943', title: 'Dữ liệu request điều khiển bộ lọc hoặc pipeline NoSQL', severity: 'high',
    impact: 'Bộ lọc do người dùng kiểm soát có thể thay đổi tập kết quả, tùy driver, toán tử và quyền.',
    remediation: 'Dùng trường và toán tử cố định. Kiểm tra kiểu của từng giá trị và dựng bộ lọc hoặc pipeline ở phía máy chủ.',
  }],
  ['srcaudit-js-prototype-pollution', {
    cwe: 'CWE-1321', title: 'Dữ liệu request điều khiển khóa được merge hoặc gán', severity: 'medium',
    impact: 'Tác động phụ thuộc vào hàm merge/gán, phiên bản thư viện và cách ứng dụng dùng object sau đó.',
    remediation: 'Sao chép các trường trong schema cho phép. Kiểm tra mọi đoạn khóa động và từ chối __proto__, constructor và prototype.',
  }],
  ['srcaudit-js-template-injection', {
    cwe: 'CWE-1336', title: 'Dữ liệu request đi vào mã template phía máy chủ', severity: 'high',
    impact: 'Nếu engine biên dịch đầu vào thành mã template, biểu thức có thể chạy trong ngữ cảnh máy chủ.',
    remediation: 'Chọn template cố định do ứng dụng quản lý và truyền nội dung người dùng qua đối số dữ liệu có kiểm tra kiểu.',
  }],
  ['srcaudit-js-code-injection', {
    cwe: 'CWE-95', title: 'Dữ liệu request được dùng làm mã JavaScript', severity: 'high',
    impact: 'Nếu API thực thi chuỗi đã nhận, nội dung có thể chạy với quyền của tiến trình hiện tại.',
    remediation: 'Dùng JSON.parse cho dữ liệu JSON. Chọn thao tác từ bảng hàm cố định và xác thực tham số trước khi gọi.',
  }],
  ['srcaudit-js-unsafe-deserialization', {
    cwe: 'CWE-502', title: 'Dữ liệu request đi vào node-serialize.unserialize()', severity: 'high',
    impact: 'Thư viện có thể khôi phục nội dung có hành vi thực thi. Cần xác minh package, phiên bản và dữ liệu đầu vào.',
    remediation: 'Dùng JSON.parse và kiểm tra dữ liệu bằng schema. Chỉ lấy các trường mà ứng dụng cần.',
  }],
  ['srcaudit-js-mass-assignment', {
    cwe: 'CWE-915', title: 'Model nhận thuộc tính cập nhật do request điều khiển', severity: 'medium',
    impact: 'Người dùng có thể thay đổi các trường ngoài phạm vi được phép nếu model và lớp phân quyền cho phép ghi.',
    remediation: 'Tạo DTO với danh sách trường cố định, kiểm tra kiểu và phân quyền ghi cho từng trường nhạy cảm.',
  }],
]);

const sql = ['CWE-89', 'Dữ liệu request đi vào câu lệnh SQL', 'high',
  'Giữ câu SQL cố định và bind giá trị qua tham số. Dùng allowlist cho tên cột hoặc bảng.'];
const command = ['CWE-78', 'Dữ liệu request điều khiển lệnh hoặc chương trình được chạy', 'high',
  'Chọn executable cố định, tắt shell và truyền đối số riêng sau khi kiểm tra theo allowlist.'];
const deserialization = ['CWE-502', 'Dữ liệu request đi vào bộ giải tuần tự đối tượng', 'high',
  'Dùng định dạng dữ liệu như JSON và kiểm tra schema. Tránh khôi phục đối tượng từ dữ liệu không tin cậy.'];
const additionalRules = {
  'srcaudit-js-file-write-path-traversal': ['CWE-22', 'Dữ liệu request điều khiển đường dẫn ghi file trong Node.js', 'high',
    'Dùng tên file do máy chủ sinh hoặc ánh xạ mã được phép sang đường dẫn cố định. Kiểm tra thư mục đích và symlink.'],
  'srcaudit-python-requests-ssrf': ['CWE-918', 'Dữ liệu request điều khiển URL của Python Requests', 'medium',
    'Ánh xạ mã dịch vụ sang URL cố định hoặc xác minh giao thức, đích DNS và từng redirect theo chính sách mạng.'],
  'srcaudit-php-open-redirect': ['CWE-601', 'Dữ liệu request điều khiển đích chuyển hướng trong PHP', 'medium',
    'Ánh xạ tên trang sang đường dẫn nội bộ cố định. Xác minh origin và đích nếu cho phép URL bên ngoài.'],
  'srcaudit-java-outbound-ssrf': ['CWE-918', 'Dữ liệu request điều khiển đích mạng trong Java', 'medium',
    'Dùng đích cố định hoặc kiểm tra giao thức, host, IP sau DNS và từng redirect trước khi gửi.'],
  'srcaudit-python-flask-ssti': ['CWE-1336', 'Dữ liệu request được biên dịch thành template Flask', 'high',
    'Dùng template cố định và truyền giá trị người dùng qua biến ngữ cảnh của template.'],
  'srcaudit-php-curl-ssrf': ['CWE-918', 'Dữ liệu request điều khiển URL đích của cURL', 'medium',
    'Ánh xạ mã dịch vụ sang URL cố định. Kiểm tra giao thức, địa chỉ IP sau DNS và đích chuyển hướng trước khi gửi.'],
  'srcaudit-go-path-traversal': ['CWE-22', 'Dữ liệu request điều khiển đường dẫn mở file trong Go', 'high',
    'Ánh xạ tên được phép sang đường dẫn cố định hoặc dùng API giới hạn truy cập trong thư mục gốc.'],
  'srcaudit-csharp-command-injection': command,
  'srcaudit-js-untrusted-module': ['CWE-470', 'Dữ liệu request điều khiển module JavaScript được nạp', 'high',
    'Ánh xạ lựa chọn từ request sang danh sách module với đường dẫn cố định.'],
  'srcaudit-python-ldap-injection': ['CWE-90', 'Dữ liệu request đi vào bộ lọc tìm kiếm LDAP', 'high',
    'Giữ cấu trúc bộ lọc cố định và dùng ldap3.utils.conv.escape_filter_chars cho từng giá trị được chèn.'],
  'srcaudit-php-unsafe-deserialization': deserialization,
  'srcaudit-java-xpath-injection': ['CWE-643', 'Dữ liệu request đi vào biểu thức XPath', 'high',
    'Dùng biểu thức XPath cố định và truyền giá trị qua XPathVariableResolver.'],
  'srcaudit-go-log-injection': ['CWE-117', 'Dữ liệu request đi vào bản ghi log văn bản', 'medium',
    'Mã hóa ký tự điều khiển trong dữ liệu trước khi ghi hoặc dùng logger có cấu trúc với trường dữ liệu riêng.'],
  'srcaudit-csharp-ssrf': ['CWE-918', 'Dữ liệu request điều khiển URL của HttpClient', 'medium',
    'Ánh xạ lựa chọn sang đích cố định hoặc kiểm tra scheme, host, IP sau DNS và mỗi redirect theo chính sách mạng.'],
  'srcaudit-python-sql-injection': sql,
  'srcaudit-python-command-injection': command,
  'srcaudit-python-unsafe-deserialization': deserialization,
  'srcaudit-php-sql-injection': sql,
  'srcaudit-php-command-injection': command,
  'srcaudit-php-file-inclusion': ['CWE-98', 'Dữ liệu request điều khiển file được nạp trong PHP', 'high',
    'Ánh xạ mã trang tới danh sách file cố định. Không ghép dữ liệu request trực tiếp vào include hoặc require.'],
  'srcaudit-java-sql-injection': sql,
  'srcaudit-java-command-injection': command,
  'srcaudit-java-unsafe-deserialization': deserialization,
  'srcaudit-go-sql-injection': sql,
  'srcaudit-go-command-injection': command,
  'srcaudit-go-ssrf': ['CWE-918', 'Dữ liệu request điều khiển URL của HTTP client Go', 'medium',
    'Dùng đích cố định hoặc allowlist đích. Kiểm tra scheme, IP sau DNS và mỗi redirect trước khi gửi yêu cầu.'],
  'srcaudit-csharp-sql-injection': sql,
  'srcaudit-csharp-path-traversal': ['CWE-22', 'Dữ liệu request điều khiển đường dẫn đọc file', 'high',
    'Ánh xạ đầu vào sang danh sách file cho phép hoặc xác minh đường dẫn chuẩn hóa nằm trong thư mục gốc, kể cả symlink.'],
  'srcaudit-csharp-open-redirect': ['CWE-601', 'Dữ liệu request điều khiển đích chuyển hướng ASP.NET', 'medium',
    'Dùng LocalRedirect cho đích nội bộ hoặc chọn đích từ allowlist cố định.'],
  'srcaudit-spring-jdbc-template-sql-injection': sql,
  'srcaudit-laravel-raw-sql-injection': sql,
  'srcaudit-rails-http-ssrf': ['CWE-918', 'Dữ liệu params của Rails điều khiển đích HTTP', 'high',
    'Ánh xạ lựa chọn sang URL cố định hoặc kiểm tra giao thức, host, địa chỉ IP sau DNS và từng redirect.'],
};
for (const [id, [cwe, title, severity, remediation]] of Object.entries(additionalRules)) {
  rules.set(id, { cwe, title, severity, remediation });
}

rules.set('srcaudit-github-actions-script-injection', {
  cwe: 'CWE-78', title: 'Dữ liệu sự kiện GitHub được chèn vào script run:', severity: 'high',
  evidence: 'Khối run: chứa biểu thức GitHub Actions lấy dữ liệu sự kiện có thể do người dùng điều khiển.',
  impact: 'Giá trị được chèn trước khi shell phân tích script. Lệnh có thể chạy với quyền của job.',
  remediation: 'Truyền giá trị qua env: của step. Trong Bash, dùng "$TEN_BIEN"; với shell khác, dùng cú pháp biến môi trường phù hợp.',
});
rules.set('srcaudit-dockerfile-root-user', {
  cwe: 'CWE-250', title: 'Stage cuối của Dockerfile có thể chạy với quyền root', severity: 'medium',
  evidence: 'Stage cuối đặt USER là root hoặc 0, hoặc dùng base image thuộc phạm vi rule mà thiếu USER.',
  impact: 'Tiến trình có thể có quyền cao hơn mức cần thiết nếu cấu hình chạy không đặt user riêng.',
  remediation: 'Tạo user không phải root và đặt USER ở stage cuối. Kiểm tra quyền truy cập file và cấu hình khi chạy.',
});
rules.set('srcaudit-node-jwt-literal-verification-key', {
  cwe: 'CWE-321', title: 'jsonwebtoken.verify dùng khóa HMAC viết cứng', severity: 'high',
  evidence: 'Đối số khóa là literal và danh sách thuật toán chỉ định một thuật toán HMAC.',
  impact: 'Người đọc được khóa đối xứng có thể tạo token có chữ ký hợp lệ nếu ứng dụng đang dùng khóa đó.',
  remediation: 'Nạp khóa từ secret manager và giữ allowlist thuật toán. Nếu khóa từng được dùng, xoay vòng khóa.',
});

const languageByExtension = new Map([
  ['.js', 'JavaScript'], ['.mjs', 'JavaScript'], ['.cjs', 'JavaScript'], ['.jsx', 'JavaScript'],
  ['.ts', 'TypeScript'], ['.tsx', 'TypeScript'], ['.py', 'Python'], ['.php', 'PHP'],
  ['.java', 'Java'], ['.go', 'Go'], ['.cs', 'C#'], ['.rb', 'Ruby'],
]);

export const SEMGREP_RULE_COUNT = rules.size;
export function semgrepLanguage(file) {
  if (path.basename(file) === 'Dockerfile') return 'Dockerfile';
  if (/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(file)) return 'GitHub Actions';
  return languageByExtension.get(path.extname(file).toLowerCase());
}

export function semgrepExecutable() {
  return process.env.SECURITYSCANNER_SEMGREP_EXE || (existsSync(bundled) ? bundled : 'semgrep');
}

function languageCounts(staged, scanned = new Set()) {
  const languages = {};
  for (const [stagedPath, { language }] of staged) {
    const count = languages[language] ??= { selected: 0, scanned: 0 };
    count.selected++;
    if (scanned.has(stagedPath)) count.scanned++;
  }
  return languages;
}

function normalize(output, workspace, staged) {
  if (!Array.isArray(output?.results) || !Array.isArray(output.errors) || !Array.isArray(output.paths?.scanned)) {
    throw new Error('Invalid Semgrep output');
  }
  const resolve = (file) => typeof file === 'string' ? path.resolve(workspace, file) : undefined;
  const scanned = new Set(output.paths.scanned.map(resolve).filter((file) => staged.has(file)));
  const findings = [];
  const seen = new Set();
  const excerpts = new Map();
  for (const result of output.results) {
    const rule = rules.get(result?.check_id);
    const stagedPath = resolve(result?.path);
    const line = result?.start?.line;
    const column = result?.start?.col;
    if (!rule || !scanned.has(stagedPath) || !Number.isSafeInteger(line) || line < 1 ||
        !Number.isSafeInteger(column) || column < 1) continue;
    const { file, text } = staged.get(stagedPath);
    const endLine = result.end?.line;
    const endColumn = result.end?.col;
    const multiline = Number.isSafeInteger(endLine) && endLine > line &&
      Number.isSafeInteger(endColumn) && endColumn >= 1;
    const id = JSON.stringify([result.check_id, file, line, column]);
    if (seen.has(id)) continue;
    seen.add(id);
    if (!excerpts.has(stagedPath)) excerpts.set(stagedPath, redactedSourceLines(file, text));
    const lastMarkedLine = multiline ? endLine - (endColumn === 1 ? 1 : 0) : line;
    const sourceExcerpt = sourceExcerptAt(excerpts.get(stagedPath), line, lastMarkedLine);
    const structural = Boolean(rule.evidence);
    findings.push({
      ...rule, ruleId: result.check_id, confidence: 'medium', status: 'needs-review',
      location: { file, line, column, ...(multiline ? { endLine, endColumn } : {}) },
      ...(sourceExcerpt ? { sourceExcerpt } : {}),
      evidence: rule.evidence ?? 'Semgrep theo dõi dữ liệu từ request tới đối số nhạy cảm. Mở vị trí trong source để xem mã.',
      impact: rule.impact ?? 'Khả năng khai thác phụ thuộc vào biện pháp kiểm tra đầu vào và ngữ cảnh chạy thực tế.',
      reference: 'https://cwe.mitre.org/data/definitions/' + rule.cwe.slice(4) + '.html',
      detection: structural
        ? { method: 'semgrep-pattern', condition: 'Đối chiếu mẫu mã nguồn với cấu hình và cách chạy thực tế.' }
        : { method: 'semgrep-taint', condition: 'Đối chiếu luồng với kiểm tra đầu vào và cấu hình thực tế.' },
    });
  }
  const partial = output.errors.length > 0 || scanned.size < staged.size;
  return {
    status: partial ? 'partial' : 'complete',
    scanned: scanned.size,
    languages: languageCounts(staged, scanned),
    findings,
    message: partial ? 'Semgrep báo lỗi phân tích hoặc bỏ qua một số file đã chọn.' : undefined,
  };
}

export async function runSemgrep(files, { executable = semgrepExecutable(), run = execute } = {}) {
  const workspace = await mkdtemp(path.join(tmpdir(), 'scanner-semgrep-'));
  const staged = new Map();
  try {
    await mkdir(path.join(workspace, 'targets'));
    for (const { file, text, language = semgrepLanguage(file) } of files) {
      if (!language) continue;
      const slot = String(staged.size + 1);
      let stagedName = slot + path.extname(file).toLowerCase();
      // Preserve only the structure needed by the parser and path filters.
      if (language === 'GitHub Actions') stagedName = path.join(slot, '.github', 'workflows', 'workflow.yml');
      if (language === 'Dockerfile') stagedName = path.join(slot, 'Dockerfile');
      const stagedPath = path.join(workspace, 'targets', stagedName);
      if (language === 'GitHub Actions' || language === 'Dockerfile') {
        await mkdir(path.dirname(stagedPath), { recursive: true });
      }
      await writeFile(stagedPath, text, { mode: 0o600, flag: 'wx' });
      staged.set(stagedPath, { file, text, language });
    }
    // Keep the child independent of user Semgrep settings, tokens and project configuration.
    const allowed = new Set(['PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'SYSTEMDRIVE', 'LANG', 'LC_ALL']);
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => allowed.has(key.toUpperCase())));
    Object.assign(env, {
      HOME: workspace, USERPROFILE: workspace, APPDATA: workspace, LOCALAPPDATA: workspace,
      TMP: workspace, TEMP: workspace, TMPDIR: workspace,
      SEMGREP_SETTINGS_FILE: path.join(workspace, 'settings.yml'),
      PYTHONUTF8: '1',
    });
    const args = [
      'scan', ...rulePaths.flatMap((file) => ['--config', file]), '--metrics=off', '--disable-version-check',
      '--no-rewrite-rule-ids', '--disable-nosem', '--no-git-ignore',
      '--max-target-bytes=0', '--jobs=1', '--timeout=5', '--timeout-threshold=1',
      '--json', '--quiet', 'targets',
    ];
    const { stdout } = await run(executable, args, {
      cwd: workspace, env, timeout: 90_000, maxBuffer: 4 * 1024 * 1024, windowsHide: true,
    });
    return normalize(JSON.parse(stdout), workspace, staged);
  } catch (error) {
    let message = 'Semgrep không hoàn tất. Kiểm tra bản cài và giới hạn của lượt quét.';
    if (error.code === 'ENOENT') message = 'Chưa tìm thấy Semgrep. Cài Semgrep CE hoặc cấu hình SECURITYSCANNER_SEMGREP_EXE.';
    else if (error.killed) message = 'Semgrep vượt thời gian phân tích 90 giây.';
    return { status: 'failed', scanned: 0, languages: languageCounts(staged), findings: [], message };
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
}
