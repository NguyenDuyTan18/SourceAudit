import { lstat, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { createReport, finishReport, SEVERITIES } from './report.mjs';
import { EXTENDED_RULES } from './extended-rules.mjs';
import { SCENARIO_RULES } from './scenario-rules.mjs';
import { analyzeFlow, FLOW_RULES } from './flow.mjs';
import { extractDependencies, dependencyFindings } from './dependencies.mjs';
import { corpusStats } from './corpus.mjs';
import { runSemgrep, semgrepLanguage, SEMGREP_RULE_COUNT } from './semgrep.mjs';

const SKIP = new Set(['.git', '.svn', 'node_modules', '.venv', 'venv', '__pycache__', 'vendor', 'dist', 'build', 'coverage', '.next', '.scanner-reports', '.scanner-tools', '.scanner-auth']);
const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.php', '.java', '.cs', '.go', '.rb', '.html', '.htm', '.vue', '.svelte', '.astro', '.css', '.scss', '.sass', '.less', '.xml', '.svg', '.sql', '.graphql', '.gql', '.razor', '.cshtml', '.ejs', '.hbs', '.erb', '.jsp', '.kt', '.kts', '.rs', '.ex', '.exs', '.erl', '.dart', '.sh', '.ps1']);
const CONFIG_EXT = new Set(['.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.config', '.properties', '.pem', '.key', '.env', '.lock', '.mod']);
export const SUPPORTED_SOURCE_EXTENSIONS = [...CODE_EXT, ...CONFIG_EXT];
export function isSupportedSourceFile(name) {
  return CODE_EXT.has(path.extname(name).toLowerCase()) || CONFIG_EXT.has(path.extname(name).toLowerCase()) || path.basename(name).startsWith('.env') || path.basename(name) === 'Dockerfile' || /^requirements(?:[.-].*)?\.txt$/i.test(path.basename(name));
}
const ref = (cwe) => `https://cwe.mitre.org/data/definitions/${cwe}.html`;
const rules = [
  { id: 'SRC-SSRF', cwe: 918, severity: 'medium', title: 'HTTP client nhận URL từ request', match: /\b(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post)|urllib\.request\.urlopen)\s*\([^\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|GET|POST))/, impact: 'Nếu URL đích không bị giới hạn, server có thể bị dùng để truy cập tài nguyên ngoài phạm vi.', fix: 'Kiểm tra allowlist đích, scheme, toàn bộ IP DNS và từng redirect; giới hạn outbound network. Cần kiểm chứng biện pháp bảo vệ hiện có.' },
  { id: 'SRC-PATH', cwe: 22, severity: 'medium', title: 'API truy cập file nhận đầu vào từ request', match: /\b(?:readFile(?:Sync)?|sendFile|send_file|open|file_get_contents)\s*\([^\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|GET|POST)|\$_(?:GET|POST|REQUEST))/, impact: 'Nếu đường dẫn không bị ràng buộc, có thể đọc file ngoài thư mục cho phép.', fix: 'Resolve/canonicalize đường dẫn và kiểm tra nằm trong root cho phép; xử lý symlink và quyền file.' },
  { id: 'SRC-SSTI', cwe: 1336, severity: 'high', title: 'Template động nhận dữ liệu từ request', match: /\b(?:render_template_string|from_string|ejs\.render)\s*\([^\n]*(?:req\.|request\.)/, impact: 'Dữ liệu người dùng trở thành mã template có thể thực thi biểu thức ngoài ý muốn.', fix: 'Dùng template cố định, chỉ truyền đầu vào dưới dạng dữ liệu; kiểm tra engine và cơ chế sandbox.' },
  { id: 'SRC-PROTOTYPE', cwe: 1321, severity: 'medium', title: 'Merge dữ liệu request vào object cần kiểm tra', match: /\b(?:merge|defaultsDeep|extend)\s*\([^\n]*(?:req\.body|request\.body)|\[\s*(?:req\.(?:query|body|params)[^\]]*)\]\s*=/, impact: 'Merge/key động không được bảo vệ có thể gây prototype pollution; phụ thuộc thư viện và cách sử dụng.', fix: 'Xác minh phiên bản/triển khai merge; chặn key nguy hiểm ở mọi cấp, dùng schema và object không có prototype khi phù hợp.' },
  { id: 'SRC-XXE', cwe: 611, severity: 'medium', title: 'XML parser bật xử lý external entity', match: /\bresolve_entities\s*=\s*True\b|\bLIBXML_NOENT\b|\bXmlResolver\s*=\s*new\s+XmlUrlResolver/, impact: 'External entity có thể truy cập file hoặc mạng nếu parser và quyền runtime cho phép.', fix: 'Tắt DTD/external entity và network access theo cấu hình XML parser đang sử dụng.' },
  { id: 'SRC-JWT', cwe: 347, severity: 'high', title: 'JWT bị tắt kiểm tra chữ ký', match: /\bverify_signature["']?\s*[:=]\s*(?:False|false)\b|\bjwt\.decode\s*\([^\n]*\bverify\s*=\s*False/, impact: 'Nếu kết quả được dùng để xác thực/phân quyền, token không có chữ ký hợp lệ có thể được tin cậy.', fix: 'Verify chữ ký, allowlist thuật toán và kiểm tra issuer/audience/expiry trước khi dùng claim.' },
  { id: 'SRC-EVAL', cwe: 95, severity: 'high', title: 'Thực thi code động cần kiểm tra', match: /\b(?:eval|exec)\s*\(/, exts: ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.php'], impact: 'Nếu đầu vào đến từ người dùng, có thể chạy code ngoài ý muốn.', fix: 'Thay eval/exec bằng parser hoặc thao tác tường minh; không truyền dữ liệu không tin cậy vào code động.' },
  { id: 'SRC-SHELL', cwe: 78, severity: 'high', title: 'Gọi shell hoặc lệnh hệ thống cần kiểm tra', match: /\b(?:child_process\s*\.\s*exec|execSync|os\s*\.\s*system|shell_exec|passthru|system)\s*\(|\bshell\s*=\s*True\b|\b(?:exec|execFile)\s*\([^\n]*(?:req\.|request\.|\$_(?:GET|POST|REQUEST))/, impact: 'Đầu vào không tin cậy ghép vào lệnh có thể dẫn đến command injection.', fix: 'Dùng API không qua shell, truyền danh sách đối số; allowlist lệnh và tham số. Kiểm tra nguồn dữ liệu trước khi xác nhận.' },
  { id: 'SRC-SQL', cwe: 89, severity: 'high', title: 'Câu SQL được ghép chuỗi cần kiểm tra', match: /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n]*(?:\+|\$\{|\s\.\s|\$_(?:GET|POST|REQUEST))|\b(?:execute|query)\s*\(\s*f["']/, impact: 'Nếu dữ liệu người dùng được ghép trực tiếp, có nguy cơ SQL injection.', fix: 'Dùng truy vấn tham số hóa hoặc prepared statement; không tự escape bằng thay thế chuỗi.' },
  { id: 'SRC-XSS', cwe: 79, severity: 'medium', title: 'Điểm xuất HTML có nguy cơ XSS', match: /\.\s*(?:innerHTML|outerHTML)\s*=|\bdangerouslySetInnerHTML\s*[:=]|\bdocument\.write\s*\(|\bres\.(?:send|write)\s*\([^\n]*(?:req\.|request\.)|\becho\s+\$_(?:GET|POST|REQUEST)/, impact: 'Dữ liệu không được escape hoặc sanitize có thể thực thi script trong trình duyệt.', fix: 'Dùng textContent hoặc template tự escape; nếu cần HTML, dùng bộ sanitize phù hợp và kiểm tra luồng dữ liệu.' },
  { id: 'SRC-DESERIALIZE', cwe: 502, severity: 'high', title: 'Giải tuần tự dữ liệu cần kiểm tra', match: /\b(?:pickle\.loads?|unserialize)\s*\(|\byaml\.load\s*\((?![^\n]*(?:SafeLoader|BaseLoader))/, impact: 'Giải tuần tự dữ liệu không tin cậy có thể tạo đối tượng hoặc thực thi code ngoài ý muốn.', fix: 'Dùng JSON có schema, yaml.safe_load hoặc cơ chế giải tuần tự không tạo đối tượng tùy ý.' },
  { id: 'SRC-TLS-VERIFY', cwe: 295, severity: 'medium', title: 'Tắt xác minh chứng chỉ TLS', match: /\brejectUnauthorized\s*:\s*false\b|\bverify\s*=\s*False\b|\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0\b|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)/, impact: 'Kết nối có thể chấp nhận máy chủ giả mạo khi chứng chỉ không được xác minh.', fix: 'Bật xác minh chứng chỉ và cấu hình CA tin cậy thay vì tắt xác minh.' },
  { id: 'SRC-DEBUG', cwe: 489, severity: 'low', title: 'Cấu hình debug đang bật', match: /\bdebug\s*[:=]\s*(?:true|True|1)\b|\b(?:APP_DEBUG|DEBUG)\s*=\s*(?:true|True|1)\b/, impact: 'Nếu dùng trong production, debug có thể lộ thông tin nội bộ hoặc chi tiết lỗi.', fix: 'Tắt debug trong production; kiểm tra môi trường triển khai thực tế.' },
  { id: 'SRC-HASH', cwe: 327, severity: 'low', title: 'Thuật toán hash yếu cần kiểm tra mục đích', match: /\b(?:md5|sha1)\s*\(|\bcreateHash\s*\(\s*["'](?:md5|sha1)["']/, impact: 'MD5/SHA-1 không phù hợp để lưu mật khẩu hoặc bảo vệ dữ liệu trước va chạm.', fix: 'Dùng Argon2id/scrypt cho mật khẩu; SHA-256 trở lên cho nhu cầu hash phù hợp. Checksum phi bảo mật có thể hợp lệ.' },
  { id: 'SRC-SECRET', cwe: 798, severity: 'high', title: 'Có thể chứa thông tin xác thực hardcode', secret: true, match: /(?:["']?\b(?:password|passwd|api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["'][^"'\r\n]{8,}["'])|(?:\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{24,}|sk_live_[A-Za-z0-9]{16,})\b)/i, impact: 'Nếu là credential thật, người có quyền đọc mã nguồn có thể sử dụng để truy cập tài nguyên.', fix: 'Xác minh credential; nếu thật, thu hồi/rotate và chuyển vào biến môi trường hoặc secret manager. Không chỉ xóa khỏi commit mới.' },
  { id: 'SRC-PRIVATE-KEY', cwe: 321, severity: 'high', title: 'Tệp có dấu hiệu chứa private key', secret: true, match: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/, impact: 'Private key được đưa vào mã nguồn có thể làm lộ danh tính hoặc quyền truy cập.', fix: 'Xác minh đây có phải key thật; nếu có, thay key/certificate và loại bỏ khỏi repo cùng lịch sử khi phù hợp.' }
];

rules.push(...EXTENDED_RULES, ...SCENARIO_RULES);
export const SOURCE_RULES = [...rules.map(({ id, title, cwe, severity, condition }) => ({ id, title, cwe: `CWE-${cwe}`, severity, condition })), ...FLOW_RULES];

function evidence(line, secret) {
  if (secret) return '[REDACTED: dấu hiệu credential/private key; mở vị trí trên máy để kiểm chứng]';
  return line.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`/g, '"[literal redacted]"')
    .replace(/\b[A-Za-z0-9_+/=-]{24,}\b/g, '[long value redacted]').trim().slice(0, 300);
}

function groupFlowFindings(findings) {
  const key = (file, line, cwe) => JSON.stringify([file, line, cwe]);
  const signatures = new Map();
  for (const finding of findings) {
    if (finding.detection?.method !== 'signature') continue;
    const location = key(finding.location.file, finding.location.line, finding.cwe);
    if (!signatures.has(location)) signatures.set(location, []);
    signatures.get(location).push(finding);
  }
  const attached = new Set();
  const grouped = findings.map((finding) => {
    if (!finding.trace?.length) return finding;
    const related = finding.trace.flatMap((step) => {
      const matches = signatures.get(key(step.file, step.line, finding.cwe)) ?? [];
      // A constructed SQL string is evidence for each distinct call that uses it.
      return step.role === 'sink' ? matches
        : matches.filter((match) => finding.ruleId === 'FLOW-SQL' && match.ruleId === 'SRC-SQL');
    });
    if (!related.length) return finding;
    for (const match of related) attached.add(match);
    const strongest = related.reduce((best, match) =>
      SEVERITIES.indexOf(match.severity) < SEVERITIES.indexOf(best.severity) ? match : best);
    return {
      ...finding,
      severity: SEVERITIES[Math.min(SEVERITIES.indexOf(finding.severity), SEVERITIES.indexOf(strongest.severity))],
      remediation: strongest.remediation,
      relatedRuleIds: [...new Set(related.map(({ ruleId }) => ruleId))],
      detection: {
        method: 'text-flow', condition: strongest.detection.condition,
        asvs: [...new Set(related.flatMap((match) => match.detection.asvs ?? []))],
      },
    };
  });
  return grouped.filter((finding) => !attached.has(finding));
}

export async function scanSource(input, options = {}) {
  const analysis = options.analysis ?? 'quick';
  if (!['quick', 'deep'].includes(analysis)) throw new Error('Chế độ quét mã nguồn không hợp lệ.');
  const deep = analysis === 'deep';
  const root = path.resolve(input);
  const rootStat = await lstat(root);
  if (rootStat.isSymbolicLink() || (!rootStat.isFile() && !rootStat.isDirectory())) throw new Error('Mục tiêu phải là file/thư mục thường, không phải symlink.');
  const base = rootStat.isDirectory() ? root : path.dirname(root);
  const report = createReport('source', root);
  const maxFiles = options.maxFiles ?? 2000;
  const maxFileBytes = options.maxFileBytes ?? 1024 * 1024;
  const customRules = options.customRules ?? [];
  const maxFindings = options.maxFindings ?? 5000;
  const excluded = new Set((options.excludePaths ?? []).map((p) => path.resolve(p)));
  const snapshot = corpusStats();
  report.stats = { filesScanned: 0, filesSkipped: 0, maxFiles, maxFileBytes, ruleCount: SOURCE_RULES.length + customRules.length, maxFindings, formats: {}, dependencyAnalysis: { packages: 0, unresolved: 0, unsupportedManifests: 0, unassessedRanges: 0, advisorySnapshot: snapshot.builtAt, advisoryCount: snapshot.advisories, supportedEcosystems: ['npm', 'pip'] }, corpus: snapshot };
  const sources = [];
  const maxDeepBytes = 20 * 1024 * 1024;
  let deepBytes = 0;
  if (deep) {
    if (customRules.length) throw new Error('Rule JSON bổ sung chỉ dùng với quét nhanh.');
    delete report.stats.dependencyAnalysis;
    report.stats.ruleCount = SEMGREP_RULE_COUNT;
    report.limitations[1] = 'Semgrep CE theo dõi dữ liệu trong từng hàm và so khớp các mẫu mã nguồn hoặc cấu hình đã khai báo. Cần kiểm chứng ngữ cảnh của vị trí được báo.';
  }
  let limitReached = false;

  async function visit(absolute) {
    if (excluded.has(absolute) || limitReached) return;
    const relative = path.relative(base, absolute).split(path.sep).join('/');
    let stat;
    try { stat = await lstat(absolute); }
    catch { report.errors.push(`Không đọc được metadata: ${relative}`); return; }
    if (stat.isSymbolicLink()) { report.stats.filesSkipped++; return; }
    if (stat.isDirectory()) {
      if (absolute !== root && SKIP.has(path.basename(absolute))) { report.stats.filesSkipped++; return; }
      let children;
      try { children = await readdir(absolute); }
      catch { report.errors.push(`Không đọc được thư mục: ${relative}`); return; }
      for (const child of children.sort()) await visit(path.join(absolute, child));
      return;
    }
    if (!stat.isFile()) return;
    const ext = path.extname(absolute).toLowerCase();
    const name = path.basename(absolute);
    const language = deep ? semgrepLanguage(absolute.split(path.sep).join('/')) : undefined;
    const supported = deep ? language : isSupportedSourceFile(absolute);
    if (!supported) { report.stats.filesSkipped++; return; }
    if (report.stats.filesScanned >= maxFiles) { limitReached = true; report.errors.push(`Đã chạm giới hạn ${maxFiles} file; còn dữ liệu chưa kiểm tra.`); return; }
    if (stat.size > maxFileBytes) { report.stats.filesSkipped++; report.errors.push(`File vượt giới hạn ${maxFileBytes} byte: ${relative}`); return; }
    let buffer;
    try { buffer = await readFile(absolute); }
    catch { report.errors.push(`Không đọc được file: ${relative}`); return; }
    if (buffer.includes(0)) { report.stats.filesSkipped++; return; }
    if (deep && buffer.length > maxFileBytes) {
      report.stats.filesSkipped++;
      report.errors.push(`File vượt giới hạn ${maxFileBytes} byte: ${relative}`);
      return;
    }
    if (deep && deepBytes + buffer.length > maxDeepBytes) {
      report.errors.push('Đã chạm giới hạn 20 MiB mã nguồn cho Semgrep; còn file chưa phân tích.');
      limitReached = true;
      return;
    }
    report.stats.filesScanned++;
    report.stats.formats[ext || name] = (report.stats.formats[ext || name] || 0) + 1;
    const text = buffer.toString('utf8');
    if (deep) {
      deepBytes += buffer.length;
      sources.push({ file: relative, text, language });
      return;
    }
    const lines = text.split(/\r?\n/);
    try {
      const inventory = extractDependencies(name, text);
      report.stats.dependencyAnalysis.packages += inventory.packages.length;
      report.stats.dependencyAnalysis.unresolved += inventory.unresolved;
      report.stats.dependencyAnalysis.unsupportedManifests += inventory.unsupported;
      const dependencies = dependencyFindings(inventory.packages, relative);
      report.stats.dependencyAnalysis.unassessedRanges += dependencies.unassessedRanges;
      report.findings.push(...dependencies.findings);
    } catch { report.errors.push(`Không đọc được dependency manifest hoặc cấu trúc JSON không hợp lệ: ${relative}`); }
    let inBlock = false;
    for (let index = 0; index < lines.length; index++) {
      const raw = lines[index];
      if (raw.length > 8192) {
        report.errors.push(`Dòng vượt giới hạn 8192 ký tự, chưa phân tích: ${relative}:${index + 1}`);
        continue;
      }
      const line = raw.trim();
      // Line-based comment handling is deliberately conservative; no language parser.
      const comment = inBlock || /^(?:\/\/|#|<!--|\/\*|\*)/.test(line);
      if (line.startsWith('/*') || line.startsWith('<!--')) inBlock = !line.includes('*/') && !line.includes('-->');
      if (line.includes('*/') || line.includes('-->')) inBlock = false;
      for (const custom of customRules) {
        if (comment || !custom.extensions.includes(ext)) continue;
        if (custom.containsAll?.length && !custom.containsAll.every((part) => raw.includes(part))) continue;
        if (custom.containsAny?.length && !custom.containsAny.some((part) => raw.includes(part))) continue;
        report.findings.push({ ruleId: custom.id, title: custom.title, severity: custom.severity, cwe: custom.cwe, confidence: 'low', status: 'needs-review', location: { file: relative, line: index + 1 }, evidence: evidence(raw, true), impact: custom.impact, remediation: custom.remediation, reference: custom.reference });
      }
      for (const rule of rules) {
        if (rule.id === 'SRC-EVAL' && ext !== '.py' && !/\beval\s*\(/.test(raw)) continue;
        let envSecret = false;
        if (rule.id === 'SRC-SECRET' && (name.startsWith('.env') || ['.ini', '.properties', '.conf', '.config'].includes(ext))) {
          const assignment = raw.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\s#"']+)/);
          envSecret = Boolean(assignment && /PASSWORD|PASSWD|API_KEY|SECRET|ACCESS_TOKEN|AUTH_TOKEN/i.test(assignment[1]) && assignment[2].length >= 8);
        }
        if ((comment && !rule.secret) || (rule.exts && !rule.exts.includes(ext)) || (!envSecret && !rule.match.test(raw))) continue;
        report.findings.push({
          ruleId: rule.id, title: rule.title, severity: rule.severity,
          confidence: rule.id === 'SRC-PRIVATE-KEY' ? 'high' : 'medium', status: 'needs-review', cwe: `CWE-${rule.cwe}`,
          location: { file: relative, line: index + 1 }, evidence: evidence(raw, rule.secret),
          impact: rule.impact, remediation: rule.fix, reference: ref(rule.cwe), detection: { method: 'signature', condition: rule.condition || 'Cần xác minh đầu vào, biện pháp bảo vệ và môi trường trước khi kết luận.', asvs: rule.asvs || [] }
        });
      }
      if (report.findings.length >= maxFindings) {
        report.findings.length = maxFindings;
        report.errors.push(`Đã chạm giới hạn ${maxFindings} phát hiện; dừng để giới hạn bộ nhớ.`);
        limitReached = true;
        break;
      }
    }
    if (!limitReached && ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.php'].includes(ext)) report.findings.push(...analyzeFlow(lines, relative));
    if (report.findings.length > maxFindings) {
      report.findings.length = maxFindings; limitReached = true;
      report.errors.push(`Đã chạm giới hạn ${maxFindings} phát hiện; còn phần chưa đánh giá.`);
    }
  }
  await visit(root);
  if (deep) {
    const result = sources.length
      ? await (options.semgrepRunner ?? runSemgrep)(sources)
      : { status: 'skipped', scanned: 0, findings: [], message: 'Không có file thuộc ngôn ngữ được hỗ trợ để phân tích sâu.' };
    report.findings = result.findings.slice(0, maxFindings);
    report.stats.sourceAnalysis = {
      mode: 'deep', engine: 'Semgrep', status: result.status, scanned: result.scanned,
      selected: sources.length, findings: report.findings.length, languages: result.languages ?? {},
    };
    if (result.message) report.errors.push(result.message);
    if (result.findings.length > maxFindings) report.errors.push(`Đã chạm giới hạn ${maxFindings} phát hiện; còn kết quả chưa hiển thị.`);
  } else {
    report.findings = groupFlowFindings(report.findings);
    if (!report.stats.filesScanned) report.errors.push('Không có file văn bản thuộc định dạng được hỗ trợ để phân tích.');
  }
  return finishReport(report);
}
