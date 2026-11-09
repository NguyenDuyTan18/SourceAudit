import { readFile, mkdir, writeFile, readdir, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { SEVERITIES, safeUrl } from './report.mjs';
import { searchCorpus, relatedContext, verificationRequirements } from './corpus.mjs';

const academy = 'https://portswigger.net/web-security/';
const owasp = 'https://cheatsheetseries.owasp.org/cheatsheets/';
function topic(id, name, cwes, keywords, references, reviewSteps) {
  return { id, name, cwes, keywords, references, reviewSteps, reviewedAt: '2026-11-05', detection: 'Heuristic; phải kiểm chứng luồng dữ liệu và biện pháp bảo vệ trước khi kết luận.' };
}

export const KNOWLEDGE = [
  topic('sql-injection', 'SQL injection', ['CWE-89'], ['sql injection', 'sql_injection', 'sql-injection', 'sqli', 'parameterized queries', 'sql ghép chuỗi'], [owasp + 'SQL_Injection_Prevention_Cheat_Sheet.html'], ['Truy vết đầu vào đến API truy vấn.', 'Kiểm tra query có bind tham số hay chỉ nối chuỗi.', 'Phân biệt tên cột/bảng động với giá trị được bind.']),
  topic('xss', 'Cross-site scripting', ['CWE-79'], ['xss', 'cross-site scripting', 'cross_site_scripting', 'html injection', 'html_injection', 'html-injection', 'innerhtml', 'dangerouslysetinnerhtml'], [owasp + 'Cross_Site_Scripting_Prevention_Cheat_Sheet.html'], ['Xác định ngữ cảnh HTML/attribute/JavaScript của dữ liệu.', 'Kiểm tra output encoding hoặc sanitizer trước sink.', 'Không kết luận có XSS chỉ vì thiếu CSP.']),
  topic('command-injection', 'OS command injection', ['CWE-78', 'CWE-95'], ['command injection', 'shell injection', 'shell_exec', 'code injection'], [owasp + 'OS_Command_Injection_Defense_Cheat_Sheet.html'], ['Kiểm tra API có qua shell hay truyền argv trực tiếp.', 'Truy vết biến đầu vào và allowlist lệnh/tham số.']),
  topic('ssrf', 'Server-side request forgery', ['CWE-918'], ['ssrf', 'server-side request forgery', 'server side request forgery'], [academy + 'ssrf', owasp + 'Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'], ['Kiểm tra URL do người dùng kiểm soát có đi vào HTTP client.', 'Đánh giá scheme, DNS/IP, redirect và outbound network policy.', 'Đầu vào là URL không tự chứng minh có SSRF.']),
  topic('path-traversal', 'Path traversal / file access', ['CWE-22'], ['path traversal', 'directory traversal', 'sendfile', 'readfile'], [academy + 'file-path-traversal'], ['Kiểm tra đường dẫn sau resolve/canonicalization còn trong thư mục cho phép.', 'Kiểm tra symlink, root và quyền đọc file.']),
  topic('deserialization', 'Unsafe deserialization', ['CWE-502'], ['deserialization', 'deserialize', 'pickle', 'unserialize', 'yaml.load'], [owasp + 'Deserialization_Cheat_Sheet.html'], ['Xác định nguồn dữ liệu có đáng tin cậy.', 'Kiểm tra API/loader và kiểu đối tượng có thể tạo.', 'Ưu tiên định dạng dữ liệu đơn giản có schema.']),
  topic('ssti', 'Server-side template injection', ['CWE-1336'], ['ssti', 'template injection', 'render_template_string'], [academy + 'server-side-template-injection'], ['Phân biệt dữ liệu truyền vào template với dữ liệu tạo thành mã template.', 'Xác định engine và cơ chế escape/sandbox trước khi kết luận.']),
  topic('prototype-pollution', 'Prototype pollution', ['CWE-1321'], ['prototype pollution', '__proto__', 'prototype-pollution'], [academy + 'prototype-pollution', 'https://portswigger.net/research/server-side-prototype-pollution'], ['Kiểm tra thao tác merge/gán key động nhận dữ liệu ngoài.', 'Đánh giá xử lý __proto__, constructor, prototype và object không có prototype.', 'Không chạy probe có thể gây DoS để tự xác nhận.']),
  topic('xxe', 'XML external entity', ['CWE-611'], ['xxe', 'external entity', 'resolve_entities'], [academy + 'xxe'], ['Kiểm tra cấu hình XML parser có cho DTD/external entity.', 'Đánh giá network/file access của parser; cấu hình thư viện theo phiên bản.']),
  topic('jwt', 'JWT signature validation', ['CWE-347'], ['jwt', 'json web token', 'verify_signature'], [academy + 'jwt'], ['Kiểm tra có xác minh chữ ký và allowlist thuật toán.', 'Kiểm tra issuer, audience, thời hạn; decode không tương đương verify.']),
  topic('secrets', 'Embedded credentials / private keys', ['CWE-798', 'CWE-321'], ['hardcoded secret', 'credential', 'private key', 'api key'], [owasp + 'Secrets_Management_Cheat_Sheet.html'], ['Xác minh chuỗi là credential thật hay fixture.', 'Nếu thật: revoke/rotate, kiểm tra lịch sử và quyền truy cập.']),
  topic('access-control', 'Broken access control / IDOR', ['CWE-639', 'CWE-862'], ['idor', 'bola', 'access control', 'authorization'], [academy + 'access-control'], ['Cần ít nhất hai danh tính và dữ liệu được phép kiểm thử.', 'Kiểm tra quyền ở server trên từng đối tượng/hành động.', 'Tool hiện chỉ cung cấp hướng kiểm tra; không tự xác nhận IDOR từ URL.'])
];

export function searchKnowledge(query = '') {
  const needle = query.toLowerCase().trim();
  return [...KNOWLEDGE.filter((entry) => !needle || [entry.id, entry.name, ...entry.cwes, ...entry.keywords].join(' ').toLowerCase().includes(needle)), ...searchCorpus(needle).results];
}

async function readBounded(file, maxBytes = 1024 * 1024) {
  const info = await stat(file);
  if (!info.isFile() || info.size > maxBytes) throw new Error('Input phải là file văn bản tối đa 1 MiB.');
  const text = await readFile(file, 'utf8');
  if (text.includes('\0')) throw new Error('Không nhận file binary.');
  return text;
}

export async function importWriteup(file, directory) {
  if (!['.md', '.txt'].includes(path.extname(file).toLowerCase())) throw new Error('Write-up phải là .md hoặc .txt.');
  const text = await readBounded(file);
  const lower = text.toLowerCase();
  const topics = KNOWLEDGE.filter((entry) => entry.keywords.some((keyword) => lower.includes(keyword))).map((entry) => entry.id);
  const references = [];
  for (const match of text.matchAll(/https:\/\/[^\s<>"')\]]+/g)) {
    try {
      // Remove URL query and fragment entirely; preserve no embedded credentials.
      const url = new URL(match[0]);
      if (url.username || url.password) continue;
      url.search = ''; url.hash = '';
      if (!references.includes(url.href)) references.push(url.href);
      if (references.length >= 30) break;
    } catch { /* Ignore malformed references. Never fetch them. */ }
  }
  const digest = createHash('sha256').update(text).digest('hex');
  const entry = { id: digest.slice(0, 16), sha256: digest, importedAt: new Date().toISOString(), topics, references, note: 'Chỉ lưu topic và URL tham khảo, không lưu nội dung gốc. Topic không tạo rule mới và không xác nhận lỗ hổng.' };
  await mkdir(directory, { recursive: true });
  const output = path.resolve(directory, `writeup-${entry.id}.json`);
  await writeFile(output, JSON.stringify(entry, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
  return { ...entry, file: output };
}

export async function loadWriteups(directory) {
  const entries = [];
  if (!directory) return entries;
  for (const name of (await readdir(directory)).filter((n) => /^writeup-[a-f0-9]{16}\.json$/.test(n)).slice(0, 200)) {
    const entry = JSON.parse(await readBounded(path.join(directory, name)));
    if (!Array.isArray(entry.topics) || !Array.isArray(entry.references) || entry.topics.some((id) => !KNOWLEDGE.some((k) => k.id === id))) throw new Error('Write-up index không hợp lệ.');
    entries.push({ id: name, topics: entry.topics, references: entry.references.filter((url) => typeof url === 'string' && /^https:\/\//.test(url)).slice(0, 30).map(safeUrl) });
  }
  return entries;
}

export function enrichReport(report, writeups = []) {
  for (const finding of report.findings) {
    const entry = KNOWLEDGE.find((item) => item.cwes.includes(finding.cwe));
    const context = relatedContext(finding.cwe);
    if (!entry && !context.weakness) continue;
    finding.knowledge = { topic: entry?.id || finding.cwe,
      references: [...new Set([...(entry?.references || []), ...(context.weakness?.references || []), ...context.tests.flatMap((item) => item.references), ...verificationRequirements(finding.detection?.asvs || []).flatMap((item) => item.references), ...context.apiScenarios.flatMap((item) => item.references)])],
      reviewSteps: entry?.reviewSteps || context.weakness?.mitigations?.slice(0, 3) || ['Kiểm chứng điều kiện CWE trong source và môi trường triển khai.'],
      cweContext: context.weakness ? { name: context.weakness.name, description: context.weakness.description, consequences: context.weakness.consequences, abstraction: context.weakness.abstraction } : undefined,
      owaspTests: context.tests.map(({ id, name, references }) => ({ id, name, references })),
      verificationRequirements: verificationRequirements(finding.detection?.asvs || []).map(({ id, description, references, level }) => ({ id, description, references, level })),
      apiScenarios: context.apiScenarios.map(({ id, name, references }) => ({ id, name, references })),
      advisoryExamples: context.examples.map(({ id, cve, name, references }) => ({ id, cve, name, references: references.slice(0, 1), role: 'context-only-not-a-match' })),
      relatedWriteups: writeups.filter((w) => entry && w.topics.includes(entry.id)).map((w) => ({ id: w.id, references: w.references })) };
  }
  return report;
}

export async function loadCustomRules(file) {
  const data = JSON.parse(await readBounded(file));
  if (!Array.isArray(data) || data.length > 100) throw new Error('Rule pack phải là JSON array tối đa 100 rule.');
  const ids = new Set();
  return data.map((rule) => {
    const allowedKeys = ['id', 'title', 'severity', 'cwe', 'extensions', 'containsAll', 'containsAny', 'impact', 'remediation', 'reference'];
    if (Object.keys(rule).some((key) => !allowedKeys.includes(key))) throw new Error('Rule chứa trường không hỗ trợ; chỉ nhận literal, không nhận regex/code.');
    if (!/^CUSTOM-[A-Z0-9-]{1,50}$/.test(rule.id) || ids.has(rule.id)) throw new Error('Rule id phải duy nhất, bắt đầu CUSTOM-.');
    ids.add(rule.id);
    for (const field of ['title', 'impact', 'remediation', 'reference']) if (typeof rule[field] !== 'string' || !rule[field].trim() || rule[field].length > 1500) throw new Error(`Rule thiếu/sai trường ${field}.`);
    if (!SEVERITIES.includes(rule.severity) || !/^CWE-\d{1,5}$/.test(rule.cwe)) throw new Error('Severity hoặc CWE không hợp lệ.');
    if (!Array.isArray(rule.extensions) || !rule.extensions.length || rule.extensions.length > 30 || rule.extensions.some((ext) => !/^\.[a-z0-9]{1,10}$/.test(ext))) throw new Error('Extensions không hợp lệ.');
    for (const key of ['containsAll', 'containsAny']) {
      if (rule[key] !== undefined && (!Array.isArray(rule[key]) || rule[key].length > 20 || rule[key].some((value) => typeof value !== 'string' || !value.length || value.length > 200))) throw new Error('Pattern phải là danh sách chuỗi ngắn.');
    }
    if (!(rule.containsAll?.length || rule.containsAny?.length)) throw new Error('Cần ít nhất một literal pattern.');
    const reference = new URL(rule.reference);
    if (reference.protocol !== 'https:' || reference.username || reference.password) throw new Error('Reference phải là URL HTTPS không chứa credential.');
    return { ...rule, reference: safeUrl(reference) };
  });
}
