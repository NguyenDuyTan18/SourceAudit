const flowRules = [
  ['FLOW-SQL', 89, /(?:\bdb\.query|\bcursor\.execute|\.executeQuery)\s*\(/, 'Truy vấn nhận biến có nguồn từ request'],
  ['FLOW-EVAL', 95, /\beval\s*\(/, 'Code động nhận biến có nguồn từ request'],
  ['FLOW-SHELL', 78, /(?:\bexec|\bexecSync|\bos\.system|\bshell_exec|\bos\.popen)\s*\(/, 'Lệnh hệ thống nhận biến có nguồn từ request'],
  ['FLOW-SSRF', 918, /(?:\bfetch|\brequests\.get|\baxios\.get)\s*\(/, 'HTTP client nhận biến có nguồn từ request'],
  ['FLOW-PATH', 22, /(?:\breadFile|\breadFileSync|\bsendFile|\bfile_get_contents)\s*\(/, 'API file nhận biến có nguồn từ request'],
  ['FLOW-REDIRECT', 601, /(?:\bres\.redirect|\bHttpResponseRedirect)\s*\(/, 'Redirect nhận biến có nguồn từ request']
];
export const FLOW_RULES = flowRules.map(([id, cwe, , title]) => ({ id, cwe: `CWE-${cwe}`, title, severity: 'medium' }));
const words = (value) => value.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`/g, '').match(/\$?[A-Za-z_][A-Za-z0-9_]*/g) || [];
const stringsRemoved = (value) => value.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`/g, '"[literal redacted]"');
function firstArgument(value) {
  let quote = ''; let nesting = 0; let escaped = false;
  for (let i = 0; i < value.length; i++) {
    const ch = value[i];
    if (quote) { if (escaped) escaped = false; else if (ch === '\\') escaped = true; else if (ch === quote) quote = ''; continue; }
    if ('"\'`'.includes(ch)) { quote = ch; continue; }
    if ('([{'.includes(ch)) nesting++;
    if (')]}'.includes(ch)) { if (!nesting) return value.slice(0, i); nesting--; }
    if (ch === ',' && !nesting) return value.slice(0, i);
  }
  return value;
}
export function analyzeFlow(lines, file) {
  const tainted = new Map(); const findings = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (raw.length > 8192 || /^\s*(?:#|\/\/|\/\*|\*)/.test(raw)) continue;
    if (/^\s*(?:export\s+)?(?:function\b|(?:async\s+)?def\b|class\b)/.test(raw)) tainted.clear();
    for (const [name, record] of tainted) if (i - record.last > 12) tainted.delete(name);
    const assignment = raw.match(/^\s*(?:(?:const|let|var|final|String)\s+)?(\$?[A-Za-z_][A-Za-z0-9_]{0,79})\s*=\s*(?!=)(.*)/);
    if (assignment) {
      const [, name, expression] = assignment;
      const source = /\b(?:req\.(?:query|body|params)|request\.(?:args|GET|POST|form)|\$_(?:GET|POST|REQUEST))\b/.test(expression);
      const inherited = words(stringsRemoved(expression)).map((word) => tainted.get(word)).find(Boolean);
      if (source || inherited) {
        if (tainted.size >= 50) tainted.delete(tainted.keys().next().value);
        const step = { file, line: i + 1, role: source ? 'source' : 'propagation', evidence: stringsRemoved(raw).trim().slice(0, 300) };
        tainted.set(name, { last: i, trace: [...(source ? [] : inherited.trace), step].slice(-4) });
      } else tainted.delete(name);
    }
    for (const [id, cwe, pattern, title] of flowRules) {
      const match = pattern.exec(raw); if (!match) continue;
      const argument = stringsRemoved(firstArgument(raw.slice(match.index + match[0].length)));
      const record = words(argument).map((name) => tainted.get(name)).find(Boolean);
      if (!record || record.trace.some((step) => step.line === i + 1)) continue;
      findings.push({ ruleId: id, cwe: `CWE-${cwe}`, title, severity: 'medium', confidence: 'low', status: 'needs-review', location: { file, line: i + 1 },
        evidence: stringsRemoved(raw).trim().slice(0, 300), trace: [...record.trace, { file, line: i + 1, role: 'sink', evidence: stringsRemoved(raw).trim().slice(0, 300) }],
        impact: 'Theo dõi văn bản cục bộ cho thấy biến có nguồn từ request đi tới API nhạy cảm trong tối đa 12 dòng. Chưa phân tích AST, scope hoặc sanitizer đầy đủ; có thể báo nhầm.',
        remediation: 'Kiểm chứng luồng dữ liệu và biện pháp bảo vệ ở các dòng được đánh dấu; dùng API tham số hóa, allowlist hoặc encoding đúng ngữ cảnh.', reference: `https://cwe.mitre.org/data/definitions/${cwe}.html` });
    }
  }
  return findings;
}
