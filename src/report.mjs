import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export function safeUrl(input) {
  const url = new URL(input);
  url.username = ''; url.password = ''; url.hash = '';
  for (const key of [...url.searchParams.keys()]) url.searchParams.set(key, '[REDACTED]');
  return url.href;
}

export function createReport(mode, target) {
  return {
    tool: 'SrcAudit — Static Source Scanner', version: '1.0.0',
    startedAt: new Date().toISOString(), mode, target, status: 'complete',
    findings: [], errors: [], stats: {},
    limitations: [
      'Không có phát hiện không đồng nghĩa với không có lỗ hổng.',
      'Phân tích signature và luồng văn bản cục bộ (không phải AST/taint đầy đủ); đối chiếu npm/PyPI với snapshot advisory offline cho manifest được hỗ trợ. Chưa xác minh khả năng khai thác. Có thể có dương tính/âm tính giả và advisory chưa được thu thập.',
      'Mức độ là đánh giá sơ bộ theo rule, không phải điểm CVSS đã xác nhận.'
    ]
  };
}

export function finishReport(report) {
  report.finishedAt = new Date().toISOString();
  report.findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  report.summary = Object.fromEntries(SEVERITIES.map((level) => [level, report.findings.filter((f) => f.severity === level).length]));
  if (report.errors.length) report.status = report.stats.filesScanned ? 'partial' : 'failed';
  return report;
}

export function locationText(location) {
  if (location.url) return location.url;
  if (location.line) {
    const start = `${location.file}:${location.line}${location.column ? ':' + location.column : ''}`;
    return location.endLine ? `${start}–${location.endLine}:${location.endColumn}` : start;
  }
  return location.file + (location.pointer ? ' #' + location.pointer : '');
}

export function renderText(report) {
  const lines = [report.tool, `Mục tiêu: ${report.target}`, `Chế độ: ${report.mode} | Trạng thái: ${report.status}`, `Phát hiện: ${report.findings.length}`, ''];
  if (report.stats.sourceAnalysis) {
    const { status, scanned, selected, findings, languages } = report.stats.sourceAnalysis;
    lines.push(`Phân tích sâu bằng Semgrep · ${status} · ${scanned}/${selected} file · ${findings} phát hiện`);
    const counts = Object.entries(languages ?? {}).map(([name, count]) => `${name}: ${count.scanned}/${count.selected}`);
    if (counts.length) lines.push('Theo ngôn ngữ: ' + counts.join(' · '));
    lines.push('');
  }
  for (const [index, f] of report.findings.entries()) {
    lines.push(`${index + 1}. [${f.severity.toUpperCase()}] ${f.title} (${f.ruleId})`,
      `   Vị trí: ${locationText(f.location)}`, `   Phân loại: ${f.cwe} | Tin cậy: ${f.confidence} | Kết luận: ${f.status}`,
      `   Bằng chứng: ${f.evidence}`, `   Tác động: ${f.impact}`, `   Cách sửa: ${f.remediation}`, `   Tham khảo: ${f.reference}`);
    if (f.sourceExcerpt) lines.push('   Mã tại vị trí phát hiện (đã che):', f.sourceExcerpt);
    if (f.relatedRuleIds?.length) lines.push('   Quy tắc liên quan: ' + f.relatedRuleIds.join(', '));
    if (f.knowledge) lines.push('   Các bước kiểm chứng:', ...f.knowledge.reviewSteps.map((s) => `     - ${s}`), ...f.knowledge.references.map((s) => `   Nguồn: ${s}`), ...f.knowledge.relatedWriteups.map((w) => `   Write-up liên quan: ${w.id} ${w.references.join(' ')}`));
    if (f.knowledge?.cweContext) lines.push(`   Ngữ cảnh CWE: ${f.knowledge.cweContext.name}: ${f.knowledge.cweContext.description}`);
    if (f.knowledge?.owaspTests?.length) lines.push(`   OWASP: ${f.knowledge.owaspTests.map((entry) => entry.id + ': ' + entry.name).join('; ')}`);
    if (f.detection) lines.push(`   Điều kiện áp dụng: ${f.detection.condition}`);
    if (f.trace) lines.push('   Dòng liên quan (luồng văn bản cần kiểm chứng):', ...f.trace.map((step) => `     ${step.file}:${step.line} [${step.role}] ${step.evidence}`));
    if (f.advisory) lines.push(`   Advisory: ${f.advisory.id} | ${f.advisory.cve || 'chưa có CVE'} | ${f.advisory.package}@${f.advisory.version}`, `   Phạm vi ảnh hưởng: ${f.advisory.affectedRange} | Bản vá: ${f.advisory.fixed || 'chưa nêu'}`, '   Khớp phiên bản không đồng nghĩa xác nhận khai thác được.');
    if (f.advisory?.kev) lines.push(`   CISA KEV: ${f.advisory.kev.scope} Ngày thêm: ${f.advisory.kev.dateAdded}`);
    if (f.knowledge?.verificationRequirements?.length) lines.push('   Yêu cầu ASVS:', ...f.knowledge.verificationRequirements.map((entry) => `     ${entry.id} [L${entry.level}]: ${entry.description}`));
    if (f.knowledge?.apiScenarios?.length) lines.push('   Kịch bản API Security:', ...f.knowledge.apiScenarios.map((entry) => `     ${entry.id}: ${entry.name}`));
    lines.push('');
  }
  if (!report.findings.length) lines.push('Không phát hiện mẫu rủi ro trong phạm vi đã kiểm tra.', '');
  if (report.errors.length) lines.push('Phần chưa kiểm tra được / bị bỏ qua:', ...report.errors.map((e) => `- ${e}`), '');
  lines.push('Giới hạn:', ...report.limitations.map((s) => `- ${s}`));
  return lines.join('\n');
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

function contextRows(finding) {
  const rows = [];
  if (finding.relatedRuleIds?.length) rows.push(['Quy tắc liên quan', finding.relatedRuleIds.join(', ')]);
  if (finding.advisory?.kev) rows.push(['CISA KEV', `${finding.advisory.kev.scope}\nNgày thêm: ${finding.advisory.kev.dateAdded}`]);
  if (finding.knowledge?.verificationRequirements?.length) rows.push(['Yêu cầu ASVS', finding.knowledge.verificationRequirements.map((entry) => `${entry.id} [L${entry.level}] ${entry.description}`).join('\n')]);
  if (finding.knowledge?.apiScenarios?.length) rows.push(['Kịch bản API Security', finding.knowledge.apiScenarios.map((entry) => `${entry.id}: ${entry.name}`).join('\n')]);
  if (finding.knowledge?.cweContext) rows.push(['Ngữ cảnh CWE', `${finding.knowledge.cweContext.name}\n${finding.knowledge.cweContext.description}`]);
  return rows;
}

export function renderHtml(report) {
  const e = escapeHtml;
  const cards = report.findings.map((f) => `<article class="${e(f.severity)}"><h2><span>${e(f.severity.toUpperCase())}</span> ${e(f.title)}</h2><p><strong>${e(f.ruleId)} · ${e(f.cwe)}</strong></p><dl>${[
    ['Vị trí', locationText(f.location)], ['Độ tin cậy', f.confidence], ['Kết luận', f.status], ['Bằng chứng', f.evidence], ['Tác động', f.impact], ['Cách khắc phục', f.remediation], ['Tham khảo', f.reference], ...(f.detection ? [['Điều kiện áp dụng', f.detection.condition]] : []), ...(f.trace ? [['Dòng liên quan (luồng văn bản cần kiểm chứng)', f.trace.map((step) => `${step.file}:${step.line} [${step.role}] ${step.evidence}`).join('\n')]] : []), ...(f.advisory ? [['CVE / GHSA', `${f.advisory.cve || ''} ${f.advisory.id}`], ['Dependency', `${f.advisory.ecosystem} ${f.advisory.package}@${f.advisory.version}`], ['Ảnh hưởng / bản vá', `${f.advisory.affectedRange} / ${f.advisory.fixed || 'chưa nêu'}`], ['Ngữ cảnh advisory', f.advisory.description]] : []), ...(f.knowledge ? [['Kiểm chứng', f.knowledge.reviewSteps.join('\n')], ['Nguồn bổ sung', f.knowledge.references.join('\n')], ['Write-up đã nạp', f.knowledge.relatedWriteups.map((w) => w.id + ': ' + w.references.join(', ')).join('\n') || 'Chưa có']] : [])
  , ...(f.sourceExcerpt ? [['Mã tại vị trí phát hiện (đã che)', f.sourceExcerpt]] : []), ...contextRows(f)].map(([k, v]) => `<dt>${e(k)}</dt><dd><pre>${e(v)}</pre></dd>`).join('')}</dl></article>`).join('');
  return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>SrcAudit — Báo cáo bảo mật</title><style>body{font:16px/1.6 system-ui,sans-serif;background:#0c1220;color:#e6edf7;max-width:1100px;margin:36px auto;padding:0 24px}h1{font-size:32px}h2{font-size:21px}article,section{background:#152037;padding:22px;margin:18px 0;border-radius:12px;border-left:5px solid #60728e}article.critical,article.high{border-color:#ff737b}article.medium{border-color:#eab45c}article.low{border-color:#70b6ff}span{font-size:13px;color:#eab45c}dt{font-weight:bold;color:#a9c3e9;margin-top:10px}dd{margin-left:0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;margin:0}small{color:#a4b5cf}</style></head><body><h1>Báo cáo kiểm tra bảo mật</h1><p>SrcAudit</p><p><strong>${e(report.target)}</strong></p><p>${e(report.mode)} · ${e(report.status)} · ${report.findings.length} phát hiện</p><small>${e(report.startedAt)}</small>${cards || '<section>Không phát hiện mẫu rủi ro trong phạm vi đã kiểm tra.</section>'}<section><h2>Phạm vi</h2><pre>${e(JSON.stringify(report.stats, null, 2))}</pre></section>${report.errors.length ? `<section><h2>Phần chưa kiểm tra được</h2><ul>${report.errors.map((s) => `<li>${e(s)}</li>`).join('')}</ul></section>` : ''}<section><h2>Giới hạn</h2><ul>${report.limitations.map((s) => `<li>${e(s)}</li>`).join('')}</ul></section></body></html>`;
}

export async function writeReports(report, outDir) {
  await mkdir(outDir, { recursive: true });
  const files = { json: path.resolve(outDir, 'report.json'), html: path.resolve(outDir, 'report.html'), text: path.resolve(outDir, 'report.txt') };
  await writeFile(files.json, JSON.stringify(report, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
  await writeFile(files.html, renderHtml(report), { encoding: 'utf8', mode: 0o600 });
  await writeFile(files.text, renderText(report) + '\n', { encoding: 'utf8', mode: 0o600 });
  return files;
}
