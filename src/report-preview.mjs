import { findingStatement, groupReportFindings, locationText, reportMode, scanModeLabel, SEVERITIES } from './report-findings.mjs';

const labels = { critical: 'Nghiêm trọng', high: 'Cao', medium: 'Trung bình', low: 'Thấp', info: 'Gợi ý' };
const title = 'Báo cáo đánh giá an toàn mã nguồn';
const issueLimit = 4;
const locationLimit = 2;
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));

function compact(value, size) {
  const text = String(value ?? '').replace(/\s+/g, ' ').trim();
  return text.length > size ? text.slice(0, size - 1) + '…' : text;
}

function edit(value, field, limit, edits, editable) {
  const text = escapeHtml(compact(edits[field] || value, limit));
  return editable ? `<span contenteditable="plaintext-only" data-a4-field="${field}" data-limit="${limit}">${text}</span>` : text;
}

function issueCard({ finding, occurrences }, index, edits, editable) {
  const severity = SEVERITIES.includes(finding.severity) ? finding.severity : 'info';
  const locations = occurrences.slice(0, locationLimit).map((item) => {
    const location = locationText(item.location);
    const shortLocation = location.length > 52 ? `…${location.slice(-51)}` : location;
    return `<li><code title="${escapeHtml(location)}">${escapeHtml(shortLocation)}</code><code>${escapeHtml(compact(findingStatement(item).replace(/^> \d+ \| /gm, ''), 145))}</code></li>`;
  }).join('');
  const extra = occurrences.length - locationLimit;
  return `<li class="a4-issue ${severity}"><div class="a4-issue-header"><span class="a4-badge">${labels[severity]}</span><h3>${escapeHtml(compact(finding.title, 95))}</h3><code>${escapeHtml(finding.ruleId)} · ${escapeHtml(finding.cwe)}</code></div>
    <ul class="a4-locations">${locations}</ul>${extra > 0 ? `<p class="a4-muted">${extra} vị trí khác trong báo cáo chi tiết.</p>` : ''}
    <p><strong>Ảnh hưởng</strong> ${edit(finding.impact, `impact-${index}`, 132, edits, editable)}</p>
    <p><strong>Hướng xử lý</strong> ${edit(finding.remediation, `fix-${index}`, 132, edits, editable)}</p></li>`;
}

export function renderA4Sheet(report, edits = {}, editable = false) {
  const groups = groupReportFindings(report.findings).sort((a, b) => SEVERITIES.indexOf(a.finding.severity) - SEVERITIES.indexOf(b.finding.severity));
  const count = (level) => groups.filter(({ finding }) => finding.severity === level).length;
  const stats = ['critical', 'high', 'medium', 'low'].map((level) => `<div class="${level}"><strong>${count(level) + (level === 'low' ? count('info') : 0)}</strong><span>${level === 'low' ? 'Thấp &amp; Gợi ý' : labels[level]}</span><i aria-hidden="true"></i></div>`).join('');
  const shown = groups.slice(0, issueLimit);
  const remaining = groups.length - shown.length;
  const date = new Date(report.startedAt);
  const scanned = Number(report.stats?.filesScanned) || 0;
  const complete = report.status === 'complete';
  const locations = groups.reduce((sum, group) => sum + group.occurrences.length, 0);
  return `<article id="a4-enduser-report" class="a4-sheet" aria-labelledby="a4-title">
    <header class="a4-banner"><div><div class="a4-brand"><span aria-hidden="true">S</span><div><h1 id="a4-title">${edit(title, 'title', 72, edits, editable)}</h1><p>${edit('Tóm tắt phát hiện và hướng xử lý cho người sử dụng', 'subtitle', 110, edits, editable)}</p></div></div>
    <div class="a4-meta"><span>Dự án <strong>${escapeHtml(compact(String(report.target ?? '').replace(/^Upload: /, ''), 55))}</strong></span><span>Ngày quét <strong>${Number.isNaN(date.valueOf()) ? '—' : escapeHtml(new Intl.DateTimeFormat('vi-VN').format(date))}</strong></span><span>Công cụ <strong>${scanModeLabel(reportMode(report))}</strong></span></div></div>
    <div class="a4-status ${complete ? '' : 'a4-partial'}"><span>Phạm vi quét</span><strong>${complete ? 'Đã hoàn tất' : 'Phạm vi chưa đầy đủ'}</strong><small>${scanned} tệp · ${locations} vị trí</small></div></header>
    <section class="a4-stats" aria-label="Phát hiện theo mức độ">${stats}</section>
    <section class="a4-findings" aria-labelledby="a4-findings-title"><div class="a4-heading"><h2 id="a4-findings-title">Các vấn đề cần chú ý</h2><span>${groups.length} nhóm phát hiện</span></div>
    ${shown.length ? `<ul class="a4-issues">${shown.map((group, index) => issueCard(group, index, edits, editable)).join('')}</ul>` : '<p class="a4-empty">Chưa ghi nhận phát hiện trong phần mã đã kiểm tra.</p>'}
    ${remaining ? `<p class="a4-remainder">${remaining} nhóm khác trong báo cáo chi tiết.</p>` : ''}</section>
    <section class="a4-actions" aria-labelledby="a4-actions-title"><h2 id="a4-actions-title">Kế hoạch xử lý</h2><div>
    <p><strong>Ưu tiên</strong>${count('critical') + count('high') ? 'Kiểm tra trước các mục nghiêm trọng và cao.' : 'Rà soát các mục theo mức độ và phạm vi ảnh hưởng.'}</p>
    <p><strong>Đối chiếu</strong>Kiểm tra đúng tệp, dòng và ngữ cảnh sử dụng.</p>
    <p><strong>Xác minh</strong>Quét lại sau khi sửa bằng cùng chế độ.</p></div></section>
    <footer class="a4-footer"><span>SrcAudit · Báo cáo tóm tắt</span><span>Trang 1 / 1</span></footer></article>`;
}

export function renderA4Document(report, stylesheet, edits) {
  return `<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>${escapeHtml(compact(edits?.title || title, 72))}</title><style>${stylesheet.replace(/<\/style/gi, '<\\/style')}</style></head><body class="a4-standalone">${renderA4Sheet(report, edits)}</body></html>`;
}
