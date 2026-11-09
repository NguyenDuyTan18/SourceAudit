const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const token = $('meta[name="session-token"]').content;
const levels = ['critical', 'high', 'medium', 'low', 'info'];
const names = { critical: 'Nghiêm trọng', high: 'Cao', medium: 'Trung bình', low: 'Thấp', info: 'Thông tin' };
const state = { job: null, selected: null, busy: false, ready: false, knowledgePage: 1, knowledgeRequest: 0, folderFiles: [] };
const uploadLimit = 20 * 1024 * 1024;
const sourceExtensions = new Set();
const ignoredFolders = new Set(['node_modules', '.git', '.svn', '.venv', 'venv', 'vendor', 'dist', 'build', 'coverage', '.next', '__pycache__', '.scanner-reports', '.scanner-tools', '.scanner-auth']);

function element(tag, className, text) {
  const result = document.createElement(tag);
  if (className) result.className = className;
  if (text !== undefined) result.textContent = String(text);
  return result;
}
function message(text) {
  $('#global-message').textContent = text || '';
  $('#global-message').hidden = !text;
}
async function api(route, data) {
  let response;
  try {
    response = await fetch(route, { method: data === undefined ? 'GET' : 'POST', headers: { 'X-Session-Token': token, ...(data === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
  } catch {
    throw new Error('Không kết nối được với SrcAudit. Kiểm tra ứng dụng đang chạy rồi tải lại trang.');
  }
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const hints = {
      401: 'Phiên đăng nhập đã hết hạn. Hãy tải lại trang và đăng nhập.',
      403: 'Phiên giao diện không hợp lệ. Hãy mở lại SrcAudit hoặc tải lại trang.',
      413: 'Tệp gửi lên vượt giới hạn. Hãy giảm kích thước ZIP hoặc chọn thư mục nhỏ hơn.',
    };
    throw new Error(hints[response.status] || body?.error || `SrcAudit không xử lý được yêu cầu (HTTP ${response.status}).`);
  }
  if (!body) throw new Error('SrcAudit trả về phản hồi không hợp lệ. Hãy tải lại trang.');
  return body;
}
function setBusy(value) {
  state.busy = value;
  const disabled = value || !state.ready;
  $('#scan-button').disabled = disabled;
  $('#source-upload').disabled = disabled;
  $('#source-analysis-options').disabled = disabled;
  $('#scan-progress').hidden = !value;
  $('#scan-action').textContent = value ? 'Đang xử lý…' : 'Bắt đầu kiểm tra';
  if (value) $('#scan-stage').textContent = 'Đang chuẩn bị lượt quét…';
}
function setScanReadiness(status, text) {
  const badge = $('#scan-readiness');
  badge.dataset.state = status;
  badge.textContent = text;
}
function showView(view) {
  $$('.view').forEach((section) => { section.hidden = section.id !== `view-${view}`; });
  $$('.nav-item').forEach((button) => {
    const active = button.dataset.view === view;
    button.classList.toggle('active', active);
    if (active) { button.setAttribute('aria-current', 'page'); $('#breadcrumb-current').textContent = button.textContent.trim(); }
    else button.removeAttribute('aria-current');
  });
  if (view === 'history') loadHistory().catch((error) => message(error.message));
  if (view === 'users') loadUsers().catch((error) => message(error.message));
}
function updateSourceAnalysis() {
  const deep = $('#source-analysis').value === 'deep';
  $('#source-analysis-help').textContent = deep
    ? 'Theo dõi luồng dữ liệu từ request tới API nhạy cảm trong JavaScript, TypeScript, Python, PHP, Java, Go và C#.'
    : 'Dò mẫu mã nguồn, cấu hình và phiên bản thư viện.';
  $('#scan-scope').textContent = deep ? 'Semgrep · 8 ngôn ngữ và cấu hình · Xử lý trên máy' : 'Phân tích tĩnh · Xử lý trên máy';
}
function updateZipSelection(event) {
  const input = event.currentTarget;
  const file = input.files[0];
  message('');
  if (file && (!/\.zip$/i.test(file.name) || !file.size || file.size > uploadLimit)) {
    message('Chọn một tệp .zip có dung lượng tối đa 20 MiB.');
    input.value = '';
  }
  $('#source-selection').textContent = input.files.length
    ? file.name + ' · ' + (file.size / (1024 * 1024)).toFixed(2) + ' MiB'
    : 'Chưa chọn tệp ZIP.';
}
function updateFolderSelection() {
  message('');
  const input = $('#source-folder');
  state.folderFiles = [];
  $('#source-selection').textContent = 'Chưa chọn thư mục mã nguồn.';
  if (!input.files.length) return;
  const root = input.files[0].webkitRelativePath.split('/')[0];
  const files = [];
  let bytes = 0;
  try {
    for (const file of input.files) {
      const parts = file.webkitRelativePath.split('/');
      if (parts.length < 2 || parts[0] !== root) throw new Error('Chọn một thư mục mã nguồn.');
      if (parts.slice(0, -1).some((part) => ignoredFolders.has(part.toLowerCase()))) continue;
      const dot = file.name.lastIndexOf('.');
      const knownExtension = dot > 0 && sourceExtensions.has(file.name.slice(dot).toLowerCase());
      if (!knownExtension && !file.name.startsWith('.env') && file.name !== 'Dockerfile' &&
          !/^requirements(?:[.-].*)?\.txt$/i.test(file.name)) continue;
      if (file.size > 1024 * 1024) throw new Error(`Tệp ${file.webkitRelativePath} vượt giới hạn 1 MiB.`);
      bytes += file.size;
      files.push(file);
      if (files.length > 2000 || bytes > uploadLimit) throw new Error('Chọn thư mục có tối đa 2.000 tệp mã nguồn và tổng dung lượng tối đa 20 MiB.');
    }
    if (!files.length) throw new Error('Thư mục không có tệp mã nguồn được hỗ trợ.');
    state.folderFiles = files;
    const ignored = input.files.length - files.length;
    $('#source-selection').textContent = `${root} · ${files.length} tệp · ${(bytes / 1024 / 1024).toFixed(2)} MiB` +
      (ignored ? ` · Đã bỏ qua ${ignored} tệp` : '');
  } catch (error) {
    input.value = '';
    message(error.message);
  }
}
function updateUploadKind() {
  const folder = $('#upload-kind-folder').checked;
  $('#zip-picker').hidden = folder;
  $('#folder-picker').hidden = !folder;
  $('#source-zip').disabled = folder;
  $('#source-zip').required = !folder;
  $('#source-folder').disabled = !folder;
  $('#source-folder').required = folder;
  if (folder) updateFolderSelection();
  else updateZipSelection({ currentTarget: $('#source-zip') });
}
async function zipFolder(files) {
  const { zipSync } = await import('/fflate-browser.js');
  const entries = Object.create(null);
  for (const file of files) {
    const relative = file.webkitRelativePath;
    if (Object.hasOwn(entries, relative)) throw new Error('Thư mục có hai tệp trùng đường dẫn.');
    entries[relative] = new Uint8Array(await file.arrayBuffer());
  }
  const archive = new Blob([zipSync(entries, { level: 1 })], { type: 'application/zip' });
  if (archive.size > uploadLimit) throw new Error('ZIP tạo từ thư mục vượt giới hạn 20 MiB.');
  return archive;
}
function fileBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(',')[1]);
    reader.onerror = () => reject(new Error('Không đọc được file đã chọn.'));
    reader.readAsDataURL(file);
  });
}
function field(container, title, text, code = false) {
  const section = element('div', 'detail-field');
  section.append(element('h4', '', title), element(code ? 'pre' : 'p', '', text));
  container.append(section);
  return section;
}
function locationOf(finding) {
  const { file, line, column, endLine, endColumn, pointer } = finding.location;
  if (line) {
    const start = `${file}:${line}${column ? ':' + column : ''}`;
    return endLine ? `${start}–${endLine}:${endColumn}` : start;
  }
  return file + (pointer ? ' #' + pointer : '');
}
function renderDetail(finding) {
  const container = $('#finding-detail'); container.replaceChildren();
  if (!finding) { container.append(element('p', 'no-match', 'Chọn một phát hiện để xem chi tiết.')); return; }
  const badge = element('span', `severity-chip ${finding.severity}`, names[finding.severity]);
  container.append(badge, element('h3', '', finding.title));
  const meta = element('div', 'detail-meta');
  meta.append(element('span', 'rule-id', `${finding.ruleId} · ${finding.cwe}`), element('span', '', `Tin cậy: ${names[finding.confidence] || finding.confidence}`), element('span', '', finding.status === 'observed' ? 'Cấu hình đã quan sát' : finding.status === 'version-match' ? 'Khớp phiên bản advisory; chưa xác minh khai thác' : 'Cần kiểm chứng'));
  container.append(meta);
  field(container, 'VỊ TRÍ CẦN KIỂM TRA', locationOf(finding), true);
  field(container, 'CÁCH KHẮC PHỤC', finding.remediation);
  if (finding.sourceExcerpt) field(container, 'MÃ TẠI VỊ TRÍ PHÁT HIỆN (ĐÃ CHE)', finding.sourceExcerpt, true);
  if (finding.relatedRuleIds?.length) field(container, 'QUY TẮC LIÊN QUAN', finding.relatedRuleIds.join(', '));
  field(container, 'BẰNG CHỨNG', finding.evidence, true);
  field(container, 'TÁC ĐỘNG TIỀM NĂNG', finding.impact);
  if (finding.detection) field(container, 'ĐIỀU KIỆN ÁP DỤNG', finding.detection.condition);
  if (finding.trace) {
    const roles = { source: 'Đầu vào', propagation: 'Truyền dữ liệu', sink: 'Điểm sử dụng' };
    field(container, 'DÒNG LIÊN QUAN', finding.trace.map((step) =>
      `${step.file}:${step.line} [${roles[step.role] || step.role}] ${step.evidence}`).join('\n'), true);
  }
  if (finding.advisory) {
    field(container, 'CVE / GHSA', `${finding.advisory.cve || 'Chưa có CVE'} · ${finding.advisory.id}`);
    field(container, 'PACKAGE / PHIÊN BẢN / PHẠM VI', `${finding.advisory.ecosystem} ${finding.advisory.package}@${finding.advisory.version}\nẢnh hưởng: ${finding.advisory.affectedRange}\nBản vá theo advisory: ${finding.advisory.fixed || 'Chưa nêu'}`, true);
    field(container, 'NGỮ CẢNH ADVISORY', finding.advisory.description);
    if (finding.advisory.kev) field(container, 'CISA KEV — LỊCH SỬ KHAI THÁC CÔNG KHAI', `${finding.advisory.kev.scope}\nNgày được thêm vào catalog: ${finding.advisory.kev.dateAdded}`);
  }
  if (finding.knowledge) {
    if (finding.knowledge.cweContext) field(container, 'NGỮ CẢNH CWE', `${finding.knowledge.cweContext.name}\n${finding.knowledge.cweContext.description}`);
    if (finding.knowledge.owaspTests?.length) field(container, 'KIỂM THỬ OWASP LIÊN QUAN', finding.knowledge.owaspTests.map((entry) => `${entry.id}: ${entry.name}`).join('\n'));
    if (finding.knowledge.verificationRequirements?.length) field(container, 'YÊU CẦU XÁC MINH ASVS', finding.knowledge.verificationRequirements.map((entry) => `${entry.id} · L${entry.level}\n${entry.description}`).join('\n\n'));
    if (finding.knowledge.apiScenarios?.length) field(container, 'KỊCH BẢN API SECURITY LIÊN QUAN', finding.knowledge.apiScenarios.map((entry) => `${entry.id}: ${entry.name}`).join('\n'));
    const section = element('div', 'detail-field'); section.append(element('h4', '', 'CÁC BƯỚC KIỂM CHỨNG'));
    const list = element('ul'); finding.knowledge.reviewSteps.forEach((step) => list.append(element('li', '', step)));
    section.append(list); container.append(section);
    if (finding.knowledge.relatedWriteups.length) field(container, 'WRITE-UP ĐÃ LIÊN KẾT', `${finding.knowledge.relatedWriteups.length} ghi chú đã nhập thuộc nhóm ${finding.knowledge.topic}.`);
    if (finding.knowledge.advisoryExamples?.length) field(container, 'VÍ DỤ CÙNG CWE — CHỈ LÀ NGỮ CẢNH', finding.knowledge.advisoryExamples.map((entry) => `${entry.cve || entry.id}: ${entry.name}`).join('\n') + '\nCác ví dụ này không phải kết luận ứng dụng mắc những CVE đó.');
  }
  const writeupReferences = finding.knowledge?.relatedWriteups.flatMap((entry) => entry.references) ?? [];
  const references = [...new Set([finding.reference, ...writeupReferences, ...(finding.knowledge?.references || [])])];
  const section = element('div', 'detail-field'); section.append(element('h4', '', 'NGUỒN THAM KHẢO'));
  for (const reference of references) {
    if (!/^https:\/\//.test(reference)) continue;
    const link = element('a', '', reference); link.href = reference; link.target = '_blank'; link.rel = 'noopener noreferrer'; section.append(link);
  }
  container.append(section);
}
function renderFindings() {
  const report = state.job?.report;
  const search = $('#finding-search').value.toLowerCase().trim();
  const severity = $('#severity-filter').value;
  const findings = (report?.findings || []).filter((finding) => (severity === 'all' || severity === finding.severity) && `${finding.title} ${finding.ruleId} ${finding.cwe} ${locationOf(finding)}`.toLowerCase().includes(search));
  $('#results-empty').hidden = Boolean(report?.findings.length);
  $('#finding-workspace').hidden = !report?.findings.length;
  if (!report?.findings.length) {
    $('#results-empty h3').textContent = report ? 'Chưa ghi nhận dấu hiệu theo các rule hiện có.' : 'Chưa có kết quả phân tích.';
    $('#results-empty p').textContent = report ? 'Xem thông báo về phạm vi và giới hạn của lượt quét.' : 'Tải ZIP hoặc chọn thư mục mã nguồn để xem báo cáo.';
    return;
  }
  if (!findings.includes(state.selected)) state.selected = findings[0];
  const list = $('#finding-list'); list.replaceChildren();
  for (const finding of findings) {
    const row = element('button', `finding-row${state.selected === finding ? ' selected' : ''}`);
    row.type = 'button';
    const top = element('div', 'row-top'); top.append(element('span', `severity-chip ${finding.severity}`, names[finding.severity]), element('span', 'rule-id', finding.cwe));
    row.append(top, element('h3', '', finding.title), element('p', '', locationOf(finding)));
    row.addEventListener('click', () => { state.selected = finding; renderFindings(); }); list.append(row);
  }
  if (!findings.length) list.append(element('p', 'no-match', 'Không có phát hiện khớp bộ lọc.'));
  renderDetail(state.selected);
}
function renderReport() {
  const report = state.job?.report;
  $('#result-total').textContent = report?.findings.length || 0;
  for (const level of levels) $(`#count-${level}`).textContent = report?.findings.filter((finding) => finding.severity === level).length || 0;
  $('#result-target').textContent = report ? report.target : 'Chưa có lần kiểm tra nào được chọn.';
  $$('[data-download]').forEach((button) => { button.disabled = !report; });
  const notice = $('#report-notice'); notice.hidden = !report;
  notice.classList.toggle('error', Boolean(report && report.status !== 'complete'));
  if (report) notice.textContent = `${report.status === 'complete' ? 'Đã hoàn tất phạm vi đã chọn.' : 'Có phần chưa kiểm tra được.'} ${report.stats.filesScanned} file đã đọc. Mức độ là đánh giá sơ bộ và các dấu hiệu cần được kiểm chứng.${report.errors.length ? '\n' + report.errors.slice(0, 10).join('\n') : ''}`;
  if (report?.stats.formats) notice.textContent += `\nĐịnh dạng đã đọc: ${Object.entries(report.stats.formats).map(([format, count]) => `${format} (${count})`).join(', ') || 'Chưa có'}. Đọc được định dạng không đồng nghĩa phân tích đầy đủ ngữ nghĩa.`;
  if (report?.stats.dependencyAnalysis) {
    const dep = report.stats.dependencyAnalysis;
    notice.textContent += `\nDependency: ${dep.packages} phiên bản npm/PyPI được đối chiếu với snapshot ${dep.advisoryCount} advisory; ${dep.unresolved} khai báo không chốt phiên bản trong manifest; ${dep.unsupportedManifests} manifest chưa hỗ trợ so phiên bản. Snapshot không bao phủ toàn bộ CVE.`;
  }
  const engineStatuses = { complete: 'Hoàn tất', partial: 'Một phần', skipped: 'Đã bỏ qua', failed: 'Lỗi' };
  if (report?.stats.sourceAnalysis) {
    const analysis = report.stats.sourceAnalysis;
    notice.textContent += `\nSemgrep · ${engineStatuses[analysis.status]} · ${analysis.scanned}/${analysis.selected} file đã phân tích · ${analysis.findings} phát hiện.`;
    const languages = Object.entries(analysis.languages ?? {}).map(([name, counts]) =>
      `${name}: ${counts.scanned}/${counts.selected}`);
    if (languages.length) notice.textContent += '\nTheo ngôn ngữ: ' + languages.join(' · ') + '.';
  }
  renderFindings();
}
async function watchJob(id) {
  for (;;) {
    const job = await api(`/api/jobs/${id}`);
    if (job.status === 'failed') throw new Error(job.error);
    if (job.status === 'done') { state.job = job; state.selected = null; $('#finding-search').value = ''; $('#severity-filter').value = 'all'; renderReport(); return; }
    const stage = job.stage || 'Đang kiểm tra mục tiêu…';
    if ($('#scan-stage').textContent !== stage) $('#scan-stage').textContent = stage;
    await new Promise((resolve) => setTimeout(resolve, 600));
  }
}
async function begin() {
  if (state.busy || !state.ready) return;
  message(''); setBusy(true);
  try {
    const sourceAnalysis = $('#source-analysis').value;
    const folder = $('#upload-kind-folder').checked;
    const files = state.folderFiles;
    if (folder && !files.length) throw new Error('Chọn một thư mục mã nguồn.');
    if (folder) $('#scan-stage').textContent = 'Đang nén thư mục…';
    const archive = folder ? await zipFolder(files) : $('#source-zip').files[0];
    if (!archive) throw new Error('Chọn một tệp ZIP mã nguồn.');
    const label = folder ? files[0].webkitRelativePath.split('/')[0] : archive.name;
    $('#scan-stage').textContent = 'Đang gửi mã nguồn…';
    const job = await api('/api/upload', {
      sourceAnalysis,
      label,
      upload: { archive: { content: await fileBase64(archive) } },
    });
    await watchJob(job.id);
  } catch (error) { message(error.message || 'Mất kết nối với ứng dụng. Hãy tải lại trang.'); }
  finally { setBusy(false); }
}
async function renderKnowledge() {
  const requestId = ++state.knowledgeRequest;
  const needle = $('#knowledge-search').value.trim();
  const grid = $('#knowledge-grid'); grid.replaceChildren();
  try {
  const result = await api('/api/knowledge?' + new URLSearchParams({ q: needle, kind: $('#knowledge-kind').value, page: String(state.knowledgePage) }));
  if (requestId !== state.knowledgeRequest) return;
  state.knowledgePage = result.page;
  $('#knowledge-total').textContent = `${result.total} kết quả · Trang ${result.page}/${Math.max(1, result.pages)}`;
  $('#knowledge-prev').disabled = result.page <= 1; $('#knowledge-next').disabled = result.page >= result.pages;
  for (const entry of result.results) {
    const card = element('article', 'panel knowledge-card');
    const identifier = entry.cve ? `${entry.cve} · ${entry.id}` : entry.id;
    const labels = entry.cwes.filter((id) => id !== entry.id);
    card.append(element('span', 'rule-id', identifier + (labels.length ? ' · ' + labels.join(' · ') : '')), element('h2', '', entry.name), element('p', '', (entry.description || entry.detection || '').slice(0, 800)));
    if (entry.kind === 'asvs') card.append(element('p', '', `ASVS v5.0.0 · Mức xác minh L${entry.level} · Yêu cầu cần kiểm chứng, không phải kết quả quét.`));
    if (entry.kind === 'kev') card.append(element('p', '', `CISA KEV · Thêm ngày ${entry.dateAdded}. Lịch sử khai thác công khai của CVE không chứng minh mục tiêu local bị khai thác.`));
    if (entry.kind === 'advisory') card.append(element('p', '', 'Advisory tham khảo; chỉ ghi nhận CVE trên mục tiêu khi khớp package, phiên bản và xem xét điều kiện áp dụng.'));
    else if (entry.kind) card.append(element('p', '', 'Mục ngữ cảnh; không tương đương một rule đã kiểm thử.'));
    const details = element('details'); details.append(element('summary', '', 'Xem điều kiện, hướng rà soát và nguồn'));
    const steps = entry.reviewSteps || entry.mitigations || (entry.objectives ? [entry.objectives] : ['Đối chiếu điều kiện trong nguồn gốc trước khi kết luận.']);
    const list = element('ul'); steps.forEach((step) => list.append(element('li', '', step))); details.append(list);
    if (entry.vulnerabilities) for (const affected of entry.vulnerabilities) details.append(element('p', '', `${affected.ecosystem} / ${affected.name} / ${affected.range} / vá: ${affected.fixed || 'chưa nêu'}`));
    for (const url of entry.references) { if (!/^https:\/\//.test(url)) continue; const link = element('a', '', url); link.href = url; link.target = '_blank'; link.rel = 'noopener noreferrer'; details.append(link); }
    card.append(details); grid.append(card);
  }
  if (!result.results.length) grid.append(element('p', 'no-match', 'Không tìm thấy mục phù hợp trong snapshot.'));
  } catch (error) { if (requestId === state.knowledgeRequest) message(error.message); }
}
async function loadHistory() {
  const entries = await api('/api/history'); const list = $('#history-list'); list.replaceChildren();
  for (const entry of entries) {
    const row = element('button', 'panel history-item');
    const title = element('div'); title.append(element('h3', '', entry.target || 'Kiểm tra mã nguồn'), element('p', '', `${new Date(entry.startedAt).toLocaleString('vi-VN')} · ${entry.status === 'queued' ? 'Đang chờ' : entry.status === 'running' ? 'Đang chạy' : entry.status === 'failed' ? 'Lỗi' : entry.scanStatus === 'complete' ? 'Hoàn tất' : 'Chưa hoàn tất phạm vi'}`));
    row.append(title, element('span', 'history-count', entry.count !== undefined ? `${entry.count} phát hiện ↗` : '↗'));
    row.addEventListener('click', async () => {
      if (entry.status === 'failed') { message('Lần kiểm tra này chưa hoàn tất. Hãy nhập lại mục tiêu và thử lại.'); return; }
      showView('scan'); setBusy(true);
      try { await watchJob(entry.id); } catch (error) { message(error.message); } finally { setBusy(false); }
    }); list.append(row);
  }
  if (!entries.length) list.append(element('div', 'panel empty-state', 'Tài khoản của bạn chưa có lần kiểm tra nào.'));
}
async function loadUsers() {
  const users = await api('/api/users'); const list = $('#user-list'); list.replaceChildren();
  for (const user of users) {
    const row = element('div', 'panel history-item');
    const title = element('div');
    title.append(element('h3', '', user.username), element('p', '', user.role === 'admin' ? 'Tài khoản chủ' : `Thành viên · tạo ${new Date(user.createdAt).toLocaleString('vi-VN')}`));
    row.append(title);
    if (user.role !== 'admin') {
      const remove = element('button', 'button small', 'Xóa');
      remove.type = 'button';
      remove.addEventListener('click', async () => {
        if (!window.confirm(`Xóa tài khoản ${user.username} và toàn bộ báo cáo của tài khoản này?`)) return;
        remove.disabled = true;
        try { await api(`/api/users/${user.id}/delete`, {}); await loadUsers(); }
        catch (error) { message(error.message); remove.disabled = false; }
      });
      row.append(remove);
    }
    list.append(row);
  }
}
for (const button of $$('.nav-item')) button.addEventListener('click', () => showView(button.dataset.view));
$('#logout-button').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await api('/api/logout', {});
    window.location.replace('/login');
  } catch (error) {
    message(error.message || 'Không đăng xuất được. Hãy thử lại.');
    button.disabled = false;
  }
});
$('#source-analysis').addEventListener('change', updateSourceAnalysis);
for (const radio of $$('input[name="upload-kind"]')) radio.addEventListener('change', updateUploadKind);
$('#source-zip').addEventListener('change', updateZipSelection);
$('#source-folder').addEventListener('change', updateFolderSelection);
$('#scan-form').addEventListener('submit', (event) => { event.preventDefault(); void begin(); });
$('#finding-search').addEventListener('input', renderFindings);
$('#severity-filter').addEventListener('change', renderFindings);
let knowledgeTimer;
$('#knowledge-search').addEventListener('input', () => { clearTimeout(knowledgeTimer); knowledgeTimer = setTimeout(() => { state.knowledgePage = 1; void renderKnowledge(); }, 250); });
$('#knowledge-kind').addEventListener('change', () => { state.knowledgePage = 1; void renderKnowledge(); });
$('#knowledge-prev').addEventListener('click', () => { state.knowledgePage--; void renderKnowledge(); });
$('#knowledge-next').addEventListener('click', () => { state.knowledgePage++; void renderKnowledge(); });
$('#refresh-history').addEventListener('click', () => loadHistory().catch((error) => message(error.message)));
$('#user-form').addEventListener('submit', async (event) => {
  event.preventDefault(); message(''); $('#user-button').disabled = true;
  try {
    const created = await api('/api/users', { username: $('#new-username').value, password: $('#new-password').value });
    $('#user-form').reset();
    const box = $('#user-result'); box.hidden = false; box.textContent = `Đã tạo tài khoản ${created.username}.`;
    await loadUsers();
  } catch (error) { message(error.message); }
  finally { $('#user-button').disabled = false; }
});
api('/api/me').then((me) => {
  $('#account-name').textContent = me.username === 'local' ? 'Local workspace' : me.username;
  $('#nav-users').hidden = !me.canManageUsers;
}).catch(() => {});
for (const button of $$('[data-download]')) button.addEventListener('click', async () => {
  try {
    const format = button.dataset.download;
    const response = await fetch(`/api/reports/${state.job.id}/${format}`, { headers: { 'X-Session-Token': token } });
    if (!response.ok) throw new Error('Không tải được báo cáo.');
    const url = URL.createObjectURL(await response.blob());
    const anchor = element('a'); anchor.href = url; anchor.download = `security-report.${format}`; document.body.append(anchor); anchor.click(); anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 30000);
  } catch (error) { message(error.message); }
});

$('#writeup-file').addEventListener('change', async (event) => {
  const file = event.target.files[0]; if (!file) return;
  if (file.size > 1024 * 1024 || !/\.(?:txt|md)$/i.test(file.name)) { message('Chọn file TXT/Markdown không quá 1 MiB.'); return; }
  $('#writeup-text').value = await file.text();
});
$('#writeup-form').addEventListener('submit', async (event) => {
  event.preventDefault(); message(''); $('#writeup-button').disabled = true;
  try {
    const result = await api('/api/writeups', { text: $('#writeup-text').value });
    const box = $('#writeup-result'); box.hidden = false;
    box.textContent = result.topics.length ? `Đã liên kết ${result.topics.length} nhóm: ${result.topics.join(', ')}.` : 'Đã đọc ghi chú, chưa tìm thấy chủ đề trùng thư viện.';
  } catch (error) { message(error.message); }
  finally { $('#writeup-button').disabled = false; }
});
api('/api/bootstrap').then((bootstrap) => {
  if (bootstrap.uploadSchema !== 1 || !Array.isArray(bootstrap.sourceExtensions)) {
    setScanReadiness('error', 'Cần khởi động lại');
    message('Tiến trình SrcAudit đang chạy bản cũ. Mở lại Start-UI.cmd để nạp bản mới, rồi tải lại trang.');
    return;
  }
  for (const extension of bootstrap.sourceExtensions) sourceExtensions.add(extension);
  state.ready = true;
  setBusy(false);
  setScanReadiness('ready', 'Sẵn sàng quét');
  updateUploadKind();
  $('#rule-count').textContent = bootstrap.sourceRules.length;
  $('#topic-count').textContent = bootstrap.corpus?.total || bootstrap.knowledge.length;
  if (bootstrap.corpus) $('#corpus-summary').textContent = `${bootstrap.corpus.cwe} CWE · ${bootstrap.corpus.owasp} WSTG · ${bootstrap.corpus.asvs || 0} yêu cầu ASVS · ${bootstrap.corpus.api || 0} mục API Security · ${bootstrap.corpus.advisories} advisory đã review · ${bootstrap.corpus.kev || 0} KEV.\nTải lúc ${new Date(bootstrap.corpus.builtAt).toLocaleString('vi-VN')}. Quét dùng snapshot tại máy; không gửi source hay danh sách package ra ngoài. Các mục ngữ cảnh không tương đương detector.`;
  renderKnowledge(); renderReport();
}).catch((error) => {
  setScanReadiness('error', 'Chưa kết nối');
  message(error.message || 'Hãy mở lại Start-UI.cmd rồi tải lại trang.');
});
