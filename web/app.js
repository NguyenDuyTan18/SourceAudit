import { isDockerfileName, isTestPath, MAX_SOURCE_FILE_BYTES, MAX_SOURCE_FILES, MAX_SOURCE_TOTAL_BYTES, MAX_ZIP_BYTES, MIB } from '/scan-scope.js';

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const token = $('meta[name="session-token"]').content;
const levels = ['critical', 'high', 'medium', 'low', 'info'];
const names = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const state = { job: null, selected: null, busy: false, ready: false, knowledgePage: 1, knowledgeRequest: 0, folderFiles: [] };
const sourceFileCount = MAX_SOURCE_FILES.toLocaleString('en-US');
$('#zip-limits').textContent = `Up to ${sourceFileCount} source files, ${MAX_SOURCE_FILE_BYTES / MIB} MiB per file, ${MAX_SOURCE_TOTAL_BYTES / MIB} MiB of source in total, and ${MAX_ZIP_BYTES / MIB} MiB per ZIP. Test files are skipped.`;
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
    throw new Error('Could not connect to SrcAudit. Make sure the application is running and reload this page.');
  }
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const hints = {
      401: 'Your session expired. Reload the page and sign in again.',
      403: 'The browser session is invalid. Reload this page.',
      413: body?.error || 'The upload exceeds the limit. Use a smaller ZIP or folder.',
    };
    throw new Error(hints[response.status] || body?.error || `SrcAudit could not process the request (HTTP ${response.status}).`);
  }
  if (!body) throw new Error('SrcAudit returned an invalid response. Reload the page.');
  return body;
}
function setBusy(value) {
  state.busy = value;
  const disabled = value || !state.ready;
  $('#scan-button').disabled = disabled;
  $('#source-upload').disabled = disabled;
  $('#source-analysis-options').disabled = disabled;
  $('#scan-progress').hidden = !value;
  $('#scan-action').textContent = value ? 'Scanning…' : 'Start scan';
  if (value) $('#scan-stage').textContent = 'Preparing the scan…';
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
    ? 'Use Semgrep to analyze code and configuration and check dependency versions.'
    : 'Check source patterns, configuration and dependency versions.';
  $('#scan-scope').textContent = deep ? 'Semgrep · 8 languages plus configuration · Local processing' : 'Static analysis · Local processing';
}
function updateZipSelection(event) {
  const input = event.currentTarget;
  const file = input.files[0];
  message('');
  if (file && (!/\.zip$/i.test(file.name) || !file.size || file.size > MAX_ZIP_BYTES)) {
    message(`Choose a ZIP file no larger than ${MAX_ZIP_BYTES / MIB} MiB.`);
    input.value = '';
  }
  $('#source-selection').textContent = input.files.length
    ? file.name + ' · ' + (file.size / MIB).toFixed(2) + ' MiB'
    : 'No ZIP file selected.';
}
function updateFolderSelection() {
  message('');
  const input = $('#source-folder');
  state.folderFiles = [];
  $('#source-selection').textContent = 'No source folder selected.';
  if (!input.files.length) return;
  const root = input.files[0].webkitRelativePath.split('/')[0];
  const files = [];
  let bytes = 0;
  try {
    for (const file of input.files) {
      const parts = file.webkitRelativePath.split('/');
      if (parts.length < 2 || parts[0] !== root) throw new Error('Choose a source folder.');
      if (isTestPath(file.webkitRelativePath) || parts.slice(0, -1).some((part) => ignoredFolders.has(part.toLowerCase()))) continue;
      const dot = file.name.lastIndexOf('.');
      const knownExtension = dot > 0 && sourceExtensions.has(file.name.slice(dot).toLowerCase());
      if (!knownExtension && !file.name.startsWith('.env') && !isDockerfileName(file.name) &&
          !/^requirements(?:[.-].*)?\.txt$/i.test(file.name)) continue;
      if (file.size > MAX_SOURCE_FILE_BYTES) throw new Error(`${file.webkitRelativePath} exceeds the ${MAX_SOURCE_FILE_BYTES / MIB} MiB per-file limit.`);
      bytes += file.size;
      files.push(file);
      if (files.length > MAX_SOURCE_FILES || bytes > MAX_SOURCE_TOTAL_BYTES) throw new Error(`Choose a folder with up to ${sourceFileCount} source files and ${MAX_SOURCE_TOTAL_BYTES / MIB} MiB of source in total.`);
    }
    if (!files.length) throw new Error('The folder contains no supported source files.');
    state.folderFiles = files;
    const ignored = input.files.length - files.length;
    $('#source-selection').textContent = `${root} · ${files.length} files · ${(bytes / MIB).toFixed(2)} MiB` +
      (ignored ? ` · Skipped ${ignored} files` : '');
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
    if (Object.hasOwn(entries, relative)) throw new Error('Two files in the folder have the same path.');
    entries[relative] = new Uint8Array(await file.arrayBuffer());
  }
  const archive = new Blob([zipSync(entries, { level: 1 })], { type: 'application/zip' });
  if (archive.size > MAX_ZIP_BYTES) throw new Error(`The ZIP generated from the folder exceeds the limit of ${MAX_ZIP_BYTES / MIB} MiB.`);
  return archive;
}
function fileBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(',')[1]);
    reader.onerror = () => reject(new Error('Could not read the selected file.'));
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
  if (!finding) { container.append(element('p', 'no-match', 'Select a finding to see its details.')); return; }
  const badge = element('span', `severity-chip ${finding.severity}`, names[finding.severity]);
  container.append(badge, element('h3', '', finding.title));
  const meta = element('div', 'detail-meta');
  meta.append(element('span', 'rule-id', `${finding.ruleId} · ${finding.cwe}`), element('span', '', `Confidence: ${names[finding.confidence] || finding.confidence}`), element('span', '', finding.status === 'observed' ? 'Observed configuration' : finding.status === 'version-match' ? 'Matches an advisory version range' : 'Needs review'));
  const method = finding.advisory ? 'Dependency version matching' : {
    signature: 'Pattern matching', 'text-flow': 'Local data-flow tracking', 'yaml-structure': 'YAML configuration check',
    'semgrep-pattern': 'Semgrep structural matching', 'semgrep-taint': 'Semgrep data-flow analysis',
  }[finding.detection?.method];
  if (method) meta.append(element('span', '', method));
  container.append(meta);
  field(container, 'LOCATION', locationOf(finding), true);
  if (finding.sourceExcerpt) field(container, 'SOURCE EXCERPT (REDACTED)', finding.sourceExcerpt, true);
  if (finding.relatedRuleIds?.length) field(container, 'RELATED RULES', finding.relatedRuleIds.join(', '));
  field(container, 'EVIDENCE', finding.evidence, true);
  field(container, 'POTENTIAL IMPACT', finding.impact);
  if (finding.detection) field(container, 'WHEN THIS APPLIES', finding.detection.condition);
  field(container, 'REMEDIATION', finding.remediation);
  if (finding.trace) {
    const roles = { source: 'Input', propagation: 'Propagation', sink: 'Sink' };
    field(container, 'DATA-FLOW TRACE', finding.trace.map((step) =>
      `${step.file}:${step.line} [${roles[step.role] || step.role}] ${step.evidence}`).join('\n'), true);
  }
  if (finding.advisory) {
    field(container, 'CVE / GHSA', `${finding.advisory.cve || 'No CVE assigned'} · ${finding.advisory.id}`);
    field(container, 'PACKAGE / VERSION / RANGE', `${finding.advisory.ecosystem} ${finding.advisory.package}@${finding.advisory.version}\nAffected versions: ${finding.advisory.affectedRange}\nFixed version: ${finding.advisory.fixed || 'Not specified'}`, true);
    if (finding.advisory.description) field(container, 'ADVISORY CONTEXT', finding.advisory.description);
    if (finding.advisory.kev) field(container, 'CISA KEV — KNOWN EXPLOITATION HISTORY', `${finding.advisory.kev.scope}\nAdded to the catalog: ${finding.advisory.kev.dateAdded}`);
  }
  if (finding.knowledge) {
    if (finding.knowledge.cweContext) field(container, 'CWE CONTEXT', `${finding.knowledge.cweContext.name}\n${finding.knowledge.cweContext.description}`);
    if (finding.knowledge.owaspTests?.length) field(container, 'RELATED OWASP TESTS', finding.knowledge.owaspTests.map((entry) => `${entry.id}: ${entry.name}`).join('\n'));
    if (finding.knowledge.verificationRequirements?.length) field(container, 'ASVS VERIFICATION REQUIREMENTS', finding.knowledge.verificationRequirements.map((entry) => `${entry.id} · L${entry.level}\n${entry.description}`).join('\n\n'));
    if (finding.knowledge.apiScenarios?.length) field(container, 'RELATED API SECURITY SCENARIOS', finding.knowledge.apiScenarios.map((entry) => `${entry.id}: ${entry.name}`).join('\n'));
    const section = element('div', 'detail-field'); section.append(element('h4', '', 'REVIEW STEPS'));
    const list = element('ul'); finding.knowledge.reviewSteps.forEach((step) => list.append(element('li', '', step)));
    section.append(list); container.append(section);
    if (finding.knowledge.relatedWriteups.length) field(container, 'RELATED WRITE-UPS', `${finding.knowledge.relatedWriteups.length} imported notes on ${finding.knowledge.topic}.`);
    if (finding.knowledge.advisoryExamples?.length) field(container, 'ADVISORY EXAMPLES FOR THIS CWE', finding.knowledge.advisoryExamples.map((entry) => `${entry.cve || entry.id}: ${entry.name}`).join('\n') + '\nThese examples illustrate the weakness category.');
  }
  const writeupReferences = finding.knowledge?.relatedWriteups.flatMap((entry) => entry.references) ?? [];
  const references = [...new Set([finding.reference, ...writeupReferences, ...(finding.knowledge?.references || [])])];
  const section = element('div', 'detail-field'); section.append(element('h4', '', 'REFERENCES'));
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
  const kind = $('#finding-kind').value;
  const findings = (report?.findings || []).filter((finding) => {
    const group = finding.advisory ? 'dependency' : 'source';
    const matches = (kind === 'all' || kind === group) && (severity === 'all' || severity === finding.severity);
    return matches && `${finding.title} ${finding.ruleId} ${finding.cwe} ${locationOf(finding)}`.toLowerCase().includes(search);
  });
  $('#results-empty').hidden = Boolean(report?.findings.length);
  $('#finding-workspace').hidden = !report?.findings.length;
  if (!report?.findings.length) {
    $('#results-empty h3').textContent = report ? 'The selected rules reported no findings.' : 'No scan results yet.';
    $('#results-empty p').textContent = report ? 'Review the scan coverage and any reported limits.' : 'Choose a ZIP file or folder to start a scan.';
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
  if (!findings.length) list.append(element('p', 'no-match', 'No findings match the filters.'));
  renderDetail(state.selected);
}
function renderReport() {
  const report = state.job?.report;
  $('#result-total').textContent = report?.findings.length || 0;
  for (const level of levels) $(`#count-${level}`).textContent = report?.findings.filter((finding) => finding.severity === level).length || 0;
  $('#result-target').textContent = report ? report.target : 'No scan selected.';
  $$('[data-download]').forEach((button) => { button.disabled = !report; });
  const notice = $('#report-notice'); notice.hidden = !report;
  notice.classList.toggle('error', Boolean(report && report.status !== 'complete'));
  if (report) notice.textContent = `${report.status === 'complete' ? 'Scan completed for the selected scope.' : 'The scan could not cover all selected files.'} ${report.stats.filesScanned} files read. Review findings in context before acting on the severity rating.${report.errors.length ? '\n' + report.errors.slice(0, 10).join('\n') : ''}`;
  if (report?.stats.formats) notice.textContent += `\nFormats read: ${Object.entries(report.stats.formats).map(([format, count]) => `${format} (${count})`).join(', ') || 'None'}. Analysis coverage varies by format.`;
  if (report?.stats.dependencyAnalysis) {
    const dep = report.stats.dependencyAnalysis;
    const sourceFindings = report.findings.filter(({ advisory }) => !advisory);
    const sourceRuleCount = new Set(sourceFindings.map(({ ruleId }) => ruleId)).size;
    notice.textContent += `\nSource and configuration: ${sourceFindings.length} findings across ${sourceRuleCount} rules · Dependency findings: ${report.findings.length - sourceFindings.length}.`;
    notice.textContent += `\nChecked ${dep.packages} npm, PyPI and Composer package versions against ${dep.advisoryCount} advisories. Unresolved versions: ${dep.unresolved}. Unsupported manifests: ${dep.unsupportedManifests}. Advisory ranges that could not be assessed: ${dep.unassessedRanges ?? 0}.`;
  }
  const engineStatuses = { complete: 'Complete', partial: 'Partial', skipped: 'Skipped', failed: 'Failed' };
  if (report?.stats.sourceAnalysis) {
    const analysis = report.stats.sourceAnalysis;
    notice.textContent += `\nSemgrep · ${engineStatuses[analysis.status]} · ${analysis.scanned}/${analysis.selected} files analyzed · ${analysis.findings} findings.`;
    const languages = Object.entries(analysis.languages ?? {}).map(([name, counts]) =>
      `${name}: ${counts.scanned}/${counts.selected}`);
    if (languages.length) notice.textContent += '\nBy language: ' + languages.join(' · ') + '.';
    const hmacDigests = analysis.pythonPrecision?.reasons?.['python-hmac-digest-factory'];
    if (hmacDigests) notice.textContent += `\nPython context: filtered ${hmacDigests} SHA-1 matches whose function is used only as the HMAC digest in ItsDangerous within the module.`;
  } else if (report) {
    notice.textContent += '\nQuick scan uses patterns and local data-flow tracking. Choose deep scan for Semgrep structural and data-flow analysis.';
  }
  if (report?.stats.contextFilter) {
    const { removed, downgraded } = report.stats.contextFilter;
    const count = (rules) => Object.values(rules ?? {}).reduce((sum, value) => sum + value, 0);
    const removedCount = count(removed);
    const downgradedCount = count(downgraded);
    if (removedCount || downgradedCount) notice.textContent += `\nContext checks: ${removedCount} matches filtered, ${downgradedCount} findings had their severity or confidence adjusted.`;
  }
  renderFindings();
}
async function watchJob(id) {
  for (;;) {
    const job = await api(`/api/jobs/${id}`);
    if (job.status === 'failed') throw new Error(job.error);
    if (job.status === 'done') { state.job = job; state.selected = null; $('#finding-search').value = ''; $('#severity-filter').value = 'all'; $('#finding-kind').value = 'all'; renderReport(); return; }
    const stage = job.stage || 'Analyzing source files…';
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
    if (folder && !files.length) throw new Error('Choose a source folder.');
    if (folder) $('#scan-stage').textContent = 'Compressing folder…';
    const archive = folder ? await zipFolder(files) : $('#source-zip').files[0];
    if (!archive) throw new Error('Choose a source ZIP file.');
    const label = folder ? files[0].webkitRelativePath.split('/')[0] : archive.name;
    $('#scan-stage').textContent = 'Uploading source files…';
    const job = await api('/api/upload', {
      sourceAnalysis,
      label,
      upload: { archive: { content: await fileBase64(archive) } },
    });
    await watchJob(job.id);
  } catch (error) { message(error.message || 'Connection lost. Reload the page.'); }
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
  $('#knowledge-total').textContent = `${result.total} results · Page ${result.page}/${Math.max(1, result.pages)}`;
  $('#knowledge-prev').disabled = result.page <= 1; $('#knowledge-next').disabled = result.page >= result.pages;
  for (const entry of result.results) {
    const card = element('article', 'panel knowledge-card');
    const identifier = entry.cve ? `${entry.cve} · ${entry.id}` : entry.id;
    const labels = entry.cwes.filter((id) => id !== entry.id);
    card.append(element('span', 'rule-id', identifier + (labels.length ? ' · ' + labels.join(' · ') : '')), element('h2', '', entry.name), element('p', '', (entry.description || entry.detection || '').slice(0, 800)));
    if (entry.kind === 'asvs') card.append(element('p', '', `ASVS v5.0.0 · Verification level L${entry.level} · Verification requirement.`));
    if (entry.kind === 'kev') card.append(element('p', '', `CISA KEV · Added on ${entry.dateAdded}. This catalog records exploitation observed elsewhere.`));
    if (entry.publication) card.append(element('p', '', entry.publication));
    else if (entry.kind === 'advisory') card.append(element('p', '', 'Review the package, version and conditions before applying the advisory to your project.'));
    else if (entry.kind) card.append(element('p', '', 'Reference for interpreting scan results.'));
    const details = element('details'); details.append(element('summary', '', 'Show review steps and sources'));
    const steps = entry.reviewSteps || entry.mitigations || (entry.objectives ? [entry.objectives] : ['Check the original source and its applicability conditions.']);
    const list = element('ul'); steps.forEach((step) => list.append(element('li', '', step))); details.append(list);
    if (entry.vulnerabilities) for (const affected of entry.vulnerabilities) details.append(element('p', '', `${affected.ecosystem} / ${affected.name} / ${affected.range} / fix: ${affected.fixed || 'not specified'}`));
    for (const url of entry.references) { if (!/^https:\/\//.test(url)) continue; const link = element('a', '', url); link.href = url; link.target = '_blank'; link.rel = 'noopener noreferrer'; details.append(link); }
    card.append(details); grid.append(card);
  }
  if (!result.results.length) grid.append(element('p', 'no-match', 'No library entries match.'));
  } catch (error) { if (requestId === state.knowledgeRequest) message(error.message); }
}
async function loadHistory() {
  const entries = await api('/api/history'); const list = $('#history-list'); list.replaceChildren();
  for (const entry of entries) {
    const row = element('button', 'panel history-item');
    const title = element('div'); title.append(element('h3', '', entry.target || 'Scan source code'), element('p', '', `${new Date(entry.startedAt).toLocaleString('en-US')} · ${entry.status === 'queued' ? 'Queued' : entry.status === 'running' ? 'Running' : entry.status === 'failed' ? 'Failed' : entry.scanStatus === 'complete' ? 'Complete' : 'Incomplete'}`));
    row.append(title, element('span', 'history-count', entry.count !== undefined ? `${entry.count} findings ↗` : '↗'));
    row.addEventListener('click', async () => {
      if (entry.status === 'failed') { message('This scan failed. Select the source again to retry.'); return; }
      showView('scan'); setBusy(true);
      try { await watchJob(entry.id); } catch (error) { message(error.message); } finally { setBusy(false); }
    });
    const item = element('div', 'history-entry');
    item.append(row);
    if (entry.status === 'done' || entry.status === 'failed') {
      const remove = element('button', 'button small', 'Xóa');
      remove.type = 'button';
      remove.setAttribute('aria-label', 'Delete scan ' + (entry.target || entry.startedAt));
      remove.addEventListener('click', async () => {
        if (!window.confirm('Delete this scan and its reports?')) return;
        remove.disabled = true;
        try {
          await api('/api/jobs/' + entry.id + '/delete', {});
          if (state.job?.id === entry.id) { state.job = null; state.selected = null; renderReport(); }
          await loadHistory();
        } catch (error) { message(error.message); remove.disabled = false; }
      });
      item.append(remove);
    }
    list.append(item);
  }
  if (!entries.length) list.append(element('div', 'panel empty-state', 'Your workspace has no scans yet.'));
}
async function loadUsers() {
  const users = await api('/api/users'); const list = $('#user-list'); list.replaceChildren();
  for (const user of users) {
    const row = element('div', 'panel history-item');
    const title = element('div');
    title.append(element('h3', '', user.username), element('p', '', user.role === 'admin' ? 'Owner' : `Member · created ${new Date(user.createdAt).toLocaleString('en-US')}`));
    row.append(title);
    if (user.role !== 'admin') {
      const remove = element('button', 'button small', 'Xóa');
      remove.type = 'button';
      remove.addEventListener('click', async () => {
        if (!window.confirm(`Delete ${user.username} and all reports belonging to this account?`)) return;
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
    message(error.message || 'Could not sign out. Try again.');
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
$('#finding-kind').addEventListener('change', renderFindings);
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
    const box = $('#user-result'); box.hidden = false; box.textContent = `Created account ${created.username}.`;
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
    if (!response.ok) throw new Error('Could not download the report.');
    const url = URL.createObjectURL(await response.blob());
    const anchor = element('a'); anchor.href = url; anchor.download = `security-report.${format}`; document.body.append(anchor); anchor.click(); anchor.remove(); setTimeout(() => URL.revokeObjectURL(url), 30000);
  } catch (error) { message(error.message); }
});

$('#writeup-file').addEventListener('change', async (event) => {
  const file = event.target.files[0]; if (!file) return;
  if (file.size > 1024 * 1024 || !/\.(?:txt|md)$/i.test(file.name)) { message('Choose a TXT or Markdown file up to 1 MiB.'); return; }
  $('#writeup-text').value = await file.text();
});
$('#writeup-form').addEventListener('submit', async (event) => {
  event.preventDefault(); message(''); $('#writeup-button').disabled = true;
  try {
    const result = await api('/api/writeups', { text: $('#writeup-text').value });
    const box = $('#writeup-result'); box.hidden = false;
    box.textContent = result.topics.length ? `Linked ${result.topics.length} topics: ${result.topics.join(', ')}.` : 'No library topics matched this note.';
  } catch (error) { message(error.message); }
  finally { $('#writeup-button').disabled = false; }
});
api('/api/bootstrap').then((bootstrap) => {
  if (bootstrap.uploadSchema !== 1 || !Array.isArray(bootstrap.sourceExtensions)) {
    setScanReadiness('error', 'Restart required');
    message('Restart the SrcAudit process and reload this page.');
    return;
  }
  for (const extension of bootstrap.sourceExtensions) sourceExtensions.add(extension);
  state.ready = true;
  setBusy(false);
  setScanReadiness('ready', 'Ready to scan');
  updateUploadKind();
  $('#rule-count').textContent = bootstrap.sourceRules.length;
  $('#topic-count').textContent = bootstrap.corpus?.total || bootstrap.knowledge.length;
  if (bootstrap.corpus) $('#corpus-summary').textContent = `${bootstrap.corpus.cwe} CWE · ${bootstrap.corpus.owasp} WSTG · ${bootstrap.corpus.asvs || 0} ASVS requirements · ${bootstrap.corpus.api || 0} API Security entries · ${bootstrap.corpus.advisories} reviewed advisories · ${bootstrap.corpus.kev || 0} KEV entries · ${bootstrap.corpus.research || 0} research papers · ${bootstrap.corpus.references || 0} technical references.\nAdvisory snapshot updated ${new Date(bootstrap.corpus.builtAt).toLocaleString('en-US')}.`;
  renderKnowledge(); renderReport();
}).catch((error) => {
  setScanReadiness('error', 'Not connected');
  message(error.message || 'Start SrcAudit and reload this page.');
});
