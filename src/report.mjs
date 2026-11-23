import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { renderSarif } from './sarif.mjs';
import { findingStatement, flowTraceText, groupReportFindings, locationText, reportMode, scanModeLabel, SEVERITIES } from './report-findings.mjs';

export { locationText, SEVERITIES };

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
      'Review the scan coverage even when no findings are reported.',
      'Quick scan uses signatures and local data-flow checks. Results depend on rule coverage and the advisory snapshot.',
      'Severity is a preliminary rule rating. Review evidence and deployment context before acting.'
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

function triageText(report) {
  const lines = [];
  if (report.baseline) {
    const { source, matched, new: fresh, fixed, unassessed = 0 } = report.baseline;
    lines.push(`Baseline comparison (${source}): ${fresh} new · ${matched} matched and hidden · ${fixed} no longer found in assessed files · ${unassessed} not assessed`, '');
  }
  if (report.stats?.diff) lines.push(`Changes since ${report.stats.diff.ref ?? 'ref'}: ${report.stats.diff.changedFiles} changed files, ${report.stats.diff.unchanged} other files`, '');
  const removedByContext = Object.values(report.stats?.contextFilter?.removed ?? {}).reduce((a, b) => a + b, 0);
  const downgraded = Object.values(report.stats?.contextFilter?.downgraded ?? {}).reduce((a, b) => a + b, 0);
  if (report.filtered?.length || removedByContext || downgraded) {
    lines.push(`Context filtering: ${report.filtered?.length ?? 0} filtered by AST checks · ${removedByContext} filtered by contextual checks · ${downgraded} findings had severity or confidence adjusted`, '');
  }
  if (report.suppressed?.length) {
    lines.push(`Suppressed by srcaudit-ignore: ${report.suppressed.length}`,
      ...report.suppressed.map((f) => `- ${f.ruleId} at ${locationText(f.location)} — ${f.suppression.reason}`), '');
  }
  return lines;
}

export function renderText(report) {
  const groups = groupReportFindings(report.findings);
  const lines = [report.tool, `Target: ${report.target}`, `Mode: ${scanModeLabel(reportMode(report))} Status: ${report.status}`, `Findings: ${groups.length} unique issues`, ''];
  if (report.stats.sourceAnalysis) {
    const { status, scanned, selected, findings, languages } = report.stats.sourceAnalysis;
    lines.push(`Deep analysis with Semgrep · ${status} · ${scanned}/${selected} files · ${findings} findings`);
    const counts = Object.entries(languages ?? {}).map(([name, count]) => `${name}: ${count.scanned}/${count.selected}`);
    if (counts.length) lines.push('By language: ' + counts.join(' · '));
    lines.push('');
  }
  if (report.stats.dependencyAnalysis?.manifests) {
    const dep = report.stats.dependencyAnalysis;
    lines.push('Dependencies · ' + dep.manifests + ' manifests · ' + dep.packages + ' package versions · ' + dep.findings + ' findings', '');
  }
  for (const [index, { finding: f, occurrences }] of groups.entries()) {
    lines.push(`${index + 1}. [${f.severity.toUpperCase()}] ${f.title} (${f.ruleId})`,
      `   Category: ${f.cwe} · Confidence: ${f.confidence} · Status: ${f.status}`,
      ...occurrences.flatMap((occurrence) => [`   Location: ${locationText(occurrence.location)}`, `   ${f.advisory ? 'Dependency evidence' : 'Flagged code or evidence'}: ${findingStatement(occurrence)}`]),
      `   Impact: ${f.impact}`, `   Remediation: ${f.remediation}`, `   References: ${f.reference}`);
    if (f.relatedRuleIds?.length) lines.push('   Related rules: ' + f.relatedRuleIds.join(', '));
    if (f.knowledge) lines.push('   Review steps:', ...f.knowledge.reviewSteps.map((s) => `     - ${s}`), ...f.knowledge.references.map((s) => `   Source: ${s}`), ...f.knowledge.relatedWriteups.map((w) => `   Related write-up: ${w.id} ${w.references.join(' ')}`));
    if (f.knowledge?.cweContext) lines.push(`   CWE Context: ${f.knowledge.cweContext.name}: ${f.knowledge.cweContext.description}`);
    if (f.knowledge?.owaspTests?.length) lines.push(`   OWASP: ${f.knowledge.owaspTests.map((entry) => entry.id + ': ' + entry.name).join('; ')}`);
    if (f.detection) lines.push(`   Applicability: ${f.detection.condition}`);
    const trace = flowTraceText(occurrences);
    if (trace) lines.push('   Data-flow trace (review these lines):', ...trace.split('\n').map((line) => `     ${line}`));
    if (f.advisory) lines.push(`   Advisory: ${f.advisory.id} | ${f.advisory.cve || 'No CVE'} | ${f.advisory.package}@${f.advisory.version}`, `   Affected versions: ${f.advisory.affectedRange} Fixed version: ${f.advisory.fixed || 'not available'}`, '   Review whether the affected version and advisory conditions apply.');
    if (f.advisory?.kev) lines.push(`   CISA KEV: ${f.advisory.kev.scope} Added on: ${f.advisory.kev.dateAdded}`);
    if (f.knowledge?.verificationRequirements?.length) lines.push('   ASVS requirements:', ...f.knowledge.verificationRequirements.map((entry) => `     ${entry.id} [L${entry.level}]: ${entry.description}`));
    if (f.knowledge?.apiScenarios?.length) lines.push('   API Security scenarios:', ...f.knowledge.apiScenarios.map((entry) => `     ${entry.id}: ${entry.name}`));
    lines.push('');
  }
  if (!report.findings.length) lines.push(report.baseline ? 'No new findings relative to the baseline.' : 'No findings in the selected scope.', '');
  lines.push(...triageText(report));
  if (report.errors.length) lines.push('Incomplete or skipped coverage:', ...report.errors.map((e) => `- ${e}`), '');
  lines.push('Limits:', ...report.limitations.map((s) => `- ${s}`));
  return lines.join('\n');
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

function contextRows(finding) {
  const rows = [];
  if (finding.relatedRuleIds?.length) rows.push(['Related rules', finding.relatedRuleIds.join(', ')]);
  if (finding.advisory?.kev) rows.push(['CISA KEV', `${finding.advisory.kev.scope}\nAdded on: ${finding.advisory.kev.dateAdded}`]);
  if (finding.knowledge?.verificationRequirements?.length) rows.push(['ASVS requirements', finding.knowledge.verificationRequirements.map((entry) => `${entry.id} [L${entry.level}] ${entry.description}`).join('\n')]);
  if (finding.knowledge?.apiScenarios?.length) rows.push(['API Security scenarios', finding.knowledge.apiScenarios.map((entry) => `${entry.id}: ${entry.name}`).join('\n')]);
  if (finding.knowledge?.cweContext) rows.push(['CWE context', `${finding.knowledge.cweContext.name}\n${finding.knowledge.cweContext.description}`]);
  return rows;
}

const reportStyles = `
:root{color-scheme:light;--ink:#162638;--muted:#526577;--line:#d9e4ec;--paper:#fff;--wash:#edf3f7}
*{box-sizing:border-box}body{margin:0;padding:32px 16px;background:var(--wash);font:15px/1.5 "Segoe UI",system-ui,sans-serif;color:var(--ink)}
main{max-width:900px;margin:auto;border:1px solid var(--line);border-radius:24px;background:var(--paper);padding:clamp(18px,5vw,46px);box-shadow:0 18px 48px #183e5912}
header{border-radius:18px;background:linear-gradient(145deg,#eff6f9,#f8fafc);border:1px solid var(--line);padding:24px}
h1,h2,h3,p,dl{margin:0}h1{font-size:clamp(24px,5vw,38px);line-height:1.13;letter-spacing:-.035em}h2{font-size:20px}h3{font-size:17px;line-height:1.3}
.mode{color:#155f68;font-weight:700;margin-bottom:8px}.metadata{display:flex;flex-wrap:wrap;gap:6px 18px;color:var(--muted);margin-top:10px}.target{overflow-wrap:anywhere;font-weight:650;color:var(--ink)}
.summary{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:8px;margin:18px 0 27px}.summary div{background:var(--tint);border:1px solid var(--line);border-radius:12px;padding:10px 12px;color:var(--tone)}
.summary strong{display:block;font-size:24px;line-height:1.15}.summary span{font-size:12px}
.critical{--tone:#a71943;--tint:#fff0f4}.high{--tone:#a53512;--tint:#fff1e9}.medium{--tone:#855407;--tint:#fff5de}.low{--tone:#135b9a;--tint:#edf6ff}.info{--tone:#5c4186;--tint:#f4f0fb}
.findings-heading{display:flex;align-items:baseline;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:12px}.muted{color:var(--muted)}
article{border:1px solid var(--line);border-radius:14px;margin-bottom:12px;overflow-wrap:anywhere}article>header{background:var(--tint);border:0;border-bottom:1px solid var(--line);border-radius:14px 14px 0 0;padding:14px 18px}
.issue-meta{display:flex;gap:6px 12px;flex-wrap:wrap;align-items:center;margin-top:6px;font-size:12px;color:var(--muted)}.severity{color:var(--tone);font-weight:800}
.issue-body{padding:14px 18px}.occurrences{margin:0;padding:0;list-style:none}.occurrences>li+li{margin-top:10px}.occurrences>li{break-inside:avoid}.file-line{font:600 12px/1.5 ui-monospace,Consolas,monospace;overflow-wrap:anywhere}.statement{background:#edf4f8;border:1px solid var(--line);padding:9px 11px;border-radius:8px;margin:4px 0 0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;font:12px/1.55 ui-monospace,Consolas,monospace}dt{margin-top:10px;font-weight:700}dd{margin:2px 0 0}summary{cursor:pointer;font-weight:650;color:#155f68}
details,main>section+section{margin-top:12px}.coverage{border-top:1px solid var(--line);padding-top:14px}.coverage p,.coverage ul{margin:6px 0}
@media(max-width:500px){body{padding:0}main{border-radius:0}.summary{grid-template-columns:repeat(3,minmax(0,1fr))}header{padding:16px}}
@page{size:A4 portrait;margin:12mm}
@media print{body{padding:0;background:white;font-size:10pt}main{max-width:none;padding:0;border:0;box-shadow:none}header,.summary,article>header{print-color-adjust:exact;-webkit-print-color-adjust:exact}article>header,h2,summary{break-after:avoid}.summary{break-inside:avoid}}
`;

function reportCard({ finding, occurrences }) {
  const e = escapeHtml;
  const code = occurrences.map((item) => `<li><div class="file-line">${e(locationText(item.location))}</div><pre class="statement">${e(findingStatement(item))}</pre>${item.sourceExcerpt ? `<details><summary>Redacted source context</summary><pre>${e(item.sourceExcerpt)}</pre></details>` : ''}</li>`).join('');
  const additionalDetails = [
    ['Confidence', finding.confidence], ['Status', finding.status], ['References', finding.reference],
    ...(finding.detection ? [['Applicability', finding.detection.condition]] : []),
    ['Data-flow trace', flowTraceText(occurrences)],
    ...(finding.advisory ? [['Affected range / fix', `${finding.advisory.affectedRange} / ${finding.advisory.fixed || 'not available'}`], ['Advisory context', finding.advisory.description]] : []),
    ...(finding.knowledge ? [['Review steps', (finding.knowledge.reviewSteps ?? []).join('\n')], ['Knowledge references', (finding.knowledge.references ?? []).join('\n')], ['Related write-ups', (finding.knowledge.relatedWriteups ?? []).map((w) => w.id + ': ' + w.references.join(', ')).join('\n')]] : []),
    ...contextRows(finding),
  ];
  const details = additionalDetails.filter(([, value]) => value).map(([label, value]) => `<dt>${e(label)}</dt><dd><pre>${e(value)}</pre></dd>`).join('');
  return `<article class="${e(finding.severity)}"><header><h3>${e(finding.title)}</h3><div class="issue-meta"><span class="severity">${e(finding.severity.toUpperCase())}</span><span>${e(finding.ruleId)} · ${e(finding.cwe)}</span><span>${occurrences.length} ${occurrences.length === 1 ? 'location' : 'locations'}</span></div></header><div class="issue-body"><ul class="occurrences">${code}</ul><dl><dt>Impact</dt><dd>${e(finding.impact)}</dd><dt>Remediation</dt><dd>${e(finding.remediation)}</dd></dl>${details ? `<details><summary>Technical details</summary><dl>${details}</dl></details>` : ''}</div></article>`;
}

export function renderHtml(report) {
  const e = escapeHtml;
  const groups = groupReportFindings(report.findings);
  const occurrences = groups.reduce((sum, group) => sum + group.occurrences.length, 0);
  const triage = triageText(report).join('\n').trim();
  const summary = SEVERITIES.map((level) => `<div class="${level}"><strong>${groups.filter(({ finding }) => finding.severity === level).length}</strong><span>${level[0].toUpperCase() + level.slice(1)}</span></div>`).join('');
  const mode = scanModeLabel(reportMode(report));
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>SrcAudit — Security Scan Report</title><style>${reportStyles}</style></head>
<body><main><header><p class="mode">${mode}</p><h1>Security Scan Report</h1><div class="metadata"><span class="target">${e(report.target)}</span><span>${e(report.startedAt)}</span><span>Status · ${e(report.status)}</span></div></header>
<section class="summary" aria-label="Unique issues by severity">${summary}</section>
<section id="findings" aria-labelledby="findings-title"><div class="findings-heading"><h2 id="findings-title">Findings</h2><span class="muted">${groups.length} unique issues · ${occurrences} tracked locations</span></div>
${groups.map(reportCard).join('') || `<p>${report.baseline ? 'No new findings relative to the baseline.' : 'No findings in the selected scope.'}</p>`}</section>
<section class="coverage"><h2>Scan coverage</h2><p>${report.stats.filesScanned ?? 0} files read</p>${report.errors.length ? `<ul>${report.errors.map((error) => `<li>${e(error)}</li>`).join('')}</ul>` : ''}<details><summary>Coverage details and limits</summary><pre>${e(JSON.stringify(report.stats, null, 2))}</pre><ul>${report.limitations.map((limit) => `<li>${e(limit)}</li>`).join('')}</ul></details>${triage ? `<details><summary>Baseline and suppressions</summary><pre>${e(triage)}</pre></details>` : ''}</section></main></body></html>`;
}

export class ReportSizeError extends Error {}

export async function writeReports(report, outDir, { maxTotalBytes = Infinity } = {}) {
  const files = { json: path.resolve(outDir, 'report.json'), html: path.resolve(outDir, 'report.html'), text: path.resolve(outDir, 'report.txt'), sarif: path.resolve(outDir, 'report.sarif') };
  const output = {
    json: JSON.stringify(report, null, 2) + '\n',
    sarif: JSON.stringify(renderSarif(report), null, 2) + '\n',
    html: renderHtml(report),
    text: renderText(report) + '\n',
  };
  if (Object.values(output).reduce((sum, value) => sum + Buffer.byteLength(value), 0) > maxTotalBytes) {
    throw new ReportSizeError('The report exceeds the storage limit. Delete an older report or scan a smaller scope.');
  }
  await mkdir(outDir, { recursive: true });
  for (const [format, body] of Object.entries(output)) await writeFile(files[format], body, { encoding: 'utf8', mode: 0o600 });
  return files;
}
