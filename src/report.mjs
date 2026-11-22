import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { renderSarif } from './sarif.mjs';

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

export function locationText(location) {
  if (location.url) return location.url;
  if (location.line) {
    const start = `${location.file}:${location.line}${location.column ? ':' + location.column : ''}`;
    return location.endLine ? `${start}–${location.endLine}:${location.endColumn}` : start;
  }
  return location.file + (location.pointer ? ' #' + location.pointer : '');
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
  const lines = [report.tool, `Target: ${report.target}`, `Mode: ${report.mode} Status: ${report.status}`, `Findings: ${report.findings.length}`, ''];
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
  for (const [index, f] of report.findings.entries()) {
    lines.push(`${index + 1}. [${f.severity.toUpperCase()}] ${f.title} (${f.ruleId})`,
      `   Location: ${locationText(f.location)}`, `   Category: ${f.cwe} · Confidence: ${f.confidence} · Status: ${f.status}`,
      `   Evidence: ${f.evidence}`, `   Impact: ${f.impact}`, `   Remediation: ${f.remediation}`, `   References: ${f.reference}`);
    if (f.sourceExcerpt) lines.push('   Source excerpt (redacted):', f.sourceExcerpt);
    if (f.relatedRuleIds?.length) lines.push('   Related rules: ' + f.relatedRuleIds.join(', '));
    if (f.knowledge) lines.push('   Review steps:', ...f.knowledge.reviewSteps.map((s) => `     - ${s}`), ...f.knowledge.references.map((s) => `   Source: ${s}`), ...f.knowledge.relatedWriteups.map((w) => `   Related write-up: ${w.id} ${w.references.join(' ')}`));
    if (f.knowledge?.cweContext) lines.push(`   CWE Context: ${f.knowledge.cweContext.name}: ${f.knowledge.cweContext.description}`);
    if (f.knowledge?.owaspTests?.length) lines.push(`   OWASP: ${f.knowledge.owaspTests.map((entry) => entry.id + ': ' + entry.name).join('; ')}`);
    if (f.detection) lines.push(`   Applicability: ${f.detection.condition}`);
    if (f.trace) lines.push('   Data-flow trace (review these lines):', ...f.trace.map((step) => `     ${step.file}:${step.line} [${step.role}] ${step.evidence}`));
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

export function renderHtml(report) {
  const e = escapeHtml;
  const cards = report.findings.map((f) => `<article class="${e(f.severity)}"><h2><span>${e(f.severity.toUpperCase())}</span> ${e(f.title)}</h2><p><strong>${e(f.ruleId)} · ${e(f.cwe)}</strong></p><dl>${[
    ['Location', locationText(f.location)], ['Confidence', f.confidence], ['Status', f.status], ['Evidence', f.evidence], ['Impact', f.impact], ['Remediation', f.remediation], ['References', f.reference], ...(f.detection ? [['Applicability', f.detection.condition]] : []), ...(f.trace ? [['Data-flow trace', f.trace.map((step) => `${step.file}:${step.line} [${step.role}] ${step.evidence}`).join('\n')]] : []), ...(f.advisory ? [['CVE / GHSA', `${f.advisory.cve || ''} ${f.advisory.id}`], ['Dependency', `${f.advisory.ecosystem} ${f.advisory.package}@${f.advisory.version}`], ['Affected range / fix', `${f.advisory.affectedRange} / ${f.advisory.fixed || 'not available'}`], ['Advisory context', f.advisory.description]] : []), ...(f.knowledge ? [['Review steps', f.knowledge.reviewSteps.join('\n')], ['Knowledge references', f.knowledge.references.join('\n')], ['Related write-ups', f.knowledge.relatedWriteups.map((w) => w.id + ': ' + w.references.join(', ')).join('\n') || 'None']] : [])
  , ...(f.sourceExcerpt ? [['Source excerpt (redacted)', f.sourceExcerpt]] : []), ...contextRows(f)].map(([k, v]) => `<dt>${e(k)}</dt><dd><pre>${e(v)}</pre></dd>`).join('')}</dl></article>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>SrcAudit — Security Report</title><style>body{font:16px/1.6 system-ui,sans-serif;background:#0c1220;color:#e6edf7;max-width:1100px;margin:36px auto;padding:0 24px}h1{font-size:32px}h2{font-size:21px}article,section{background:#152037;padding:22px;margin:18px 0;border-radius:12px;border-left:5px solid #60728e}article.critical,article.high{border-color:#ff737b}article.medium{border-color:#eab45c}article.low{border-color:#70b6ff}span{font-size:13px;color:#eab45c}dt{font-weight:bold;color:#a9c3e9;margin-top:10px}dd{margin-left:0}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;margin:0}small{color:#a4b5cf}</style></head><body><h1>Security Scan Report</h1><p>SrcAudit</p><p><strong>${e(report.target)}</strong></p><p>${e(report.mode)} · ${e(report.status)} · ${report.findings.length} findings</p><small>${e(report.startedAt)}</small>${cards || `<section>${report.baseline ? 'No new findings relative to the baseline.' : 'No findings in the selected scope.'}</section>`}${triageText(report).length ? `<section><h2>Baseline and suppressions</h2><pre>${e(triageText(report).join('\n').trim())}</pre></section>` : ''}<section><h2>Coverage</h2><pre>${e(JSON.stringify(report.stats, null, 2))}</pre></section>${report.errors.length ? `<section><h2>Incomplete coverage</h2><ul>${report.errors.map((s) => `<li>${e(s)}</li>`).join('')}</ul></section>` : ''}<section><h2>Limits</h2><ul>${report.limitations.map((s) => `<li>${e(s)}</li>`).join('')}</ul></section></body></html>`;
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
