import { createHash } from 'node:crypto';
import { SEVERITIES } from './report.mjs';

// Inline suppression, placed in a comment on the flagged line or alone on the line above:
//   db.query(sql); // srcaudit-ignore SRC-SQL -- SQL is a fixed internal query
//   # srcaudit-ignore CWE-798,SRC-SECRET -- fixture value used by a test
// Rule list is optional (omitted = every finding on that line). A reason after `--` is required.
const DIRECTIVE = /(?:\/\/|#|\/\*|<!--|--|;|\{\{!?--)\s*srcaudit-ignore\b([^\r\n]*)/;
const COMMENT_ONLY = /^\s*(?:\/\/|#|\/\*|\*|<!--|--|;|\{\{!?--)/;

export function collectSuppressions(lines) {
  const directives = new Map();
  let invalid = 0;
  for (const [index, raw] of lines.entries()) {
    if (raw.length > 8192 || !raw.includes('srcaudit-ignore')) continue;
    const match = raw.match(DIRECTIVE);
    if (!match) continue;
    const [spec, ...reasonParts] = match[1].split('--');
    const reason = reasonParts.join('--').replace(/(?:\*\/|-->|--\}\})\s*$/, '').trim().slice(0, 300);
    const ids = spec.replace(/^[\s:[]+|[\s\]]+$/g, '').split(/[\s,]+/).filter(Boolean).map((id) => id.toUpperCase());
    if (!reason || ids.some((id) => !/^[A-Z0-9][A-Z0-9_.-]{0,99}$/.test(id))) { invalid++; continue; }
    const target = COMMENT_ONLY.test(raw) ? index + 2 : index + 1;
    const entry = { rules: ids.length ? new Set(ids) : null, reason, line: index + 1 };
    directives.set(target, [...(directives.get(target) ?? []), entry]);
  }
  return { directives, invalid };
}

function directiveFor(finding, directives) {
  const line = finding.location?.line;
  if (!line || !directives) return undefined;
  const ids = [finding.ruleId, ...(finding.relatedRuleIds ?? []), finding.cwe].filter(Boolean).map((id) => String(id).toUpperCase());
  return (directives.get(line) ?? []).find((entry) => !entry.rules || ids.some((id) => entry.rules.has(id)));
}

/** Moves suppressed findings from `report.findings` to `report.suppressed`. */
export function applySuppressions(report, suppressionsByFile) {
  const kept = []; const suppressed = [];
  for (const finding of report.findings) {
    const entry = directiveFor(finding, suppressionsByFile.get(finding.location?.file)?.directives);
    if (entry) suppressed.push({ ...finding, suppression: { kind: 'inSource', reason: entry.reason, line: entry.line } });
    else kept.push(finding);
  }
  report.findings = kept;
  report.suppressed = suppressed;
  const invalid = [...suppressionsByFile.values()].reduce((sum, item) => sum + item.invalid, 0);
  report.stats.suppressions = { applied: suppressed.length, invalidDirectives: invalid };
  if (invalid) report.limitations.push(`${invalid} srcaudit-ignore directives were skipped because their reason or rule ID format was invalid.`);
  return report;
}

const redactLine = (raw) => String(raw ?? '')
  .replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`/g, '""')
  .replace(/\b[A-Za-z0-9_+/=-]{24,}\b/g, '~')
  .replace(/\s+/g, ' ').trim();

/**
 * Stable identity for a finding that survives line shifts. Built only from the
 * rule, the file and redacted content, so the hash never covers a raw credential.
 */
export function assignFingerprints(findings, linesByFile) {
  const seen = new Map();
  for (const finding of findings) {
    const file = finding.location?.file ?? '';
    let content;
    if (finding.advisory) content = `${finding.advisory.package}@${finding.advisory.version}`;
    else if (String(finding.evidence ?? '').startsWith('[REDACTED')) content = '';
    else content = redactLine(linesByFile.get(file)?.[(finding.location?.line ?? 0) - 1]);
    const key = createHash('sha256').update(JSON.stringify([finding.ruleId, file, content])).digest('hex').slice(0, 32);
    const occurrence = seen.get(key) ?? 0;
    seen.set(key, occurrence + 1);
    finding.fingerprint = `${key}:${occurrence}`;
  }
  return findings;
}

export function summarize(report) {
  report.summary = Object.fromEntries(SEVERITIES.map((level) => [level, report.findings.filter((f) => f.severity === level).length]));
  return report;
}

/** Drops findings already present in a previous report.json; records counts in `report.baseline`. */
export function applyBaseline(report, baselineReport, label = 'baseline') {
  if (!Array.isArray(baselineReport?.findings) ||
      (baselineReport.baselineMatched !== undefined && !Array.isArray(baselineReport.baselineMatched))) {
    throw new Error('The baseline must be a SrcAudit report.json file.');
  }
  const known = new Map();
  for (const finding of [...baselineReport.findings, ...(baselineReport.baselineMatched ?? [])]) {
    if (typeof finding?.fingerprint === 'string') known.set(finding.fingerprint, finding);
  }
  if (!known.size && baselineReport.findings.length) throw new Error('The baseline has no finding fingerprints. Regenerate it with the current version of SrcAudit.');
  const fresh = []; const matched = [];
  for (const finding of report.findings) (known.has(finding.fingerprint) ? matched : fresh).push(finding);
  const current = new Set([...report.findings, ...(report.suppressed ?? [])].map((f) => f.fingerprint));
  const sameMode = Boolean(report.stats?.sourceAnalysis) === Boolean(baselineReport.stats?.sourceAnalysis);
  let fixed = 0;
  for (const [fingerprint, finding] of known) {
    if (current.has(fingerprint) || report.status !== 'complete') continue;
    const dependency = finding.advisory || finding.ruleId?.startsWith('DEP-');
    const files = dependency ? report.scanScope?.dependencyFiles : sameMode && report.scanScope?.codeFiles;
    if (files && files.has(finding.location?.file)) fixed++;
  }
  report.findings = fresh;
  if (report.stats?.dependencyAnalysis) report.stats.dependencyAnalysis.findings = fresh.filter(({ advisory }) => advisory).length;
  report.baselineMatched = matched.map(({ fingerprint, ruleId, location }) => ({ fingerprint, ruleId, location }));
  report.baseline = { source: label, known: known.size, matched: matched.length, new: fresh.length, fixed, unassessed: known.size - matched.length - fixed };
  return summarize(report);
}
