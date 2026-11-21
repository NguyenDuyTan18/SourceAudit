// SARIF 2.1.0 export, accepted by GitHub code scanning, GitLab, Azure DevOps and the VS Code SARIF viewer.
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
// GitHub maps security-severity to critical (>= 9.0), high (7.0-8.9), medium (4.0-6.9), low (0.1-3.9).
const SECURITY_SEVERITY = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' };

const toUri = (file) => String(file ?? '').split('\\').join('/').split('/').map(encodeURIComponent).join('/');

function region(location) {
  const startLine = Number.isInteger(location?.line) && location.line > 0 ? location.line : 1;
  const out = { startLine };
  if (Number.isInteger(location?.column) && location.column > 0) out.startColumn = location.column;
  if (Number.isInteger(location?.endLine) && location.endLine >= startLine) {
    out.endLine = location.endLine;
    if (Number.isInteger(location.endColumn) && location.endColumn > 0) out.endColumn = location.endColumn;
  }
  return out;
}

function ruleDescriptor(finding) {
  const tags = ['security', ...(finding.cwe ? [finding.cwe] : [])];
  if (finding.advisory) tags.push('dependency');
  return {
    id: finding.ruleId,
    name: finding.ruleId.replace(/[^A-Za-z0-9]+/g, ''),
    shortDescription: { text: finding.advisory ? `${finding.advisory.cve || finding.advisory.id}: ${finding.advisory.package}` : finding.title },
    fullDescription: { text: finding.impact || finding.title },
    help: { text: finding.remediation || '', markdown: `${finding.remediation || ''}${finding.reference ? `\n\n[Tham khảo](${finding.reference})` : ''}` },
    ...(finding.reference ? { helpUri: finding.reference } : {}),
    defaultConfiguration: { level: LEVEL[finding.severity] ?? 'warning' },
    properties: { tags, precision: finding.confidence === 'high' ? 'high' : finding.confidence === 'low' ? 'low' : 'medium', 'security-severity': SECURITY_SEVERITY[finding.severity] ?? '5.5' },
  };
}

export function renderSarif(report) {
  const rules = []; const ruleIndex = new Map();
  const all = [...report.findings, ...(report.suppressed ?? [])];
  for (const finding of all) {
    if (ruleIndex.has(finding.ruleId)) continue;
    ruleIndex.set(finding.ruleId, rules.length);
    rules.push(ruleDescriptor(finding));
  }
  const result = (finding) => ({
    ruleId: finding.ruleId,
    ruleIndex: ruleIndex.get(finding.ruleId),
    level: LEVEL[finding.severity] ?? 'warning',
    message: { text: `${finding.title}. ${finding.evidence ?? ''}`.trim() },
    locations: [{ physicalLocation: { artifactLocation: { uri: toUri(finding.location?.file), uriBaseId: '%SRCROOT%' }, region: region(finding.location) } }],
    ...(finding.trace?.length ? {
      codeFlows: [{ threadFlows: [{ locations: finding.trace.map((step) => ({ location: {
        physicalLocation: { artifactLocation: { uri: toUri(step.file), uriBaseId: '%SRCROOT%' }, region: { startLine: step.line } },
        message: { text: `[${step.role}] ${step.evidence}` },
      } })) }] }],
    } : {}),
    ...(finding.fingerprint ? { partialFingerprints: { 'srcauditFingerprint/v1': finding.fingerprint } } : {}),
    ...(finding.suppression ? { suppressions: [{ kind: 'inSource', justification: finding.suppression.reason }] } : {}),
    properties: { severity: finding.severity, confidence: finding.confidence, status: finding.status, ...(finding.cwe ? { cwe: finding.cwe } : {}), ...(finding.context ? { context: finding.context } : {}) },
  });
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'SrcAudit', semanticVersion: report.version, version: report.version, rules } },
      automationDetails: { id: `srcaudit/${report.mode}/${report.stats?.sourceAnalysis?.mode ?? 'quick'}/` },
      invocations: [{
        executionSuccessful: report.status === 'complete',
        startTimeUtc: report.startedAt, ...(report.finishedAt ? { endTimeUtc: report.finishedAt } : {}),
        toolExecutionNotifications: report.errors.map((text) => ({ level: 'warning', message: { text } })),
      }],
      results: all.map(result),
    }],
  };
}
