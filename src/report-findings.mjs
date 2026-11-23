export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export function scanModeLabel(mode) {
  return mode === 'deep' ? 'Deep Scan with Semgrep' : 'Quick Scan';
}

export function reportMode(report) {
  return report?.stats?.sourceAnalysis ? 'deep' : 'quick';
}

export function locationText(location = {}) {
  if (location.url) return location.url;
  if (location.line) {
    const start = `${location.file}:${location.line}${location.column ? ':' + location.column : ''}`;
    return location.endLine ? `${start}–${location.endLine}${location.endColumn ? ':' + location.endColumn : ''}` : start;
  }
  return (location.file ?? '') + (location.pointer ? ' #' + location.pointer : '');
}

export function findingStatement(finding) {
  const marked = finding.sourceExcerpt?.split('\n').filter((line) => line.startsWith('> ')).join('\n');
  return marked || finding.matchedOperation || finding.evidence || '';
}

export function flowTraceText(occurrences) {
  return occurrences.filter(({ trace }) => trace?.length).map(({ trace }) =>
    trace.map(({ file, line, role, evidence }) => `${file}:${line} [${role}] ${evidence}`).join('\n')).join('\n\n');
}

export function groupReportFindings(findings) {
  const groups = new Map();
  for (const finding of findings) {
    const { ruleId, advisory, location } = finding;
    const key = JSON.stringify([ruleId, advisory?.ecosystem, advisory?.package, advisory?.version]);
    if (!groups.has(key)) groups.set(key, { finding, occurrences: new Map() });
    const group = groups.get(key);
    if (SEVERITIES.indexOf(finding.severity) < SEVERITIES.indexOf(group.finding.severity)) group.finding = finding;
    const locationKey = JSON.stringify([locationText(location), location?.pointer]);
    const previous = group.occurrences.get(locationKey);
    if (!previous || (!previous.sourceExcerpt && finding.sourceExcerpt)) group.occurrences.set(locationKey, finding);
  }
  return [...groups.values()].map(({ finding, occurrences }) => ({ finding, occurrences: [...occurrences.values()] }));
}
