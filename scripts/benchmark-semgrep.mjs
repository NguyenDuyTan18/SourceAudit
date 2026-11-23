import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanSource } from '../src/source.mjs';
import { pairs as internalCases } from './benchmark-cases.mjs';
import { frameworkConfigCases } from './semgrep-framework-config-cases.mjs';
import { pythonCoverageCases } from './semgrep-python-coverage-cases.mjs';

const pairs = [...internalCases, ...pythonCoverageCases];
const compareQuick = process.argv.includes('--compare-quick');

const folder = await mkdtemp(path.join(tmpdir(), 'scanner-semgrep-bench-'));
try {
  const filename = (item, variant) => item.name + '-' + variant + (item.target ? '/' + item.target : '.' + item.ext);
  for (const item of pairs) {
    for (const variant of ['vulnerable', 'fixed']) {
      const destination = path.join(folder, filename(item, variant));
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, item[variant], { flag: 'wx' });
    }
  }
  const deep = await scanSource(folder, { analysis: 'deep' });
  if (deep.status !== 'complete') throw new Error(deep.errors.join(' '));
  assert.equal(deep.stats.sourceAnalysis.scanned, pairs.length * 2);
  const quick = compareQuick ? await scanSource(folder) : undefined;
  if (quick) assert.equal(quick.stats.filesScanned, pairs.length * 2);
  const languages = { js: 'JavaScript', ts: 'TypeScript', py: 'Python', php: 'PHP', java: 'Java', go: 'Go', cs: 'C#', rb: 'Ruby' };
  const expectedCounts = {};
  for (const item of pairs) {
    const count = expectedCounts[item.language ?? languages[item.ext]] ??= { selected: 0, scanned: 0 };
    count.selected += 2;
    count.scanned += 2;
  }
  assert.deepEqual(deep.stats.sourceAnalysis.languages, expectedCounts);

  const matching = (report, item, variant) => report.findings.filter((finding) =>
    finding.cwe === item.cwe && finding.location.file === filename(item, variant));
  const detected = (report, item, variant) => matching(report, item, variant).length > 0;
  const rows = pairs.map((item) => ({
    case: item.name, cwe: item.cwe,
    deepVulnerable: detected(deep, item, 'vulnerable'),
    deepFixedFlagged: detected(deep, item, 'fixed'),
    ...(quick ? { quickVulnerable: detected(quick, item, 'vulnerable'), quickFixedFlagged: detected(quick, item, 'fixed') } : {}),
  }));
  console.table(rows);
  console.log(JSON.stringify({
    pairs: rows.length,
    deepDetected: rows.filter((row) => row.deepVulnerable).length,
    deepFalsePositives: rows.filter((row) => row.deepFixedFlagged).length,
    ...(quick ? {
      quickDetected: rows.filter((row) => row.quickVulnerable).length,
      quickFalsePositives: rows.filter((row) => row.quickFixedFlagged).length,
      newlyDetected: rows.filter((row) => !row.quickVulnerable && row.deepVulnerable).map((row) => row.case),
    } : {}),
  }, null, 2));
  assert.ok(rows.every((row) => row.deepVulnerable && !row.deepFixedFlagged), 'Deep mode must distinguish every fixture pair.');
  for (const item of frameworkConfigCases) {
    const findings = matching(deep, item, 'vulnerable');
    assert.deepEqual(findings.map(({ ruleId }) => ruleId), [item.ruleId], item.name);
    assert.ok(findings[0].remediation, item.name);
    assert.doesNotMatch(JSON.stringify(findings), /SYNTHETIC_KEY_FIXTURE/, item.name);
  }
  for (const item of pairs.filter(({ sink }) => sink)) {
    const finding = deep.findings.find(({ location, cwe }) => location.file === filename(item, 'vulnerable') && cwe === item.cwe);
    const { line, column } = finding.location;
    assert.equal(item.vulnerable.split('\n')[line - 1]?.slice(column - 1, column - 1 + item.sink.length), item.sink, item.name);
    if (item.multiline) {
      assert.ok(finding.location.endLine > line, item.name);
      if (finding.sourceExcerpt) assert.ok(finding.sourceExcerpt.includes('> ' + finding.location.endLine + ' |'), item.name);
    }
    if (item.ext === 'js' || item.ext === 'ts') assert.ok(finding.sourceExcerpt, item.name);
    else assert.equal(finding.sourceExcerpt, undefined);
  }
  const examples = fileURLToPath(new URL('../examples/', import.meta.url));
  const collected = await scanSource(examples, { analysis: 'deep' });
  assert.equal(collected.status, 'complete', collected.errors.join(' '));
  const expected = [
    ['demo-src/app.js', 'CWE-22'],
    ['demo-src/app.js', 'CWE-79'],
    ['demo-src/app.js', 'CWE-601'],
    ['demo-src/app.js', 'CWE-1321'],
    ['demo-src/app.js', 'CWE-95'],
    ['research-demo/app.js', 'CWE-79'],
    ['research-demo/app.js', 'CWE-943'],
    ['research-demo/app.js', 'CWE-95'],
  ];
  for (const [file, cwe] of expected) {
    assert.ok(collected.findings.some((finding) => finding.location.file === file && finding.cwe === cwe), file + ' ' + cwe);
  }
  const evaluated = collected.findings.find((finding) =>
    finding.location.file === 'demo-src/app.js' && finding.ruleId === 'srcaudit-js-code-injection');
  assert.match(evaluated.sourceExcerpt, /> \d+ \|.*eval\(req\.query\.code\)/);
  assert.doesNotMatch(evaluated.sourceExcerpt, /DEMO-ONLY-NOT-A-REAL-CREDENTIAL/);
  console.log(JSON.stringify({ collectedFilesScanned: collected.stats.sourceAnalysis.scanned, expectedMatches: expected }));
} finally {
  await rm(folder, { recursive: true, force: true });
}
