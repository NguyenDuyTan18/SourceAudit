import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { scanSource } from '../src/source.mjs';
import { isIgnored, parseGitignore } from '../src/gitignore.mjs';
import { applyBaseline, collectSuppressions } from '../src/triage.mjs';
import { renderSarif } from '../src/sarif.mjs';
import { extractDependencies, parsePnpmLock, parseYarnLock } from '../src/dependencies.mjs';
import { changedFiles, pathKey } from '../src/git-diff.mjs';

const repoRoot = path.resolve(import.meta.dirname, '..');
async function fixture(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'srcaudit-ci-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}
const cli = (...args) => spawnSync(process.execPath, ['scan.mjs', ...args], { cwd: repoRoot, encoding: 'utf8' });

test('gitignore matcher follows git pattern rules', () => {
  const root = parseGitignore('# comment\n*.log\n/build\nsecrets/\n!keep.log\ndocs/**/draft.md\n\\#hash\nfoo/**\n');
  const ignored = (p, dir = false) => isIgnored([root], p, dir);
  assert.ok(ignored('a/b/debug.log'));
  assert.ok(!ignored('keep.log'));
  assert.ok(ignored('build', true));
  assert.ok(!ignored('src/build', true), 'leading slash anchors to the .gitignore directory');
  assert.ok(ignored('x/secrets', true));
  assert.ok(!ignored('x/secrets', false), 'trailing slash matches directories only');
  assert.ok(ignored('docs/draft.md') && ignored('docs/a/b/draft.md'));
  assert.ok(ignored('#hash'));
  assert.ok(ignored('foo/x.js') && !ignored('foo', true));
  const classes = parseGitignore('*.[oa]\nlib[!x].js\n[abc\n');
  assert.ok(isIgnored([classes], 'x/main.o', false) && isIgnored([classes], 'lib.a', false));
  assert.ok(isIgnored([classes], 'liby.js', false) && !isIgnored([classes], 'libx.js', false));
  assert.ok(isIgnored([classes], '[abc', false), 'unterminated class is literal');
  const nested = parseGitignore('*.tmp.js\n', 'pkg');
  assert.ok(isIgnored([root, nested], 'pkg/a/x.tmp.js', false));
  assert.ok(!isIgnored([root, nested], 'other/x.tmp.js', false));
});

test('scanner respects .gitignore by default and can disable it', async (t) => {
  const root = await fixture(t);
  await mkdir(path.join(root, 'generated'));
  await writeFile(path.join(root, '.gitignore'), 'generated/\n');
  await writeFile(path.join(root, 'generated', 'bundle.js'), 'eval(req.query.code);');
  await writeFile(path.join(root, 'app.js'), 'const ok = 1;');
  const respected = await scanSource(root);
  assert.equal(respected.findings.length, 0);
  assert.equal(respected.stats.gitignore.ignored, 1);
  const all = await scanSource(root, { gitignore: false });
  assert.ok(all.findings.some((f) => f.location.file === 'generated/bundle.js'));
});

test('inline srcaudit-ignore needs a reason and only hides the targeted rule', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'app.js'), [
    'eval(req.query.a); // srcaudit-ignore SRC-EVAL -- chỉ chạy trong sandbox test',
    '// srcaudit-ignore -- cả dòng dưới là mã mẫu',
    'eval(req.query.b);',
    'eval(req.query.c); // srcaudit-ignore SRC-EVAL',
    'eval(req.query.d); // srcaudit-ignore SRC-SQL -- sai quy tắc nên không ẩn',
  ].join('\n'));
  const report = await scanSource(root);
  const lines = (list) => list.filter((f) => f.ruleId === 'SRC-EVAL').map((f) => f.location.line).sort();
  assert.deepEqual(lines(report.suppressed), [1, 3]);
  assert.deepEqual(lines(report.findings), [4, 5]);
  assert.equal(report.suppressed[0].suppression.reason, 'chỉ chạy trong sandbox test');
  assert.equal(report.stats.suppressions.invalidDirectives, 1);
  assert.equal(report.summary.high, report.findings.filter((f) => f.severity === 'high').length);
  assert.equal(collectSuppressions(['x # srcaudit-ignore CWE-89 -- ok']).directives.get(1)[0].rules.has('CWE-89'), true);
});

test('fingerprints survive line shifts and baseline only reports new findings', async (t) => {
  const root = await fixture(t);
  const file = path.join(root, 'app.js');
  await writeFile(file, 'eval(req.query.a);\nconst password = "hunter2-hunter2";\n');
  const before = await scanSource(root);
  assert.ok(before.findings.every((f) => /^[0-9a-f]{32}:\d+$/.test(f.fingerprint)));
  assert.ok(!JSON.stringify(before).includes('hunter2'));
  await writeFile(file, '\n\n// moved\neval(req.query.a);\nconst password = "hunter2-hunter2";\neval(req.body.b);\n');
  const after = await scanSource(root);
  applyBaseline(after, JSON.parse(JSON.stringify(before)), 'before.json');
  assert.deepEqual(after.findings.map((f) => f.location.line), [6]);
  assert.equal(after.baseline.matched, before.findings.length);
  assert.equal(after.baseline.fixed, 0);
  assert.equal(after.summary.high, 1);
  assert.throws(() => applyBaseline(after, { nope: true }), /report\.json/);
});

test('deep diff with no eligible targets completes and leaves baseline entries unassessed', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'app.js'), 'const value = 1;\n');
  const report = await scanSource(root, { analysis: 'deep', onlyFiles: new Set() });
  assert.equal(report.status, 'complete');
  assert.equal(report.stats.sourceAnalysis.scanned, 0);
  applyBaseline(report, { findings: [{ fingerprint: 'old', location: { file: 'app.js' } }] });
  assert.equal(report.baseline.fixed, 0);
  assert.equal(report.baseline.unassessed, 1);
});

test('baseline marks only previously flagged files assessed by the current diff as fixed', async (t) => {
  const root = await fixture(t);
  const changed = path.join(root, 'changed.js');
  const unchanged = path.join(root, 'unchanged.js');
  for (const file of [changed, unchanged]) await writeFile(file, 'eval(req.query.input);\n');
  const baseline = await scanSource(root);
  assert.equal(baseline.findings.length, 2);
  await writeFile(changed, 'const value = 1;\n');
  const report = await scanSource(root, { onlyFiles: new Set([pathKey(changed)]) });
  applyBaseline(report, baseline);
  assert.equal(report.baseline.fixed, 1);
  assert.equal(report.baseline.unassessed, 1);
});

test('a dependency-only deep scan assesses Composer pins and skips unsupported version syntax', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'composer.lock'), JSON.stringify({
    packages: [{ name: 'twig/twig', version: 'v3.25.0' }, { name: 'twig/twig', version: 'dev-main' }],
    'packages-dev': [{ name: 'phpunit/phpunit', version: '13.4.4' }],
  }));
  const report = await scanSource(root, { analysis: 'deep' });
  assert.equal(report.status, 'complete');
  assert.equal(report.stats.sourceAnalysis.status, 'skipped');
  assert.equal(report.stats.dependencyAnalysis.unresolved, 1);
  const twig = report.findings.find(({ advisory }) => advisory?.id === 'GHSA-7p85-w9px-jpjp');
  assert.equal(twig.location.file, 'composer.lock');
  assert.equal(twig.location.pointer, '/packages/0');
  assert.equal(twig.advisory.ecosystem, 'composer');
});

test('deep scan checks dependency manifests alongside source files', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'app.js'), 'const value = 1;\n');
  await writeFile(path.join(root, 'requirements.txt'), 'Django==1.11.0\n');
  const report = await scanSource(root, {
    analysis: 'deep',
    semgrepRunner: async (files) => {
      assert.deepEqual(files.map(({ file }) => file), ['app.js']);
      return { status: 'complete', scanned: 1, findings: [] };
    },
  });
  assert.equal(report.status, 'complete');
  assert.equal(report.stats.dependencyAnalysis.packages, 1);
  assert.ok(report.findings.some(({ advisory }) => advisory?.ecosystem === 'pip'));
});

test('SARIF export is valid 2.1.0 with rules, regions, fingerprints and suppressions', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'app.js'), 'eval(req.query.a);\neval(req.query.b); // srcaudit-ignore SRC-EVAL -- test\n');
  await writeFile(path.join(root, 'package-lock.json'), JSON.stringify({ packages: { 'node_modules/lodash': { version: '4.17.20' } } }));
  const sarif = renderSarif(await scanSource(root));
  assert.equal(sarif.version, '2.1.0');
  const [run] = sarif.runs;
  assert.equal(run.tool.driver.name, 'SrcAudit');
  const ids = run.tool.driver.rules.map((rule) => rule.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const result of run.results) {
    assert.equal(run.tool.driver.rules[result.ruleIndex].id, result.ruleId);
    assert.ok(['error', 'warning', 'note'].includes(result.level));
    assert.ok(result.locations[0].physicalLocation.region.startLine >= 1);
    assert.ok(result.partialFingerprints['srcauditFingerprint/v1']);
  }
  const suppressed = run.results.filter((r) => r.suppressions);
  assert.equal(suppressed.length, 1);
  assert.equal(suppressed[0].locations[0].physicalLocation.region.startLine, 2);
  const dep = run.results.find((r) => r.ruleId.startsWith('DEP-'));
  assert.equal(dep.locations[0].physicalLocation.artifactLocation.uri, 'package-lock.json');
  assert.ok(run.tool.driver.rules.every((rule) => Number(rule.properties['security-severity']) >= 0));

  await writeFile(path.join(root, 'route.js'), 'function r(req) {\n  const id = req.query.id;\n  const s = "SELECT * FROM t WHERE id=" + id;\n  db.query(s);\n}\n');
  const flow = renderSarif(await scanSource(root)).runs[0].results.find((r) => r.codeFlows);
  assert.ok(flow, 'text-flow finding exports a codeFlow');
  assert.deepEqual(flow.codeFlows[0].threadFlows[0].locations.map((l) => l.location.physicalLocation.region.startLine), [2, 3, 4]);
});

test('yarn.lock v1 / Berry and pnpm-lock v5 / v6 / v9 resolve exact versions', () => {
  const yarnV1 = [
    '# yarn lockfile v1', '',
    '"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4":', '  version "7.12.13"', '  resolved "https://registry/x.tgz"', '',
    'lodash@^4.17.0:', '  version "4.17.20"', '',
  ].join('\n');
  assert.deepEqual(parseYarnLock(yarnV1).map(({ name, version, line }) => [name, version, line]), [['@babel/code-frame', '7.12.13', 4], ['lodash', '4.17.20', 8]]);
  const berry = [
    '__metadata:', '  version: 6', '',
    '"lodash@npm:^4.17.0, lodash@npm:^4.17.20":', '  version: 4.17.20', '',
    '"my-app@workspace:.":', '  version: 0.0.0-use.local', '',
  ].join('\n');
  const berryResult = extractDependencies('yarn.lock', berry);
  assert.deepEqual(berryResult.packages.map((p) => `${p.name}@${p.version}`), ['lodash@4.17.20']);
  const pnpm5 = 'lockfileVersion: 5.4\npackages:\n  /lodash/4.17.20:\n    resolution: {}\n  /@babel/plugin/7.0.0_@babel+core@7.0.0:\n    dev: true\n';
  const pnpm6 = "lockfileVersion: '6.0'\npackages:\n  /lodash@4.17.20:\n    resolution: {}\n  /@scope/pkg@1.2.3(react@18.0.0):\n    dev: false\n";
  const pnpm9 = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies: {}\npackages:\n  lodash@4.17.20:\n    resolution: {}\n  '@scope/pkg@1.2.3':\n    resolution: {}\nsnapshots:\n  lodash@4.17.20: {}\n";
  const names = (text) => parsePnpmLock(text).filter((e) => e.name).map((e) => `${e.name}@${e.version}`);
  assert.deepEqual(names(pnpm5), ['lodash@4.17.20', '@babel/plugin@7.0.0']);
  assert.deepEqual(names(pnpm6), ['lodash@4.17.20', '@scope/pkg@1.2.3']);
  assert.deepEqual(extractDependencies('pnpm-lock.yaml', pnpm9).packages.map((p) => `${p.name}@${p.version}`), ['lodash@4.17.20', '@scope/pkg@1.2.3']);
});

test('vulnerable package in yarn.lock is reported at the version line', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'yarn.lock'), 'lodash@^4.17.0:\n  version "4.17.20"\n');
  const report = await scanSource(root);
  const cve = report.findings.find((f) => f.advisory?.cve === 'CVE-2021-23337');
  assert.ok(cve);
  assert.equal(cve.location.line, 2);
  assert.equal(report.stats.dependencyAnalysis.unsupportedManifests, 0);
});

const git = (cwd, ...args) => spawnSync('git', args, { cwd, encoding: 'utf8' });
const hasGit = git(repoRoot, '--version').status === 0;

test('--diff scans only files changed since the merge base, including untracked ones', { skip: !hasGit && 'git không có trên PATH' }, async (t) => {
  const root = await fixture(t);
  const run = (...args) => assert.equal(git(root, ...args).status, 0, args.join(' '));
  run('init', '-q', '-b', 'main');
  run('-c', 'user.email=t@example.invalid', '-c', 'user.name=t', 'commit', '-q', '--allow-empty', '-m', 'root');
  await writeFile(path.join(root, 'old.js'), 'eval(req.query.old);');
  run('add', '.');
  run('-c', 'user.email=t@example.invalid', '-c', 'user.name=t', 'commit', '-q', '-m', 'old');
  run('checkout', '-q', '-b', 'feature');
  await writeFile(path.join(root, 'new.js'), 'eval(req.query.fresh);');
  const diff = await changedFiles(root, 'main');
  assert.equal(diff.files.size, 1);
  const report = await scanSource(root, { onlyFiles: diff.files, diffInfo: { ref: 'main' } });
  assert.deepEqual([...new Set(report.findings.map((f) => f.location.file))], ['new.js']);
  assert.equal(report.stats.diff.unchanged, 1);
  await assert.rejects(changedFiles(root, '--output=/tmp/x'), /hợp lệ/);
  await assert.rejects(changedFiles(root, 'no-such-branch'), /git/);

  const out = path.join(root, '.scanner-reports', 'diff');
  const result = cli('--src', root, '--diff', 'main', '--out', out, '--fail-on', 'high');
  assert.equal(result.status, 1, result.stderr);
  const sarif = JSON.parse(await readFile(path.join(out, 'report.sarif'), 'utf8'));
  assert.deepEqual([...new Set(sarif.runs[0].results.map((r) => r.locations[0].physicalLocation.artifactLocation.uri))], ['new.js']);
});

test('CLI writes SARIF and --baseline turns a failing scan into a passing one', async (t) => {
  const root = await fixture(t);
  await mkdir(path.join(root, 'src'));
  await writeFile(path.join(root, 'src', 'app.js'), 'eval(req.query.code);');
  const first = path.join(root, 'out1'); const second = path.join(root, 'out2');
  const initial = cli('--src', path.join(root, 'src'), '--out', first, '--fail-on', 'high');
  assert.equal(initial.status, 1, initial.stderr);
  assert.match(initial.stdout, /report\.sarif/);
  const baselined = cli('--src', path.join(root, 'src'), '--out', second, '--fail-on', 'high', '--baseline', path.join(first, 'report.json'));
  assert.equal(baselined.status, 0, baselined.stderr);
  assert.match(baselined.stdout, /Không có phát hiện mới so với baseline/);
  const bad = path.join(root, 'bad.json');
  await writeFile(bad, '{"findings":[{"ruleId":"X"}]}');
  const rejected = cli('--src', path.join(root, 'src'), '--out', path.join(root, 'out3'), '--baseline', bad);
  assert.equal(rejected.status, 2);
  assert.match(rejected.stderr, /fingerprint/);
  assert.equal(cli('--list-rules', '--diff', 'main').status, 2);
});
