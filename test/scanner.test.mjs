import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { scanSource } from '../src/source.mjs';
import { createReport, renderText, renderHtml, writeReports } from '../src/report.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'security-scanner-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('source groups SQL construction with its sink and keeps distinct calls separate', async (t) => {
  const root = await fixture(t);
  const file = path.join(root, 'route.js');
  await writeFile(file, [
    'function route(req) {',
    '  const id = req.query.id;',
    '  const statement = "SELECT * FROM users WHERE id=" + id;',
    '  db.query(statement);',
    '  db.query(statement);',
    '}',
  ].join('\n'));
  const report = await scanSource(file);
  const sql = report.findings.filter(({ cwe }) => cwe === 'CWE-89');
  assert.deepEqual(sql.map(({ location }) => location.line), [4, 5]);
  for (const finding of sql) {
    assert.deepEqual(finding.trace.map(({ line }) => line), [2, 3, finding.location.line]);
    assert.ok(finding.relatedRuleIds.includes('SRC-SQL'));
    assert.match(finding.remediation, /tham số/i);
  }
  assert.match(renderText(report), /Dòng liên quan[\s\S]*route\.js:3/);
  assert.match(renderHtml(report), /Cách khắc phục[\s\S]*Dòng liên quan/);
});

test('source identifies risky sinks with file, line and remediation; never copies credentials', async (t) => {
  const root = await fixture(t);
  const secret = ['madeup', 'credential', '1234567890'].join('-');
  await writeFile(path.join(root, 'app.js'), `const password = "${secret}";\neval(req.query.code);\nchild_process.exec(req.query.cmd);\ndb.query("SELECT * FROM users WHERE id=" + req.query.id);\nres.send("<b>" + req.query.name);\n`);
  const report = await scanSource(root);
  for (const id of ['SRC-SECRET', 'SRC-EVAL', 'SRC-SHELL', 'SRC-SQL', 'SRC-XSS']) {
    const finding = report.findings.find((f) => f.ruleId === id);
    assert.ok(finding, id);
    assert.equal(finding.location.file, 'app.js');
    assert.ok(finding.location.line > 0);
    assert.ok(finding.remediation);
    assert.equal(finding.status, 'needs-review');
  }
  assert.ok(!JSON.stringify(report).includes(secret));
  assert.equal(report.status, 'complete');
});

test('source skips dependencies, comments, binary and oversized files; records limits', async (t) => {
  const root = await fixture(t);
  await mkdir(path.join(root, 'node_modules'));
  await writeFile(path.join(root, 'node_modules', 'bad.js'), 'eval(input)');
  await writeFile(path.join(root, 'safe.js'), '// eval(req.query.code)\nconst x = 1;');
  await writeFile(path.join(root, 'large.js'), 'x'.repeat(120));
  await writeFile(path.join(root, 'binary.js'), Buffer.from([0, 1, 2]));
  let report = await scanSource(root, { maxFileBytes: 100 });
  assert.equal(report.findings.length, 0);
  assert.equal(report.status, 'partial');
  assert.ok(report.errors.some((e) => e.includes('large.js')));
  report = await scanSource(root, { maxFiles: 1 });
  assert.equal(report.status, 'partial');
  await assert.rejects(scanSource(path.join(root, 'missing')), /không|not|ENOENT/i);
});

test('source supports single files, Python, PHP, config and private-key detection', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'app.py'), 'import pickle\npickle.loads(data)\nsubprocess.run(cmd, shell=True)\napp.run(debug=True)\nyaml.load(data)');
  await writeFile(path.join(root, 'index.php'), '<?php\nmysqli_query($db, "SELECT * FROM users WHERE id=" . $_GET["id"]);\nunserialize($_POST["data"]);');
  await writeFile(path.join(root, '.env'), 'DEBUG=true\nAPI_KEY="synthetic-not-a-real-key-12345"');
  await writeFile(path.join(root, 'key.pem'), '-----BEGIN PRIVATE KEY-----\nSYNTHETIC\n-----END PRIVATE KEY-----');
  const report = await scanSource(root);
  for (const rule of ['SRC-DESERIALIZE', 'SRC-SHELL', 'SRC-DEBUG', 'SRC-SQL', 'SRC-PRIVATE-KEY']) assert.ok(report.findings.some((f) => f.ruleId === rule), rule);
  assert.ok(!JSON.stringify(report).includes('synthetic-not-a-real-key-12345'));
  const single = await scanSource(path.join(root, 'app.py'));
  assert.equal(single.stats.filesScanned, 1);
});

test('shell exec is not mislabeled as JavaScript code eval', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'app.js'), 'child_process.exec(req.query.cmd);');
  const report = await scanSource(root);
  assert.ok(report.findings.some((f) => f.ruleId === 'SRC-SHELL'));
  assert.ok(!report.findings.some((f) => f.ruleId === 'SRC-EVAL'));
});

test('unquoted environment secrets are flagged, and a finding cap is reported as partial', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, '.env'), 'API_KEY=demo-only-no-real-credential-123456\nPASSWORD=another-demo-only-value');
  let report = await scanSource(root);
  assert.equal(report.findings.filter((f) => f.ruleId === 'SRC-SECRET').length, 2);
  assert.ok(!JSON.stringify(report).includes('demo-only-no-real'));
  await writeFile(path.join(root, 'app.js'), 'eval(input);\neval(input);\neval(input);');
  report = await scanSource(root, { maxFindings: 1 });
  assert.equal(report.findings.length, 1);
  assert.equal(report.status, 'partial');
});

test('extremely long source lines are skipped with a visible incomplete result', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'minified.js'), 'eval(input);' + 'x'.repeat(9000));
  const report = await scanSource(root);
  assert.equal(report.status, 'partial');
  assert.equal(report.findings.length, 0);
  assert.ok(report.errors.some((error) => error.includes('minified.js:1')));
});

test('an empty source directory gives an incomplete result', async (t) => {
  const report = await scanSource(await fixture(t));
  assert.equal(report.status, 'failed');
});

test('reports escape untrusted HTML, preserve details and save readable outputs', async (t) => {
  const root = await fixture(t);
  const report = createReport('source', '<script>alert(1)</script>');
  report.findings.push({ ruleId: 'TEST', title: '<img src=x onerror=alert(1)>', severity: 'high', confidence: 'medium', status: 'needs-review', cwe: 'CWE-79', location: { file: 'app.js', line: 4 }, evidence: 'line', impact: 'impact', remediation: 'fix', reference: 'https://owasp.org/' });
  const html = renderHtml(report);
  assert.ok(!html.includes('<img src=x'));
  assert.ok(html.includes('&lt;img'));
  assert.match(renderText(report), /CWE-79/);
  const files = await writeReports(report, path.join(root, 'reports'));
  assert.equal(JSON.parse(await readFile(files.json, 'utf8')).findings.length, 1);
  assert.match(await readFile(files.html, 'utf8'), /Content-Security-Policy/);
});

test('CLI end to end accepts source, produces detailed output and handles invalid arguments', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'app.js'), 'eval(req.query.code);');
  const run = (...args) => spawnSync(process.execPath, ['scan.mjs', ...args], { cwd: path.resolve(import.meta.dirname, '..'), encoding: 'utf8' });
  let result = run('--src', root, '--out', path.join(root, 'report'), '--fail-on', 'high');
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stdout, /SRC-EVAL/);
  assert.match(result.stdout, /app.js:1/);
  result = run('--help');
  assert.equal(result.status, 0);
  assert.doesNotMatch(result.stdout, /--url|--allow-private/);
  for (const args of [[], ['--wat'], ['--url', 'https://example.test'], ['https://example.test'], ['--src', 'https://example.test'], ['--src', root, '--max-pages', '0'], ['--src']]) {
    result = run(...args);
    assert.equal(result.status, 2, args.join(' '));
  }
});
