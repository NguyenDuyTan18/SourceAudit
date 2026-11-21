import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { scanSource } from '../src/source.mjs';
import { classifySecret, fileContext } from '../src/context.mjs';
import { enrichReport } from '../src/knowledge.mjs';

async function fixture(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'srcaudit-context-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('secret classification separates references, placeholders and possible real values', () => {
  for (const line of ['password = "${DB_PASSWORD}"', 'api_key: "{{ vault.key }}"', "secret_key = '<your-secret-here>'", 'token = "process.env.TOKEN"', 'PASSWORD=$DB_PASS']) {
    assert.equal(classifySecret(line), 'reference', line);
  }
  for (const line of ["SECRET_KEY = 'development key'", 'password = "changeme123"', 'api_key = "xxxxxxxxxxxx"', 'token = "********"', 'secret = "your-api-key"', 'password = "aaaaaaaaaa"']) {
    assert.equal(classifySecret(line), 'placeholder', line);
  }
  for (const line of ['password = "hunter2-hunter2"', 'secret = "super-secret-123"', 'api_key = "AKIAIOSFODNN7EXAMPLE"', 'token = "q8Zr!w2Lp#kD9"', '-----BEGIN RSA PRIVATE KEY-----']) {
    assert.equal(classifySecret(line), undefined, line);
  }
});

test('file context recognizes tests, examples and generated bundles', () => {
  assert.equal(fileContext('src/__tests__/a.js'), 'test');
  assert.equal(fileContext('lib/user.spec.ts'), 'test');
  assert.equal(fileContext('pkg/test_views.py'), 'test');
  assert.equal(fileContext('cmd/server_test.go'), 'test');
  assert.equal(fileContext('docs/examples/app.js'), 'example');
  assert.equal(fileContext('config/settings.example.py'), 'example');
  assert.equal(fileContext('public/app.min.js'), 'generated');
  assert.equal(fileContext('src/contest.js'), undefined);
  assert.equal(fileContext('src/latest/test.js'), undefined);
});

test('quick scan reports weak hashlib names and unverified TLS with targeted context', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'digest.py'), [
    'import hashlib, ssl, tempfile',
    'weak = hashlib.new("MD5", data)',
    'checksum = hashlib.new("sha1", data, usedforsecurity=False)',
    'strong = hashlib.new("sha256", data)',
    'unsafe = ssl._create_unverified_context()',
    'safe = ssl.create_default_context()',
    'name = tempfile.mktemp()',
    'file = tempfile.NamedTemporaryFile()',
  ].join('\n'));
  const report = await scanSource(root);
  const findings = report.findings.filter(({ cwe }) => ['CWE-327', 'CWE-295', 'CWE-377'].includes(cwe));
  assert.deepEqual(findings.map(({ location }) => location.line).sort((a, b) => a - b), [2, 5, 7]);
  assert.ok(findings.every(({ detection, reference }) => detection.condition.length > 20 && reference.startsWith('https://')));
  enrichReport(report);
  assert.deepEqual(findings.map(({ knowledge }) => knowledge.topic).sort(), ['temporary-files', 'tls-validation', 'weak-digest']);
});

test('quick scan distinguishes Python random generators and multiline cookie policy', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'cookie.py'), [
    'import random, secrets',
    'from flask import make_response',
    'token = random.getrandbits(64)',
    'other = secrets.randbits(64)',
    'system = random.SystemRandom().getrandbits(64)',
    'response = make_response("OK")',
    'response.set_cookie(',
    '    "sid", "example", secure=False,',
    ')',
    'response.set_cookie("sid", "example", secure=True)',
    'response.set_cookie("sid", "secure=False")',
    'response.set_cookie("sid", helper(secure=False), secure=True)',
    'response.set_cookie("sid", "example", secure=False, partitioned=True)',
    'other = PreferenceStore()',
    'other.set_cookie("sid", "example", secure=False)',
  ].join('\n'));
  const report = await scanSource(root);
  const findings = report.findings.filter(({ cwe }) => ['CWE-338', 'CWE-614'].includes(cwe));
  assert.deepEqual(findings.map(({ location }) => location.line).sort((a, b) => a - b), [3, 7]);
});

test('scanner drops references, downgrades placeholders, test code and dev-only debug flags', async (t) => {
  const root = await fixture(t);
  await mkdir(path.join(root, 'tests'));
  await writeFile(path.join(root, 'app.js'), [
    'const password = "${DB_PASSWORD}";',
    'const apiKey = "changeme-please";',
    'const secret = "q8Zr!w2Lp#kD9xx";',
    'eval(req.query.code);',
  ].join('\n'));
  await writeFile(path.join(root, 'tests', 'app.test.js'), 'eval(req.query.code);\nconst password = "q8Zr!w2Lp#kD9xx";');
  await writeFile(path.join(root, 'settings.dev.py'), 'DEBUG = True\n');
  await writeFile(path.join(root, 'settings.py'), 'DEBUG = True\n');
  const report = await scanSource(root, { includeTests: true });
  const at = (file, ruleId) => report.findings.filter((f) => f.location.file === file && f.ruleId === ruleId);
  const secrets = at('app.js', 'SRC-SECRET').sort((a, b) => a.location.line - b.location.line);
  assert.deepEqual(secrets.map((f) => [f.location.line, f.severity]), [[2, 'info'], [3, 'high']]);
  assert.equal(secrets[0].context, 'placeholder');
  assert.equal(at('app.js', 'SRC-EVAL')[0].severity, 'high');
  const testEval = at('tests/app.test.js', 'SRC-EVAL')[0];
  assert.deepEqual([testEval.severity, testEval.confidence, testEval.context], ['medium', 'low', 'test']);
  assert.equal(at('tests/app.test.js', 'SRC-SECRET')[0].severity, 'high', 'credentials in tests keep severity');
  assert.equal(at('settings.dev.py', 'SRC-DEBUG')[0].severity, 'info');
  assert.equal(at('settings.py', 'SRC-DEBUG')[0].severity, 'low');
  assert.equal(report.stats.contextFilter.removed['SRC-SECRET'], 1);
  const raw = await scanSource(root, { includeTests: true, contextFilter: false });
  assert.equal(raw.findings.find((f) => f.location.file === 'tests/app.test.js' && f.ruleId === 'SRC-EVAL').severity, 'high');
});

test('python docstrings are documentation while SQL in assigned triple-quoted strings is still scanned', async (t) => {
  const root = await fixture(t);
  await writeFile(path.join(root, 'app.py'), [
    'def run():',
    '    """Run the app.',
    '',
    '    Example::',
    '        DEBUG = True',
    '        os.system("rm -rf " + path)',
    '    """',
    '    import platform',
    '    info = platform.system()',
    '    digest = hashlib.md5(data, usedforsecurity=False)',
    '    weak = hashlib.md5(data)',
    '    query = """SELECT * FROM users WHERE id = """ + user_id',
    '    os.system("ls " + folder)',
  ].join('\n'));
  const report = await scanSource(root);
  const lines = (id) => report.findings.filter((f) => f.ruleId === id).map((f) => f.location.line);
  assert.deepEqual(lines('SRC-DEBUG'), []);
  assert.deepEqual(lines('SRC-SHELL'), [13]);
  assert.deepEqual(lines('SRC-HASH'), [11]);
  assert.deepEqual(lines('SRC-SQL'), [12]);
  assert.equal(report.stats.contextFilter.removed['SRC-HASH'], 1);
});
