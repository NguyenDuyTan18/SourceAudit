import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { classifySecret } from '../src/context.mjs';
import { extractDependencies } from '../src/dependencies.mjs';
import { scanSource, SOURCE_RULES } from '../src/source.mjs';

async function fixture(t, files) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'srcaudit-quick-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  for (const [name, contents] of Object.entries(files)) {
    const file = path.join(root, name);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, contents);
  }
  return root;
}

test('Quick Scan checks workflow permissions and container confinement in the relevant YAML fields', async (t) => {
  const workflow = [
    'permissions: "write-all"', 'jobs:', '  publish: {permissions: write-all}',
    '  safe:', '    permissions: {contents: read}', '    steps:',
    '      - run: |', '          permissions: write-all',
  ].join('\n');
  const compose = [
    'services:', '  app:', '    security_opt:', '      - "seccomp=unconfined"',
    '      - apparmor:unconfined', '      - "no-new-privileges:true"',
    '    environment: {security_opt: "seccomp=unconfined"}',
    '  safe: {security_opt: ["apparmor=docker-default", "seccomp=builtin"]}',
  ].join('\n');
  const root = await fixture(t, {
    '.github/workflows/ci.yml': workflow, 'other.yml': workflow,
    'compose.override.yaml': compose, 'application.yml': compose,
  });
  const report = await scanSource(root);
  const ids = ['CFG-ACTIONS-WRITE-ALL', 'CFG-COMPOSE-UNCONFINED'];
  assert.ok(ids.every((id) => SOURCE_RULES.some((rule) => rule.id === id)));
  assert.deepEqual(report.findings.filter(({ ruleId }) => ids.includes(ruleId))
    .map(({ ruleId, location }) => [ruleId, location.file, location.line])
    .sort((a, b) => a[0].localeCompare(b[0]) || a[2] - b[2]), [
    [ids[0], '.github/workflows/ci.yml', 1], [ids[0], '.github/workflows/ci.yml', 3],
    [ids[1], 'compose.override.yaml', 4], [ids[1], 'compose.override.yaml', 5],
  ]);
  const single = await scanSource(path.join(root, '.github/workflows/ci.yml'));
  assert.equal(single.findings.filter(({ ruleId }) => ruleId === ids[0]).length, 2);
  await writeFile(path.join(root, 'compose.override.yaml'), 'services: [');
  const malformed = await scanSource(path.join(root, 'compose.override.yaml'));
  assert.ok(malformed.errors.some((message) => message.includes('Could not analyze YAML configuration')));
});

test('Quick Scan keeps dynamic SQL text and accepts fixed text with separate query values', async (t) => {
  const root = await fixture(t, { 'app.js': [
    'const id = req.query.id;',
    'db.query({ text: "SELECT * FROM items WHERE id = $1", values: [id] });',
    'db.query({ text: "SELECT * FROM items WHERE id = " + id, values: [id] });',
    'db.query({ text: "SELECT * FROM items WHERE id = $1", values: [id], ...req.body });',
    'db.query({ text: "SELECT * FROM items WHERE id = $1", values: [id], [field]: id });',
    'const cfg = { text: "SELECT * FROM items WHERE id = $1", values: [id] };',
    'db.query(cfg);',
  ].join('\n') });
  const report = await scanSource(root);
  const sql = report.findings.filter(({ cwe }) => cwe === 'CWE-89');
  assert.ok(!sql.some(({ location }) => location.line === 2));
  assert.ok([3, 4, 5, 7].every((line) => sql.some(({ location }) => location.line === line)));
  assert.ok(report.filtered.some(({ ruleId, location }) => ruleId === 'FLOW-SQL' && location.line === 2));
});

test('secret triage removes clear references and keeps literal fallback values for review', () => {
  assert.equal(classifySecret('PASSWORD = "${ENV_PASSWORD}"'), 'reference');
  assert.equal(classifySecret('PASSWORD = "${ENV_PASSWORD:-local-value}"'), undefined);
  assert.equal(classifySecret('PASSWORD = "literal-process.env.VALUE"'), undefined);
  assert.equal(classifySecret('PASSWORD = "<local-value>"'), undefined);
  assert.equal(classifySecret('PASSWORD = "<your-password-here>"'), 'reference');
  assert.equal(classifySecret('PASSWORD = "os.getenv(\'DB_PASSWORD\')"'), 'reference');
  assert.equal(classifySecret('PASSWORD = "os.getenv(\'DB_PASSWORD\', \'local-value\')"'), undefined);
  assert.equal(classifySecret('PASSWORD = "your-password-here"'), 'placeholder');
  assert.equal(classifySecret('PASSWORD = "dev-R8q7Vn29"'), undefined);
});

test('Poetry versions feed the same offline PyPI matching in both scan modes', async (t) => {
  const lock = (version) => [
    '[[package]]', 'name = "Werkzeug"', `version = "${version}"`, 'groups = ["main"]',
    '[package.dependencies]', 'MarkupSafe = ">=2.1.1"',
    '[[package]]', 'name = "local-project"', 'version = "1.0.0"',
    '[package.source]', 'type = "directory"', 'url = "../local-project"',
    '[metadata]', 'lock-version = "2.1"',
  ].join('\n');
  const root = await fixture(t, { 'poetry.lock': lock('3.0.2') });
  for (const analysis of ['quick', 'deep']) {
    const report = await scanSource(root, { analysis });
    const finding = report.findings.find(({ advisory }) => advisory?.cve === 'CVE-2024-34069');
    assert.equal(finding?.advisory.version, '3.0.2');
    assert.deepEqual(finding?.location, { file: 'poetry.lock', pointer: '/package/0/version' });
    assert.equal(report.stats.dependencyAnalysis.packages, 1);
    assert.equal(report.stats.dependencyAnalysis.unresolved, 1);
  }
  await writeFile(path.join(root, 'poetry.lock'), lock('3.0.3'));
  const patched = await scanSource(root);
  assert.ok(!patched.findings.some(({ advisory }) => advisory?.cve === 'CVE-2024-34069'));
  assert.equal(extractDependencies('poetry.lock', 'package = []\n[metadata]\nlock-version = "1.1"').unresolved, 0);
  assert.equal(extractDependencies('poetry.lock', 'package = []\n[metadata]\nlock-version = "3.0"').unsupported, 1);
  assert.throws(() => extractDependencies('poetry.lock', '[[package]'));
});
