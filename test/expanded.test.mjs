import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { scanSource, SOURCE_RULES } from '../src/source.mjs';
import { searchCorpus, corpusStats, contextForCwe } from '../src/corpus.mjs';
import { extractDependencies, matchVersion } from '../src/dependencies.mjs';
import { analyzeFlow } from '../src/flow.mjs';

test('offline corpus contains attributed CWE, versioned OWASP tests and real advisory data', () => {
  const stats = corpusStats();
  assert.ok(stats.cwe > 900); assert.ok(stats.owasp > 90); assert.ok(stats.advisories > 100);
  assert.ok(searchCorpus('CVE-2021-23337', { kind: 'advisory' }).results.some((entry) => entry.cve === 'CVE-2021-23337'));
  assert.ok(searchCorpus('WSTG-INPV-05').results.some((entry) => entry.id === 'WSTG-INPV-05'));
  assert.equal(contextForCwe('CWE-89').id, 'CWE-89');
  assert.equal(searchCorpus('not-a-real-topic-xyz').total, 0);
});

test('ecosystem-aware version comparison rejects malformed and unsupported inputs', () => {
  assert.equal(matchVersion('npm', '4.17.20', '<4.17.21'), true);
  assert.equal(matchVersion('npm', '4.17.21', '<4.17.21'), false);
  assert.equal(matchVersion('npm', '14.2.25', '>=14.0.0, <14.2.25'), false);
  assert.equal(matchVersion('pip', '2.0.0rc1', '>=2.0.0rc1,<2.0.0'), false);
  assert.equal(matchVersion('pip', '2.0.1', '>=2,<2.1'), true);
  assert.equal(matchVersion('npm', 'invalid', '<4'), null);
  assert.equal(matchVersion('maven', '2.0', '<3'), null);
});

test('dependency inventory resolves npm v1/v3, pinned requirements and distinguishes declared ranges', () => {
  const v3 = extractDependencies('package-lock.json', JSON.stringify({ packages: { '': { version: '1.0.0' }, 'node_modules/lodash': { version: '4.17.20' }, 'node_modules/a/node_modules/@scope/pkg': { version: '1.2.3' } } }));
  assert.deepEqual(v3.packages.map((p) => p.name), ['lodash', '@scope/pkg']);
  const v1 = extractDependencies('package-lock.json', JSON.stringify({ dependencies: { lodash: { version: '4.17.20', dependencies: { sub: { version: '1.2.3' } } } } }));
  assert.equal(v1.packages.length, 2);
  const requirements = extractDependencies('requirements.txt', 'Flask==2.2.2\nDjango>=4\n# comment\nprivate @ https://private.example/token\nrequests==2.31.0; python_version>"3.9"');
  assert.equal(requirements.packages.length, 1);
  assert.ok(requirements.unresolved >= 3);
  assert.ok(!JSON.stringify(requirements).includes('private.example'));
  assert.equal(extractDependencies('package.json', '{"dependencies":{"lodash":"^4.17.0"}}').packages.length, 0);
});

test('source matches a real vulnerable dependency; patched version is not flagged for the same advisory', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'scanner-cve-')); t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'package-lock.json');
  await writeFile(file, JSON.stringify({ packages: { 'node_modules/lodash': { version: '4.17.20' } } }));
  let report = await scanSource(root);
  const cve = report.findings.find((f) => f.advisory?.cve === 'CVE-2021-23337');
  assert.ok(cve); assert.equal(cve.status, 'version-match'); assert.equal(cve.advisory.package, 'lodash');
  assert.match(cve.remediation, /4\.17\.21/);
  await writeFile(file, JSON.stringify({ packages: { 'node_modules/lodash': { version: '4.17.21' } } }));
  report = await scanSource(root);
  assert.ok(!report.findings.some((f) => f.advisory?.cve === 'CVE-2021-23337'));
});

test('bounded multi-line flow catches aliases and ignores parameterized queries and overwritten input', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'scanner-flow-')); t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'app.js');
  await writeFile(file, 'const userId = req.query.id;\nconst query = "SELECT * FROM users WHERE id=" + userId;\ndb.query(query);\nconst code = req.body.code;\neval(code);');
  let report = await scanSource(root);
  assert.ok(report.findings.some((f) => f.ruleId === 'FLOW-SQL' && f.location.line === 3));
  assert.ok(report.findings.some((f) => f.ruleId === 'FLOW-EVAL' && f.trace?.length > 0));
  await writeFile(file, 'let userId = req.query.id;\nuserId = 123;\ndb.query(userId);\nconst id = req.query.id;\ndb.query("SELECT * FROM users WHERE id=?", [id]);');
  report = await scanSource(root);
  assert.ok(!report.findings.some((f) => f.ruleId.startsWith('FLOW-')));
});

test('flow never mistakes text inside a constant string for a tainted identifier', () => {
  assert.equal(analyzeFlow(['const literal = req.query.id;', 'db.query("literal");'], 'app.js').length, 0);
});

test('real PyPI advisory matches a pinned vulnerable version and excludes its patched version', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'scanner-pypi-')); t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'requirements.txt');
  await writeFile(file, 'Werkzeug==3.0.2');
  assert.ok((await scanSource(file)).findings.some((f) => f.advisory?.cve === 'CVE-2024-34069'));
  await writeFile(file, 'Werkzeug==3.0.3');
  assert.ok(!(await scanSource(file)).findings.some((f) => f.advisory?.cve === 'CVE-2024-34069'));
});

const cases = [
  ['EXT-JS-REDIRECT', 'app.js', 'res.redirect(req.query.next);', 'res.redirect("/account");'],
  ['EXT-PY-REDIRECT', 'app.py', 'HttpResponseRedirect(request.GET["next"])', 'HttpResponseRedirect("/account")'],
  ['EXT-PHP-INCLUDE', 'app.php', 'include($_GET["file"]);', 'include("header.php");'],
  ['EXT-PY-CSRF', 'app.py', '@csrf_exempt', '@csrf_protect'],
  ['EXT-VUE-HTML', 'app.vue', '<div v-html="userHtml"></div>', '<div>{{ userText }}</div>'],
  ['EXT-SVELTE-HTML', 'app.svelte', '{@html userHtml}', '{userText}'],
  ['EXT-JS-NOSQL', 'app.js', 'users.findOne(req.body);', 'users.findOne({name: String(req.body.name)});'],
  ['EXT-JS-MASS', 'app.js', 'User.update(req.body);', 'User.update({name: req.body.name});'],
  ['EXT-JS-VM', 'app.js', 'vm.runInNewContext(req.body.code);', 'vm.runInNewContext("1+1");'],
  ['EXT-PY-AUTOESCAPE', 'app.py', 'Environment(autoescape=False)', 'Environment(autoescape=True)'],
  ['EXT-PY-MARKSAFE', 'app.py', 'mark_safe(request.GET["x"])', 'escape(request.GET["x"])'],
  ['EXT-JAVA-EXEC', 'App.java', 'Runtime.getRuntime().exec(request.getParameter("cmd"));', 'Runtime.getRuntime().exec("whoami");'],
  ['EXT-GO-TLS', 'app.go', 'tls.Config{InsecureSkipVerify: true}', 'tls.Config{InsecureSkipVerify: false}'],
  ['EXT-CS-PATH', 'App.cs', 'File.ReadAllText(Request.Query["file"]);', 'File.ReadAllText("config.json");'],
  ['EXT-RUBY-DESER', 'app.rb', 'Marshal.load(params[:data])', 'JSON.parse(params[:data])'],
  ['EXT-CONFIG-PRIVILEGED', 'compose.yaml', 'privileged: true', 'privileged: false'],
  ['EXT-PHP-DISPLAY', 'app.php', 'ini_set("display_errors", 1);', 'ini_set("display_errors", 0);'],
  ['EXT-JS-COOKIE-HTTPONLY', 'app.js', 'res.cookie("s", token, {httpOnly: false});', 'res.cookie("s", token, {httpOnly: true});'],
  ['EXT-JS-WEAK-RANDOM', 'app.js', 'const token = Math.random().toString(36);', 'const token = crypto.randomBytes(32);'],
  ['EXT-CS-HTML', 'App.cshtml', '@Html.Raw(Request.Query["text"])', '@Html.Encode(Request.Query["text"])']
];
for (const [id, name, risky, safe] of cases) test(`expanded regression: ${id} distinguishes risky and benign use`, async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'scanner-pattern-')); t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, name); await writeFile(file, risky);
  assert.ok((await scanSource(file)).findings.some((f) => f.ruleId === id), id);
  await writeFile(file, safe); assert.ok(!(await scanSource(file)).findings.some((f) => f.ruleId === id), id + ' benign');
});
