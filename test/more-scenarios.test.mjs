import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseAsvs, parseApiRisk, parseKev } from '../src/scenario-import.mjs';
import { scanSource } from '../src/source.mjs';
import { corpusStats, searchCorpus } from '../src/corpus.mjs';
import { enrichReport } from '../src/knowledge.mjs';
import { renderHtml, renderText } from '../src/report.mjs';

test('ASVS and API normalization preserve identifiers and distinguish scenarios from detectors', () => {
  const entries = parseAsvs({ requirements: [{ req_id: 'V1.2.4', chapter_name: 'Encoding', section_name: 'Injection', req_description: 'Use parameterized queries.', L: '1' }] });
  assert.equal(entries[0].id, 'ASVS-v5.0.0-1.2.4');
  assert.equal(entries[0].kind, 'asvs');
  assert.throws(() => parseAsvs({ wrong: [] }));
  const api = parseApiRisk('# API1:2023 Broken Object Level Authorization\n## Example Attack Scenarios\n### Scenario #1\nAn account reads another object.\n```sh\nDO_NOT_RETAIN_CODE\n```\n## How To Prevent\nEnforce object permissions.', '0xa1-test.md', 'fixed-commit');
  assert.equal(api.length, 2);
  assert.ok(api.some((entry) => entry.id === 'API1:2023-SCENARIO-1'));
  assert.ok(!JSON.stringify(api).includes('DO_NOT_RETAIN_CODE'));
  assert.equal(parseApiRisk('# unrelated', 'file.md', 'commit').length, 0);
});

test('CISA KEV entries retain evidence of catalog inclusion without asserting local exploitation', () => {
  const data = parseKev({ vulnerabilities: [{ cveID: 'CVE-2021-23337', vulnerabilityName: 'Example', shortDescription: 'Public catalog evidence', vendorProject: 'Example', product: 'Example', dateAdded: '2026-01-01', requiredAction: 'Use vendor mitigation.', cwes: ['CWE-77'] }] });
  assert.equal(data[0].kind, 'kev');
  assert.equal(data[0].cve, 'CVE-2021-23337');
  assert.ok(!Object.hasOwn(data[0], 'dueDate'));
});

const fixtures = [
  ['SC-JS-INSERT-HTML', 'app.js', 'box.insertAdjacentHTML("beforeend", req.query.html);', 'box.insertAdjacentText("beforeend", req.query.text);'],
  ['SC-JS-FRAGMENT', 'app.js', 'range.createContextualFragment(location.hash);', 'range.createContextualFragment("<p>fixed</p>");'],
  ['SC-JS-SQL-LITERAL', 'app.js', 'Sequelize.literal(req.query.sort);', 'Sequelize.literal("CURRENT_TIMESTAMP");'],
  ['SC-PHP-SQL-RAW', 'app.php', 'DB::raw($request->input("sql"));', 'DB::raw("CURRENT_TIMESTAMP");'],
  ['SC-PY-SQL-RAW', 'app.py', 'Model.objects.raw(f"SELECT * FROM x WHERE name={name}")', 'Model.objects.raw("SELECT * FROM x WHERE id=%s", [value])'],
  ['SC-PHP-PRINT', 'app.php', 'print $_GET["html"];', 'print htmlspecialchars($_GET["text"]);'],
  ['SC-PY-XPATH', 'app.py', 'tree.xpath(request.args["query"])', 'tree.xpath("//user[@id=$id]", id=value)'],
  ['SC-JS-LDAP', 'app.js', 'ldap.search(base, {filter: req.query.filter});', 'ldap.search(base, {filter: fixedFilter});'],
  ['SC-CS-TEMPLATE', 'App.cs', 'Razor.Parse(Request.Form["template"]);', 'Razor.Parse("Hello @Model.Name", model);'],
  ['SC-JAVA-SSRF', 'App.java', 'new URL(request.getParameter("url"));', 'new URL("https://fixed.example");'],
  ['SC-GO-SSRF', 'app.go', 'http.Get(r.FormValue("url"))', 'http.Get("https://fixed.example")'],
  ['SC-RUST-TLS', 'app.rs', 'Client::builder().danger_accept_invalid_certs(true)', 'Client::builder().danger_accept_invalid_certs(false)']
];
for (const [id, name, positive, negative] of fixtures) test(`scenario regression ${id}: risky and benign`, async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'scenario-regression-')); t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, name); await writeFile(file, positive);
  assert.ok((await scanSource(file)).findings.some((entry) => entry.ruleId === id), id);
  await writeFile(file, negative);
  assert.ok(!(await scanSource(file)).findings.some((entry) => entry.ruleId === id));
});

test('additional offline sources are searchable without treating normative ASVS requirements as findings', () => {
  const stats = corpusStats();
  assert.ok(stats.asvs > 300); assert.ok(stats.api >= 20); assert.ok(stats.kev > 1000);
  assert.ok(stats.advisories > 936);
  assert.equal(searchCorpus('ASVS-v5.0.0-1.2.4', { kind: 'asvs' }).results[0].id, 'ASVS-v5.0.0-1.2.4');
});

test('ASVS conditions are attached to matching signatures and included in exports', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'asvs-context-')); t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'app.js'); await writeFile(file, 'box.insertAdjacentHTML("beforeend", req.body.html);');
  const report = enrichReport(await scanSource(file));
  const finding = report.findings.find((entry) => entry.ruleId === 'SC-JS-INSERT-HTML');
  assert.equal(finding.knowledge.verificationRequirements[0].id, 'ASVS-v5.0.0-1.2.1');
  assert.match(renderHtml(report), /ASVS-v5\.0\.0-1\.2\.1/);
  assert.match(renderText(report), /ASVS-v5\.0\.0-1\.2\.1/);
});

test('CISA context attaches only through a matched CVE and is explicit in reports', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'kev-context-')); t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'package-lock.json');
  await writeFile(file, JSON.stringify({packages:{'node_modules/jquery':{version:'3.4.1'}}}));
  const report = await scanSource(file);
  const finding = report.findings.find((entry) => entry.advisory?.cve === 'CVE-2020-11023');
  assert.ok(finding.advisory.kev);
  assert.match(finding.advisory.kev.scope, /không chứng minh/);
  assert.match(renderText(report), /CISA KEV/);
});
