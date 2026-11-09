import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { searchKnowledge, importWriteup, loadCustomRules, loadWriteups, enrichReport } from '../src/knowledge.mjs';
import { scanSource } from '../src/source.mjs';

test('curated knowledge links writeups to findings; distinguishes topics from confirmed bugs', async () => {
  const entries = searchKnowledge('prototype');
  assert.ok(entries.length > 0);
  assert.ok(entries.some((e) => e.references.some((r) => r.includes('portswigger.net/research/'))));
  const report = { findings: [{ cwe: 'CWE-89', ruleId: 'SRC-SQL' }] };
  enrichReport(report);
  assert.ok(report.findings[0].knowledge.references.length > 0);
  assert.ok(report.findings[0].knowledge.reviewSteps.length > 0);
  assert.equal(searchKnowledge('unmatched-topic-xyz').length, 0);
});

test('writeup import only stores recognized topics and URL references, not raw credentials', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'scanner-knowledge-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = path.join(root, 'notes.md');
  await writeFile(input, '# SQL injection notes\nUse parameterized queries. https://portswigger.net/web-security/sql-injection\npassword="never-copy-this-synthetic-value"');
  const result = await importWriteup(input, path.join(root, 'knowledge'));
  assert.ok(result.topics.includes('sql-injection'));
  const data = await readFile(result.file, 'utf8');
  assert.ok(!data.includes('never-copy-this'));
  const report = { findings: [{ cwe: 'CWE-89', ruleId: 'SRC-SQL' }] };
  enrichReport(report, await loadWriteups(path.join(root, 'knowledge')));
  assert.equal(report.findings[0].knowledge.relatedWriteups.length, 1);
  const unknown = path.join(root, 'empty.txt');
  await writeFile(unknown, 'unrelated cooking notes');
  assert.equal((await importWriteup(unknown, path.join(root, 'knowledge'))).topics.length, 0);
});

test('custom literal rules are validated, scan locally, and never execute regex or code', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'scanner-rules-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const input = path.join(root, 'custom.json');
  const rule = { id: 'CUSTOM-TEST', title: 'Custom risky API', severity: 'medium', cwe: 'CWE-20', extensions: ['.js'], containsAll: ['customDanger(', 'req.'], impact: 'Review input', remediation: 'Validate input', reference: 'https://owasp.org/' };
  await writeFile(input, JSON.stringify([rule]));
  const rules = await loadCustomRules(input);
  await writeFile(path.join(root, 'app.js'), 'customDanger(req.body);');
  const report = await scanSource(root, { customRules: rules });
  assert.ok(report.findings.some((f) => f.ruleId === 'CUSTOM-TEST'));
  for (const bad of [{ ...rule, id: 'SRC-SQL' }, { ...rule, containsAll: [], regex: '(a+)+$' }, { ...rule, reference: 'javascript:alert(1)' }]) {
    await writeFile(input, JSON.stringify([bad]));
    await assert.rejects(loadCustomRules(input));
  }
});

test('research-backed indicators identify SSRF, traversal, SSTI, prototype, XXE and JWT review points', async (t) => {
  const root = await mkdtemp(path.join(tmpdir(), 'scanner-research-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await writeFile(path.join(root, 'app.js'), 'fetch(req.query.url);\nres.sendFile(req.query.path);\nmerge(config, req.body);');
  await writeFile(path.join(root, 'app.py'), 'render_template_string(request.args["template"])\nXMLParser(resolve_entities=True)\njwt.decode(token, options={"verify_signature": False})');
  const report = await scanSource(root);
  for (const id of ['SRC-SSRF', 'SRC-PATH', 'SRC-SSTI', 'SRC-PROTOTYPE', 'SRC-XXE', 'SRC-JWT']) assert.ok(report.findings.some((f) => f.ruleId === id), id);
});
