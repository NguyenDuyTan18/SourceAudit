import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanSource } from '../src/source.mjs';
import { expressSqlCases } from './semgrep-express-cases.mjs';
import { frameworkConfigCases } from './semgrep-framework-config-cases.mjs';
import { expandedCases, frameworkCases, multilangCases, provenanceCases } from './semgrep-multilang-cases.mjs';

// These snippets are read by the scanners as text. They are never imported or executed.
const pairs = [
  ...frameworkConfigCases,
  ...expressSqlCases,
  ...provenanceCases,
  ...frameworkCases,
  ...expandedCases,
  ...multilangCases,
  {
    name: 'sql-string', ext: 'js', cwe: 'CWE-89',
    vulnerable: `function route(req) {
  const id = req.query.id;
  const sql = "SELECT * FROM users WHERE id=" + id;
  return db.query(sql);
}`,
    fixed: `function route(req) {
  const id = req.query.id;
  return db.query("SELECT * FROM users WHERE id=$1", [id]);
}`,
  },
  {
    name: 'sql-options', ext: 'ts', cwe: 'CWE-89',
    vulnerable: `function route(req: { body: { sql: string } }) {
  return pool.query({ text: req.body.sql });
}`,
    fixed: `function route(req: { body: { sql: string } }) {
  return pool.query({ text: "SELECT * FROM logs WHERE tag=$1", values: [req.body.sql] });
}`,
  },
  {
    name: 'shell-concat', ext: 'js', cwe: 'CWE-78',
    vulnerable: `import { execSync } from "node:child_process";
function route(req) {
  const command = "git log " + req.query.branch;
  return execSync(command);
}`,
    fixed: `import { execSync } from "node:child_process";
function route() {
  return execSync("git status --short");
}`,
  },
  {
    name: 'shell-import-alias', ext: 'ts', cwe: 'CWE-78',
    vulnerable: `import { exec as run } from "node:child_process";
function route(req: { body: { cmd: string } }) {
  const command = req.body.cmd;
  return run(command);
}`,
    fixed: `import { execFile } from "node:child_process";
function route(req: { body: { filename: string } }) {
  return execFile("git", ["show", "--", req.body.filename]);
}`,
  },
  {
    name: 'ssrf-fetch', ext: 'js', cwe: 'CWE-918',
    vulnerable: `function route(req) {
  const url = req.query.url;
  return fetch(url);
}`,
    fixed: `function route(req) {
  return fetch("https://example.test/status", { headers: { "X-Trace": req.query.trace } });
}`,
  },
  {
    name: 'ssrf-axios-options', ext: 'ts', cwe: 'CWE-918',
    vulnerable: `import axios from "axios";
function route(req: { params: { url: string } }) {
  const target = req.params.url;
  return axios.request({ url: target, method: "GET" });
}`,
    fixed: `import axios from "axios";
function route(req: { params: { url: string } }) {
  return axios.request({ url: "https://example.test/status", params: { tag: req.params.url } });
}`,
  },
  {
    name: 'express-sendfile-root', ext: 'js', cwe: 'CWE-22',
    vulnerable: `function download(req, res) {
  return res.sendFile(req.query.path);
}`,
    fixed: `function download(req, res) {
  return res.sendFile(req.query.path, { root: path.join(__dirname, "public") });
}`,
  },
  {
    name: 'express-download-allowlist', ext: 'ts', cwe: 'CWE-22',
    vulnerable: `function download(request: Request, response: Response) {
  const filename = request.params.file;
  return response.download(path.resolve(__dirname, "public", filename));
}`,
    fixed: `function download(request: Request, response: Response) {
  switch (request.params.file) {
    case "guide": return response.download(path.join(__dirname, "public", "guide.pdf"));
    case "policy": return response.download(path.join(__dirname, "public", "policy.pdf"));
    default: return response.status(404).end();
  }
}`,
  },
  {
    name: 'express-download-tainted-root', ext: 'ts', cwe: 'CWE-22',
    vulnerable: `function download(req: Request, res: Response) {
  return res.download("guide.pdf", "guide.pdf", { root: path.resolve(req.query.dir) });
}`,
    fixed: `function download(req: Request, res: Response) {
  return res.download(req.query.file, "guide.pdf", { root: path.resolve(__dirname, "public") });
}`,
  },
  {
    name: 'express-sendfile-root-override', ext: 'ts', cwe: 'CWE-22',
    vulnerable: `function download(req: Request, res: Response) {
  return res.sendFile(req.query.path, { root: path.join(__dirname, "public"), ...req.body.options });
}`,
    fixed: `function download(req: Request, res: Response) {
  return res.sendFile(req.query.path, { root: path.join(__dirname, "public"), dotfiles: "deny" });
}`,
  },
  {
    name: 'express-xss-escaped-body', ext: 'js', cwe: 'CWE-79',
    vulnerable: `function greet(req, res) {
  return res.send("<p>" + req.query.name);
}`,
    fixed: `import escapeHtml from "escape-html";
function greet(req, res) {
  return res.send(escapeHtml(req.query.name));
}`,
  },
  {
    name: 'express-xss-script-context', ext: 'ts', cwe: 'CWE-79',
    vulnerable: `import escapeHtml from "escape-html";
function greet(request: Request, response: Response) {
  const value = escapeHtml(request.query.name);
  return response.type("html").send("<script>show(" + value + ")</script>");
}`,
    fixed: `function greet(request: Request, response: Response) {
  return response.send({ name: request.query.name });
}`,
  },
  {
    name: 'dom-xss-collected-sample', ext: 'js', cwe: 'CWE-79',
    vulnerable: `box.insertAdjacentHTML("beforeend", req.body.html);`,
    fixed: `box.textContent = req.body.html;`,
  },
  {
    name: 'express-redirect-status', ext: 'ts', cwe: 'CWE-601',
    vulnerable: `function route(req: Request, res: Response) {
  const next = req.query.next;
  return res.redirect(302, next);
}`,
    fixed: `function route(req: Request, res: Response) {
  const next = req.query.next === "profile" ? "/profile" : "/";
  return res.redirect(302, next);
}`,
  },
  {
    name: 'express-redirect-header', ext: 'js', cwe: 'CWE-601',
    vulnerable: `function route(request, response) {
  const next = request.get("referer");
  return response.redirect(next);
}`,
    fixed: `function route(request, response) {
  switch (request.get("x-return-page")) {
    case "orders": return response.redirect("/orders");
    default: return response.redirect("/");
  }
}`,
  },
  {
    name: 'nosql-filter-object', ext: 'ts', cwe: 'CWE-943',
    vulnerable: `function route(req: Request) {
  const filter = req.body.filter;
  return users.findOne(filter);
}`,
    fixed: `function route(req: Request) {
  return users.findOne({ email: String(req.body.email) });
}`,
  },
  {
    name: 'nosql-aggregation-pipeline', ext: 'js', cwe: 'CWE-943',
    vulnerable: `function route(req) {
  const stages = req.body.pipeline;
  return users.aggregate(stages);
}`,
    fixed: `function route(req) {
  return users.aggregate([{ $match: { email: String(req.body.email) } }]);
}`,
  },
  {
    name: 'nosql-string-reparsed-as-filter', ext: 'ts', cwe: 'CWE-943',
    vulnerable: `function route(req: Request) {
  const filter = JSON.parse(String(req.body.filter));
  return users.findOne(filter);
}`,
    fixed: `function route(req: Request) {
  const input = JSON.parse(String(req.body.filter));
  return users.findOne({ email: String(input.email) });
}`,
  },
  {
    name: 'nosql-string-in-where-operator', ext: 'js', cwe: 'CWE-943',
    vulnerable: `function route(req) {
  return users.findOne({ $where: String(req.body.expression) });
}`,
    fixed: `function route(req) {
  return users.findOne({ username: String(req.body.username) });
}`,
  },
  {
    name: 'prototype-merge-source', ext: 'js', cwe: 'CWE-1321',
    vulnerable: `function route(req) {
  const preferences = req.body;
  return merge(config, preferences);
}`,
    fixed: `function route(req) {
  config.theme = req.body.theme === "dark" ? "dark" : "light";
  return config;
}`,
  },
  {
    name: 'prototype-dynamic-key', ext: 'ts', cwe: 'CWE-1321',
    vulnerable: `function route(req: Request) {
  const key = req.query.path;
  return _.set(config, key, req.body.value);
}`,
    fixed: `function route(req: Request) {
  return _.set(config, "theme", req.body.value);
}`,
  },
  {
    name: 'ssti-ejs-template-text', ext: 'js', cwe: 'CWE-1336',
    vulnerable: `function route(req) {
  const template = req.body.template;
  return ejs.render(template, { name: req.body.name });
}`,
    fixed: `function route(req) {
  return ejs.render("<p><%= name %></p>", { name: req.body.name });
}`,
  },
  {
    name: 'ssti-handlebars-cookie', ext: 'ts', cwe: 'CWE-1336',
    vulnerable: `function route(request: Request) {
  const template = request.cookies.layout;
  return handlebars.compile(template)({ label: request.cookies.label });
}`,
    fixed: `function route(request: Request) {
  return handlebars.compile("<p>{{label}}</p>")({ label: request.cookies.label });
}`,
  },
  {
    name: 'xss-cookie-response', ext: 'js', cwe: 'CWE-79',
    vulnerable: `function route(req, res) {
  return res.send(req.cookies.note);
}`,
    fixed: `function route(req, res) {
  return res.json({ note: req.cookies.note });
}`,
  },
  {
    name: 'code-injection-eval', ext: 'js', cwe: 'CWE-95',
    vulnerable: `function route(req) {
  const program = req.body.code;
  return eval(program);
}`,
    fixed: `function route(req) {
  return JSON.parse(req.body.code);
}`,
  },
  {
    name: 'code-injection-function', ext: 'ts', cwe: 'CWE-95',
    vulnerable: `function route(request: Request) {
  const program = request.cookies.script;
  return new Function("input", program);
}`,
    fixed: `function route(request: Request) {
  const action = request.cookies.script;
  return action === "status" ? readStatus : readSummary;
}`,
  },
  {
    name: 'deserialize-esm', ext: 'ts', cwe: 'CWE-502',
    vulnerable: `import serializer from "node-serialize";
function route(req: Request) {
  const payload = req.cookies.profile;
  return serializer.unserialize(payload);
}`,
    fixed: `function route(req: Request) {
  const input = JSON.parse(req.cookies.profile);
  return { name: String(input.name) };
}`,
  },
  {
    name: 'deserialize-commonjs', ext: 'js', cwe: 'CWE-502',
    vulnerable: `const legacy = require("node-serialize");
function route(req) {
  return legacy.unserialize(req.body.snapshot);
}`,
    fixed: `const legacy = require("node-serialize");
function route(req) {
  return JSON.parse(req.body.snapshot);
}`,
  },
  {
    name: 'mass-assignment-alias', ext: 'ts', cwe: 'CWE-915',
    vulnerable: `function route(req: Request) {
  const data = req.body;
  return User.create(data);
}`,
    fixed: `function route(req: Request) {
  const data = { name: String(req.body.name) };
  return User.create(data);
}`,
  },
  {
    name: 'mass-assignment-spread', ext: 'js', cwe: 'CWE-915',
    vulnerable: `function route(req) {
  return User.findByIdAndUpdate(req.params.id, { ...req.body, name: String(req.body.name) });
}`,
    fixed: `function route(req) {
  return User.findByIdAndUpdate(req.params.id, { name: String(req.body.name) });
}`,
  },
  {
    name: 'mass-assignment-computed-key', ext: 'js', cwe: 'CWE-915',
    vulnerable: `function route(req) {
  const data = { [req.body.field]: req.body.value };
  return User.updateOne({ id: req.params.id }, data);
}`,
    fixed: `function route(req) {
  return User.updateOne({ id: req.params.id }, { name: String(req.body.value) });
}`,
  },
];

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
  const quick = await scanSource(folder);
  const deep = await scanSource(folder, { analysis: 'deep' });
  if (deep.status !== 'complete') throw new Error(deep.errors.join(' '));
  assert.equal(quick.stats.filesScanned, pairs.length * 2);
  assert.equal(deep.stats.sourceAnalysis.scanned, pairs.length * 2);
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
    quickVulnerable: detected(quick, item, 'vulnerable'),
    deepVulnerable: detected(deep, item, 'vulnerable'),
    quickFixedFlagged: detected(quick, item, 'fixed'),
    deepFixedFlagged: detected(deep, item, 'fixed'),
  }));
  console.table(rows);
  console.log(JSON.stringify({
    pairs: rows.length,
    quickDetected: rows.filter((row) => row.quickVulnerable).length,
    deepDetected: rows.filter((row) => row.deepVulnerable).length,
    quickFalsePositives: rows.filter((row) => row.quickFixedFlagged).length,
    deepFalsePositives: rows.filter((row) => row.deepFixedFlagged).length,
    newlyDetected: rows.filter((row) => !row.quickVulnerable && row.deepVulnerable).map((row) => row.case),
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
