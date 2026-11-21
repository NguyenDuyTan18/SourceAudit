import test from 'node:test';
import assert from 'node:assert/strict';
import { filterWithAst } from '../src/ast-filter.mjs';

// Each case is one line of interest (marked `// <-`) inside a small file.
function run(ruleId, code, file = 'app.js') {
  const lines = code.split('\n');
  const line = lines.findIndex((l) => l.includes(' <-')) + 1;
  assert.ok(line > 0, 'case needs a // <- marker');
  const finding = { ruleId, location: { file, line } };
  const { findings, stats } = filterWithAst([finding], new Map([[file, code]]));
  return { kept: findings.length === 1, stats };
}
const removed = (...args) => assert.equal(run(...args).kept, false, args[1]);
const kept = (...args) => assert.equal(run(...args).kept, true, args[1]);

test('constant or sanitized sinks are removed', () => {
  removed('SRC-SHELL', 'import { execSync } from "node:child_process";\nexecSync("git status --short"); // <-');
  removed('SRC-SHELL', 'const CMD = "git " + "status";\nexecSync(CMD); // <-');
  removed('SRC-SHELL', 'execFile("git", ["show", "--", req.body.file]); // <-');
  removed('SRC-SHELL', 'spawn("git", ["log", req.query.ref], { shell: false }); // <-');
  removed('SRC-EVAL', 'eval("1 + 1"); // <-');
  removed('SRC-SSRF', 'fetch("https://api.test/status", { headers: { t: req.query.t } }); // <-');
  removed('SRC-SSRF', 'axios.request({ url: "https://api.test/x", params: { q: req.query.q } }); // <-', 'a.ts');
  removed('SRC-PATH', 'res.sendFile(req.query.p, { root: path.join(__dirname, "public") }); // <-');
  removed('SRC-PATH', 'fs.readFileSync(path.basename(req.query.p)); // <-');
  removed('SRC-XSS', 'res.send(escapeHtml(req.query.name)); // <-');
  removed('SRC-XSS', 'res.send("<p>" + escapeHtml(req.query.name) + "</p>"); // <-');
  removed('SRC-XSS', 'el.innerHTML = `<b>${"static"}</b>`; // <-');
  removed('SRC-XSS', 'const view = <div dangerouslySetInnerHTML={{ __html: "<b>ok</b>" }} />; // <-', 'v.jsx');
  removed('SRC-SSTI', 'ejs.render("<p><%= name %></p>", { name: req.body.name }); // <-');
  removed('SRC-SQL', 'const sql = "SELECT * FROM t WHERE a = " + 1 + " LIMIT " + 10; // <-');
  removed('SRC-SQL', 'db.query("SELECT * FROM users WHERE id = " + Number(req.query.id)); // <-');
  removed('SRC-SHELL', 'const x: string = "ls";\nexecSync(x as string); // <-', 'a.ts');
});

test('tainted or uncertain sinks are kept', () => {
  kept('SRC-SHELL', 'execSync("git log " + req.query.branch); // <-');
  kept('SRC-SHELL', 'import { exec as run } from "node:child_process";\nrun(req.body.cmd); // <-');
  kept('SRC-SHELL', 'spawn("sh", ["-c", req.body.cmd], { shell: true }); // <-');
  kept('SRC-SHELL', 'spawn(req.body.bin, []); // <-');
  kept('SRC-SHELL', 'spawn("git", [req.query.ref], { ...opts }); // <-');
  kept('SRC-SHELL', 'let CMD = "ls";\nCMD = req.query.c;\nexecSync(CMD); // <-');
  kept('SRC-SHELL', 'const CMD = "ls";\nfunction f(CMD) { return execSync(CMD); } // <-');
  kept('SRC-SHELL', 'execSync(`ls ${req.query.dir}`); // <-');
  kept('SRC-SSRF', 'fetch(`https://${req.query.host}/x`); // <-');
  kept('SRC-SSRF', 'axios.request({ url: "https://a.test", ...req.body }); // <-');
  kept('SRC-SSRF', 'axios({ baseURL: req.query.b, url: "/x" }); // <-');
  kept('SRC-PATH', 'res.sendFile(req.query.p, { root: "/srv", ...req.body.o }); // <-');
  kept('SRC-PATH', 'res.sendFile(req.query.p); // <-');
  kept('SRC-XSS', 'res.send("<p>" + escapeHtml(req.query.a) + req.query.b); // <-');
  kept('SRC-XSS', 'el.innerHTML = req.query.html; // <-');
  kept('SRC-XSS', 'const v = <div dangerouslySetInnerHTML={{ __html: props.html }} />; // <-', 'v.tsx');
  kept('SRC-SQL', 'const sql = "SELECT * FROM t WHERE a = " + req.query.a; // <-');
  kept('SRC-SQL', 'db.query(util.format("SELECT %s", req.query.c)); // <-');
  kept('SRC-EVAL', 'eval(code); // <-');
  kept('SRC-EVAL', 'setTimeout(req.query.code, 10); // <-');
});

test('unparseable files, unrelated lines and non-JS files keep the finding', () => {
  const broken = run('SRC-SHELL', 'execSync("ls"); // <-\nfunction (', 'broken.js');
  assert.equal(broken.kept, true);
  assert.equal(broken.stats.parseErrors, 1);
  kept('SRC-SHELL', 'const a = 1; // <- no sink here');
  kept('SRC-SHELL', 'os.system("ls") # <-', 'app.py');
  kept('SRC-HASH', 'createHash("md5"); // <-');
});
