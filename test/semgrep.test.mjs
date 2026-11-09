import assert from 'node:assert/strict';
import { access, readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { runSemgrep } from '../src/semgrep.mjs';
import { createReport, finishReport, renderHtml, renderText } from '../src/report.mjs';

test('Semgrep scans staged source and maps only recognized results back to the uploaded paths', async () => {
  let workspace;
  const result = await runSemgrep([
    { file: 'nested/route.ts', text: 'synthetic source fixture' },
    { file: 'nested/other.js', text: 'other source fixture' },
  ], { run: async (_command, args, options) => {
    workspace = options.cwd;
    assert.equal(options.timeout, 90_000);
    assert.equal(options.env.SEMGREP_APP_TOKEN, undefined);
    assert.ok(args.includes('--metrics=off'));
    assert.ok(args.includes('--disable-version-check'));
    assert.deepEqual((await readdir(workspace)).sort(), ['targets']);
    const staged = path.join(workspace, 'targets', '1.ts');
    assert.equal(await readFile(staged, 'utf8'), 'synthetic source fixture');
    const finding = {
      check_id: 'sentry-js-sql-injection', path: staged, start: { line: 8, col: 11 },
      extra: { lines: 'synthetic-credential-that-must-not-be-exported' },
    };
    return { stdout: JSON.stringify({
      results: [
        finding,
        finding,
        { ...finding, path: '../outside.ts' },
        { ...finding, path: 'targets/2.js' },
        { ...finding, check_id: 'unexpected-rule' },
        { ...finding, start: { line: -1, col: 1 } },
      ],
      errors: [],
      paths: { scanned: ['targets/1.ts', staged, '../outside.ts'] },
    }) };
  } });
  assert.equal(result.status, 'partial');
  assert.equal(result.scanned, 1);
  assert.deepEqual(result.languages, {
    TypeScript: { selected: 1, scanned: 1 },
    JavaScript: { selected: 1, scanned: 0 },
  });
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].cwe, 'CWE-89');
  assert.deepEqual(result.findings[0].location, { file: 'nested/route.ts', line: 8, column: 11 });
  assert.equal(result.findings[0].sourceExcerpt, undefined);
  assert.doesNotMatch(JSON.stringify(result), /synthetic-credential|scanner-semgrep-/);
  await assert.rejects(access(workspace), { code: 'ENOENT' });
});

test('Semgrep findings in other languages preserve location without exporting source snippets', async () => {
  const result = await runSemgrep([{ file: 'src/route.php', text: 'run(input); // sensitive code' }], {
    run: async (_command, args) => {
      const configs = args.flatMap((arg, index) => arg === '--config' ? [path.basename(args[index + 1])] : []);
      assert.deepEqual(configs, ['semgrep-js-ts.yml', 'semgrep-multilang.yml', 'semgrep-framework-config.yml']);
      return { stdout: JSON.stringify({
        results: [{ check_id: 'sentry-php-command-injection', path: 'targets/1.php', start: { line: 1, col: 5 } }],
        errors: [], paths: { scanned: ['targets/1.php'] },
      }) };
    },
  });
  assert.deepEqual(result.languages, { PHP: { selected: 1, scanned: 1 } });
  assert.equal(result.findings[0].cwe, 'CWE-78');
  assert.deepEqual(result.findings[0].location, { file: 'src/route.php', line: 1, column: 5 });
  assert.equal(result.findings[0].sourceExcerpt, undefined);
});

test('Semgrep stages configuration using synthetic paths and reports structural matches against original files', async () => {
  const workflow = 'repo/.github/workflows/check.yml';
  const result = await runSemgrep([
    { file: workflow, text: 'synthetic workflow' },
    { file: 'repo/Dockerfile', text: 'FROM scratch' },
  ], {
    run: async (_command, _args, { cwd }) => {
      const workflowPath = 'targets/1/.github/workflows/workflow.yml';
      const dockerPath = 'targets/2/Dockerfile';
      assert.equal(await readFile(path.join(cwd, workflowPath), 'utf8'), 'synthetic workflow');
      assert.equal(await readFile(path.join(cwd, dockerPath), 'utf8'), 'FROM scratch');
      return { stdout: JSON.stringify({
        results: [{
          check_id: 'sentry-github-actions-script-injection', path: workflowPath,
          start: { line: 7, col: 11 }, end: { line: 9, col: 12 },
          extra: { lines: 'sensitive workflow data' },
        }],
        errors: [], paths: { scanned: [workflowPath, dockerPath] },
      }) };
    },
  });
  assert.equal(result.status, 'complete');
  assert.deepEqual(result.languages, { 'GitHub Actions': { selected: 1, scanned: 1 }, Dockerfile: { selected: 1, scanned: 1 } });
  const [finding] = result.findings;
  assert.deepEqual(finding.location, { file: workflow, line: 7, column: 11, endLine: 9, endColumn: 12 });
  assert.equal(finding.detection.method, 'semgrep-pattern');
  assert.match(finding.remediation, /env:/);
  assert.doesNotMatch(JSON.stringify(finding), /sensitive workflow data|scanner-semgrep-/);
});

test('Semgrep failures retain a usable report message without exposing child output', async () => {
  const files = [{ file: 'app.js', text: 'fixture source' }];
  for (const failure of [
    { error: { code: 'ENOENT' }, expected: /Chưa tìm thấy Semgrep/ },
    { error: { killed: true }, expected: /90 giây/ },
    { error: {}, expected: /không hoàn tất/ },
  ]) {
    const result = await runSemgrep(files, { run: async () => {
      throw Object.assign(new Error('raw child output with sensitive source text'), failure.error);
    } });
    assert.equal(result.status, 'failed');
    assert.match(result.message, failure.expected);
    assert.deepEqual(result.findings, []);
    assert.doesNotMatch(result.message, /sensitive source/);
  }
  const malformed = await runSemgrep(files, { run: async () => ({ stdout: '{"results":[]}' }) });
  assert.equal(malformed.status, 'failed');
});

test('deep findings locate the matched code and redact literal, comment and JSX content in exports', async () => {
  const text = [
    'function route(req: Request) {',
    '  const fallback = `template starts',
    '  SECRET_TEMPLATE_CONTINUATION`; const token = "SECRET_STRING"; const rx = /SECRET_REGEX/;',
    '  return eval(req.body.code); /* SECRET_COMMENT_TEXT */',
    '  return <b>SECRET_JSX_TEXT</b>;',
    '}',
  ].join('\r\n');
  const result = await runSemgrep([{ file: 'src/route.tsx', text }], {
    run: async () => ({ stdout: JSON.stringify({
      results: [{
        check_id: 'sentry-js-code-injection', path: 'targets/1.tsx', start: { line: 4, col: 15 },
        extra: { lines: 'SECRET_ENGINE_STDOUT' },
      }],
      errors: [], paths: { scanned: ['targets/1.tsx'] },
    }) }),
  });
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.deepEqual(finding.location, { file: 'src/route.tsx', line: 4, column: 15 });
  assert.match(finding.sourceExcerpt, /> 4 \|.*eval\(req\.body\.code\)/);
  assert.doesNotMatch(JSON.stringify(finding), /SECRET_|scanner-semgrep-/);
  const report = createReport('source', 'fixture');
  report.findings.push(finding);
  finishReport(report);
  const plain = renderText(report);
  const html = renderHtml(report);
  assert.match(plain, /src\/route\.tsx:4:15/);
  assert.match(plain, /> 4 \|/);
  assert.match(html, /src\/route\.tsx:4:15/);
  assert.match(html, /&gt; 4 \|/);
  assert.match(html, /&lt;b&gt;…&lt;\/b&gt;/);
  assert.doesNotMatch(plain + html, /SECRET_/);
});

test('a multiline Semgrep match keeps its start, end and masked lines in one finding', async () => {
  const text = [
    'function route(req) {',
    '  db.query(',
    '    "SECRET_STATEMENT" +',
    '    req.query.id',
    '  );',
    '}',
  ].join('\n');
  const result = await runSemgrep([{ file: 'route.js', text }], {
    run: async () => ({ stdout: JSON.stringify({
      results: [{
        check_id: 'sentry-js-sql-injection', path: 'targets/1.js',
        start: { line: 3, col: 5 }, end: { line: 4, col: 17 },
      }],
      errors: [], paths: { scanned: ['targets/1.js'] },
    }) }),
  });
  assert.equal(result.findings.length, 1);
  const finding = result.findings[0];
  assert.deepEqual(finding.location, { file: 'route.js', line: 3, column: 5, endLine: 4, endColumn: 17 });
  assert.match(finding.sourceExcerpt, /> 3 \|.*\n> 4 \|.*req\.query\.id/);
  assert.doesNotMatch(finding.sourceExcerpt, /SECRET_STATEMENT/);
  const report = createReport('source', 'fixture');
  report.findings.push(finding);
  assert.match(renderText(report), /route\.js:3:5.*4:17/);
  assert.match(renderHtml(report), /route\.js:3:5.*4:17/);
});
