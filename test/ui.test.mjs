import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { zipSync, strToU8 } from 'fflate';
import { createUiServer } from '../src/ui-server.mjs';

function zipPayload(files = { 'app.js': 'eval(req.query.code);' }, options = {}) {
  const entries = Object.fromEntries(Object.entries(files).map(([name, text]) => [name, strToU8(text)]));
  const content = Buffer.from(zipSync(entries)).toString('base64');
  return { upload: { archive: { content } }, ...options };
}

async function setup(t, options = {}) {
  const rootDir = await mkdtemp(path.join(tmpdir(), 'scanner-ui-'));
  t.after(() => rm(rootDir, { recursive: true, force: true }));
  const server = createUiServer({ rootDir, ...options });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const authentication = options.publicAccess ? { Authorization: `Basic ${Buffer.from(`${options.publicAccess.username}:${options.publicAccess.password}`).toString('base64')}` } : {};
  const page = await (await fetch(origin, { headers: authentication })).text();
  const token = page.match(/name="session-token" content="([a-f0-9]+)"/)[1];
  const headers = { 'Content-Type': 'application/json', 'X-Session-Token': token, Origin: origin, ...authentication };
  const get = (route) => fetch(origin + route, { headers });
  const post = (route, data) => fetch(origin + route, { method: 'POST', headers, body: JSON.stringify(data) });
  return { rootDir, origin, server, token, headers, page, get, post };
}

async function waitForJob(ui, id, attempts = 100) {
  for (let i = 0; i < attempts; i++) {
    const job = await (await ui.get(`/api/jobs/${id}`)).json();
    if (!['queued', 'running'].includes(job.status)) return job;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('Job timeout');
}

test('UI serves application assets and applies local-session boundaries', async (t) => {
  const ui = await setup(t);
  assert.match(ui.page, /Kiểm tra bảo mật/);
  assert.equal((await fetch(ui.origin + '/app.js')).status, 200);
  assert.equal((await fetch(ui.origin + '/style.css')).status, 200);
  const health = await (await fetch(ui.origin + '/api/health')).json();
  assert.equal(health.application, 'security-scanner-ui');
  assert.equal((await fetch(ui.origin + '/api/bootstrap')).status, 403);
  assert.equal((await fetch(ui.origin + '/api/bootstrap', { headers: { ...ui.headers, Origin: 'https://foreign.example' } })).status, 403);
  const forgedHostStatus = await new Promise((resolve, reject) => {
    const request = http.get(ui.origin, { headers: { Host: 'evil.example' } }, (response) => { response.resume(); resolve(response.statusCode); });
    request.on('error', reject);
  });
  assert.equal(forgedHostStatus, 403);
  assert.equal((await fetch(ui.origin + '/api/bootstrap', { headers: { ...ui.headers, 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.equal((await ui.get('/missing')).status, 404);
  assert.equal((await ui.get('/api/reports/not-a-job/html')).status, 404);
  const bootstrap = await (await ui.get('/api/bootstrap')).json();
  assert.ok(bootstrap.sourceRules.length >= 50);
  assert.equal(bootstrap.knowledge.length, 12);
  assert.ok(bootstrap.sourceExtensions.includes('.js'));
  assert.equal(bootstrap.uploadSchema, 1);
});

test('UI permits opening the home page from an external link while keeping API boundaries', async (t) => {
  const ui = await setup(t);
  const navigation = { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document' };
  const requestNavigation = (route = '/', { method = 'GET', headers = {} } = {}) => new Promise((resolve, reject) => {
    const request = http.request(ui.origin + route, { method, headers: { ...navigation, ...headers } }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
      response.on('error', reject);
    });
    request.on('error', reject);
    request.end();
  });
  const page = await requestNavigation();
  assert.equal(page.status, 200);
  assert.match(page.body, /Kiểm tra bảo mật/);
  assert.equal((await ui.get('/api/bootstrap')).status, 200);
  for (const route of ['/api/bootstrap', '/api/health', '/app.js', '/style.css']) {
    assert.equal((await requestNavigation(route, { headers: ui.headers })).status, 403, route);
  }
  assert.equal((await requestNavigation('/', { headers: { Origin: 'https://foreign.example' } })).status, 403);
  assert.equal((await requestNavigation('/', { headers: { 'Sec-Fetch-Dest': 'iframe' } })).status, 403);
  assert.equal((await requestNavigation('/', { headers: { 'Sec-Fetch-Mode': 'cors' } })).status, 403);
  assert.equal((await requestNavigation('/', { method: 'POST' })).status, 403);
  assert.equal((await requestNavigation('/api/upload', { method: 'POST', headers: ui.headers })).status, 403);
  assert.equal((await requestNavigation('/', { headers: { Host: 'evil.example' } })).status, 403);
});

test('UI public access authenticates every route and accepts only the configured origin', async (t) => {
  const publicAccess = { origin: 'https://scanner.ngrok-free.dev', username: 'scanner', password: 'test-only-password-for-public-ui' };
  const ui = await setup(t, { publicAccess });
  const publicHost = new URL(publicAccess.origin).host;
  const authorization = ui.headers.Authorization;
  const request = (route = '/', { headers = {}, method = 'GET', body } = {}) => new Promise((resolve, reject) => {
    const req = http.request(ui.origin, { path: route, method, headers: { Host: publicHost, ...headers } }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.end(body);
  });
  for (const route of ['/', '/app.js', '/style.css', '/api/health', '/api/bootstrap', '/api/history', '/api/reports/00000000-0000-0000-0000-000000000000/json']) {
    const response = await request(route);
    assert.equal(response.status, 401, route);
    assert.match(response.headers['www-authenticate'], /^Basic /);
    assert.doesNotMatch(response.body, /session-token/);
  }
  assert.equal((await fetch(ui.origin + '/api/health')).status, 401);
  assert.equal((await request('/', { headers: { Authorization: 'Basic invalid' } })).status, 401);
  const loginPage = await request('/', { headers: { Accept: 'text/html' } });
  assert.equal(loginPage.status, 200);
  assert.equal(loginPage.headers['referrer-policy'], 'same-origin');
  assert.match(loginPage.body, /Đăng nhập/);
  assert.doesNotMatch(loginPage.body, /name="session-token"/);
  assert.equal(loginPage.headers['www-authenticate'], undefined);
  const csrf = loginPage.body.match(/name="csrf" value="([a-f0-9]+)"/)[1];
  const loginHeaders = { Origin: publicAccess.origin, 'Content-Type': 'application/x-www-form-urlencoded' };
  const loginBody = new URLSearchParams({ username: publicAccess.username, password: publicAccess.password, csrf }).toString();
  assert.equal((await request('/login', { method: 'POST', headers: loginHeaders, body: 'username=scanner&password=wrong&csrf=' + csrf })).status, 401);
  assert.equal((await request('/login', { method: 'POST', headers: loginHeaders, body: new URLSearchParams({ username: publicAccess.username, password: publicAccess.password }).toString() })).status, 403);
  assert.equal((await request('/login', { method: 'POST', headers: { ...loginHeaders, Origin: 'https://evil.example' }, body: loginBody })).status, 403);
  assert.equal((await request('/login', { method: 'POST', headers: { 'Content-Type': loginHeaders['Content-Type'] }, body: loginBody })).status, 403);
  assert.equal((await request('/login', { method: 'POST', headers: { ...loginHeaders, 'Content-Type': 'application/json' }, body: '{}' })).status, 415);
  assert.equal((await request('/login', { method: 'POST', headers: loginHeaders, body: 'x'.repeat(4097) })).status, 413);
  const login = await request('/login', { method: 'POST', headers: loginHeaders, body: loginBody });
  assert.equal(login.status, 303);
  assert.equal(login.headers.location, '/');
  const setCookie = login.headers['set-cookie'][0];
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Strict/);
  assert.match(setCookie, /Secure/);
  const cookie = setCookie.split(';')[0];
  assert.equal((await request('/', { headers: { Cookie: cookie } })).status, 200);
  assert.equal((await request('/api/bootstrap', { headers: { Cookie: cookie, 'X-Session-Token': ui.token, Origin: publicAccess.origin } })).status, 200);
  assert.equal((await request('/api/bootstrap', { headers: { Cookie: cookie, Origin: publicAccess.origin } })).status, 403);
  assert.equal((await request('/api/bootstrap', { headers: { Cookie: cookie, Host: new URL(ui.origin).host, Origin: ui.origin, 'X-Session-Token': ui.token } })).status, 401);
  const page = await request('/', { headers: { Authorization: authorization } });
  assert.equal(page.status, 200);
  assert.match(page.body, /Kiểm tra bảo mật/);
  assert.ok(!page.body.includes(publicAccess.password));
  const headers = { ...ui.headers, Host: publicHost, Origin: publicAccess.origin };
  assert.equal((await request('/api/bootstrap', { headers })).status, 200);
  assert.equal((await request('/api/bootstrap', { headers: { ...headers, 'X-Session-Token': 'wrong' } })).status, 403);
  assert.equal((await request('/api/bootstrap', { headers: { ...headers, Authorization: '' } })).status, 401);
  assert.equal((await request('/api/bootstrap', { headers: { ...headers, Origin: 'https://evil.example' } })).status, 403);
  assert.equal((await request('/api/bootstrap', { headers: { ...headers, 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.equal((await request('/', { headers: { Authorization: authorization, Host: 'evil.example' } })).status, 403);
  assert.equal((await request('/', { headers: { Authorization: authorization, Host: publicHost + ':444' } })).status, 403);
  assert.equal((await request('https://evil.example/', { headers: { Authorization: authorization } })).status, 403);
  const rewritten = { ...headers, Host: new URL(ui.origin).host, 'X-Forwarded-Host': publicHost };
  assert.equal((await request('/api/bootstrap', { headers: rewritten })).status, 200);
  assert.equal((await request('/api/bootstrap', { headers: { ...rewritten, 'X-Forwarded-Host': 'evil.example' } })).status, 403);
  assert.equal((await request('/', { headers: { ...rewritten, Authorization: '' } })).status, 401);
  const localhost = `localhost:${ui.server.address().port}`;
  assert.equal((await request('/api/bootstrap', { headers: { ...ui.headers, Host: localhost, Origin: `http://${localhost}` } })).status, 200);
  assert.equal((await request('/api/scan', { method: 'POST', headers, body: JSON.stringify({ mode: 'source', target: ui.rootDir }) })).status, 404);
  assert.equal((await request('/api/upload', { method: 'POST', headers, body: JSON.stringify(zipPayload(undefined, { rulesPath: 'server-rules.json' })) })).status, 400);
  const started = await request('/api/upload', { method: 'POST', headers, body: JSON.stringify(zipPayload()) });
  assert.equal(started.status, 202);
  assert.equal((await waitForJob(ui, JSON.parse(started.body).id)).status, 'done');
});

test('UI refuses incomplete or unsafe public-access configuration', () => {
  const valid = { origin: 'https://scanner.ngrok-free.dev', username: 'scanner', password: 'test-only-password-for-public-ui' };
  for (const invalid of [null, {}, { ...valid, origin: 'http://scanner.ngrok-free.dev' }, { ...valid, origin: 'https://user:pass@scanner.ngrok-free.dev' }, { ...valid, origin: valid.origin + '/extra' }, { ...valid, origin: valid.origin + '?x=1' }, { ...valid, origin: valid.origin + '#x' }, { ...valid, username: 'user:name' }, { ...valid, password: 'short' }, { ...valid, password: 'x'.repeat(257) }, { ...valid, password: 'test-only-password\nwith-control' }]) {
    assert.throws(() => createUiServer({ publicAccess: invalid }), /public/i);
  }
});

test('UI ZIP scan returns detailed findings, downloadable reports and session history', async (t) => {
  const ui = await setup(t);
  const start = await ui.post('/api/upload', zipPayload());
  assert.equal(start.status, 202);
  const job = await waitForJob(ui, (await start.json()).id);
  assert.equal(job.status, 'done');
  assert.equal(job.report.findings[0].ruleId, 'SRC-EVAL');
  for (const format of ['json', 'html', 'txt']) {
    const file = await ui.get(`/api/reports/${job.id}/${format}`);
    assert.equal(file.status, 200);
    assert.match(file.headers.get('content-disposition'), /attachment/);
    assert.match(await file.text(), /SRC-EVAL/);
  }
  assert.equal((await (await ui.get('/api/history')).json()).length, 1);
});

test('UI uses deep source analysis only when selected for a ZIP', async (t) => {
  const calls = [];
  const ui = await setup(t, { semgrepRunner: async (files) => {
    calls.push(files.map(({ file }) => file));
    return { status: 'complete', scanned: files.length, findings: [] };
  } });
  const files = {
    'project/.github/workflows/check.yml': 'jobs: {}',
    'project/Dockerfile': 'FROM scratch',
    'project/config/check.yaml': 'jobs: {}',
    'src/index.ts': 'eval(req.query.code);',
    ...Object.fromEntries(['py', 'php', 'java', 'go', 'cs', 'rb'].map((ext) => ['src/example.' + ext, 'sample'])),
  };
  const quick = await ui.post('/api/upload', zipPayload(files));
  const quickJob = await waitForJob(ui, (await quick.json()).id);
  assert.ok(quickJob.report.findings.some(({ ruleId }) => ruleId === 'SRC-EVAL'));
  assert.deepEqual(calls, []);

  const deep = await ui.post('/api/upload', zipPayload(files, { sourceAnalysis: 'deep' }));
  assert.equal(deep.status, 202);
  const deepJob = await waitForJob(ui, (await deep.json()).id);
  assert.equal(deepJob.report.stats.sourceAnalysis.status, 'complete');
  assert.equal(deepJob.report.stats.sourceAnalysis.scanned, 9);
  assert.deepEqual(calls, [[
    'project/.github/workflows/check.yml', 'project/Dockerfile',
    ...['cs', 'go', 'java', 'php', 'py', 'rb'].map((ext) => 'src/example.' + ext),
    'src/index.ts',
  ]]);
  assert.deepEqual(deepJob.report.findings, []);
  assert.equal((await ui.post('/api/upload', zipPayload(files, { sourceAnalysis: 'unknown' }))).status, 400);
});

test('UI reports a missing Semgrep engine as incomplete without falling back to quick results', async (t) => {
  const ui = await setup(t, { semgrepRunner: async () => ({
    status: 'failed', scanned: 0, findings: [], message: 'Chưa cài Semgrep.',
  }) });
  const start = await ui.post('/api/upload', zipPayload(undefined, { sourceAnalysis: 'deep' }));
  const job = await waitForJob(ui, (await start.json()).id);
  assert.equal(job.report.status, 'partial');
  assert.match(job.report.errors.join(' '), /Chưa cài Semgrep/);
  assert.deepEqual(job.report.findings, []);
});

test('UI validates input, limits request bodies and recovers after failed jobs', async (t) => {
  const ui = await setup(t);
  assert.equal((await ui.post('/api/upload', {})).status, 400);
  assert.equal((await fetch(ui.origin + '/api/upload', { method: 'POST', headers: { 'X-Session-Token': ui.token }, body: '{}' })).status, 415);
  assert.equal((await fetch(ui.origin + '/api/upload', { method: 'POST', headers: ui.headers, body: '{' })).status, 400);
  assert.equal((await fetch(ui.origin + '/api/upload', { method: 'POST', headers: ui.headers, body: ' '.repeat(30 * 1024 * 1024 + 1) })).status, 413);
  const start = await ui.post('/api/upload', { upload: { archive: { content: 'bm90IHppcA==' } } });
  const job = await waitForJob(ui, (await start.json()).id);
  assert.equal(job.status, 'failed');
  assert.match(job.error, /ZIP không hợp lệ/);
  assert.ok(!job.error.includes('ENOENT'));
  const retry = await ui.post('/api/upload', zipPayload());
  assert.equal(retry.status, 202);
  assert.equal((await waitForJob(ui, (await retry.json()).id)).status, 'done');
});

test('UI refuses concurrent source scans', async (t) => {
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const ui = await setup(t, { semgrepRunner: async (files) => {
    await gate;
    return { status: 'complete', scanned: files.length, findings: [] };
  } });
  const start = await ui.post('/api/upload', zipPayload(undefined, { sourceAnalysis: 'deep' }));
  assert.equal(start.status, 202);
  try { assert.equal((await ui.post('/api/upload', zipPayload())).status, 409); }
  finally { release(); }
  assert.equal((await waitForJob(ui, (await start.json()).id)).status, 'done');
});

test('UI and API expose source scanning only', async (t) => {
  const ui = await setup(t);
  assert.match(ui.page, /Phân tích mã nguồn/);
  assert.match(ui.page, /id="source-zip" type="file" accept="\.zip,application\/zip"/);
  assert.match(ui.page, /id="source-folder" type="file" webkitdirectory/);
  assert.doesNotMatch(ui.page, /Pentest website|OWASP ZAP|Tìm cờ CTF|id="(?:target-input|rules-path|demo-button)"/);
  const zipModule = await fetch(ui.origin + '/fflate-browser.js');
  assert.equal(zipModule.status, 200);
  assert.match(zipModule.headers.get('content-type'), /^text\/javascript/);
  for (const data of [
    { mode: 'url', profile: 'pentest', target: 'https://example.test' },
    { mode: 'url', target: 'https://example.test' },
    { mode: 'source', target: 'https://example.test' },
  ]) assert.equal((await ui.post('/api/scan', data)).status, 404);
  assert.deepEqual(await (await ui.get('/api/history')).json(), []);
});

test('scan API only accepts ZIP content and never schedules a user supplied host path', async (t) => {
  const ui = await setup(t);
  assert.equal((await ui.post('/api/scan', { mode: 'source', target: ui.rootDir })).status, 404);
  assert.equal((await ui.post('/api/demo', {})).status, 404);
  for (const data of [
    { upload: { files: [{ path: 'app.js', content: 'YQ==' }] } },
    zipPayload(undefined, { target: ui.rootDir }),
    zipPayload(undefined, { rulesPath: path.join(ui.rootDir, 'rules.json') }),
    { upload: { ...zipPayload().upload, files: [] } },
  ]) assert.equal((await ui.post('/api/upload', data)).status, 400);
  assert.deepEqual(await (await ui.get('/api/history')).json(), []);
});

test('UI imports writeup text without retaining raw article content', async (t) => {
  const ui = await setup(t);
  const result = await ui.post('/api/writeups', { text: 'SQL injection and parameterized queries. password="demo-credential-do-not-retain"' });
  assert.equal(result.status, 200);
  const imported = await result.json();
  assert.ok(imported.topics.includes('sql-injection'));
  assert.ok(!JSON.stringify(imported).includes('demo-credential'));
  assert.equal((await ui.post('/api/writeups', { text: '' })).status, 400);
});

test('UI uploads ZIP, returns relative evidence and reports formats', async (t) => {
  const ui = await setup(t);
  const response = await ui.post('/api/upload', zipPayload({ 'project/app.js': 'eval(req.query.code);' }, { label: 'C:\\private\\project.zip' }));
  assert.equal(response.status, 202);
  const job = await waitForJob(ui, (await response.json()).id);
  assert.equal(job.status, 'done');
  assert.equal(job.report.target, 'Upload: project.zip');
  assert.equal(job.report.findings[0].location.file, 'project/app.js');
  assert.equal(job.report.stats.formats['.js'], 1);
});

test('UI knowledge API searches real CVE and OWASP records with bounded pages and filters', async (t) => {
  const ui = await setup(t);
  let data = await (await ui.get('/api/knowledge?q=CVE-2021-23337&kind=advisory')).json();
  assert.ok(data.results.some((entry) => entry.cve === 'CVE-2021-23337'));
  data = await (await ui.get('/api/knowledge?kind=cwe&page=2')).json();
  assert.equal(data.page, 2); assert.equal(data.results.length, 25);
  data = await (await ui.get('/api/knowledge?kind=curated&q=sql')).json();
  assert.ok(data.results.some((entry) => entry.id === 'sql-injection'));
  assert.equal((await ui.get('/api/knowledge?kind=invalid')).status, 400);
  data = await (await ui.get('/api/knowledge?kind=asvs&q=ASVS-v5.0.0-1.2.4')).json();
  assert.equal(data.results[0].id, 'ASVS-v5.0.0-1.2.4');
  data = await (await ui.get('/api/knowledge?kind=kev&q=CVE-2020-11023')).json();
  assert.equal(data.results[0].kind, 'kev');
});
