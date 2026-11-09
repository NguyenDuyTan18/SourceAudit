import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createUiServer } from '../src/ui-server.mjs';

const password = 'synthetic account password';

async function start(rootDir, publicAccess) {
  const accountFile = path.join(rootDir, '.scanner-auth', 'owner.json');
  const server = createUiServer({ rootDir, accountFile, publicAccess });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = 'http://127.0.0.1:' + server.address().port;
  return {
    origin,
    accountFile,
    request: (route, options = {}) => fetch(origin + route, { redirect: 'manual', ...options }),
    close: () => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }),
  };
}

async function formToken(ui, route = '/login', headers = {}) {
  const response = await ui.request(route, { headers: { Accept: 'text/html', ...headers } });
  assert.equal(response.status, 200);
  return (await response.text()).match(/name="csrf" value="([a-f0-9]+)"/)?.[1];
}

function submit(ui, route, fields, headers = {}) {
  return ui.request(route, {
    method: 'POST',
    headers: { Origin: ui.origin, ...headers },
    body: new URLSearchParams(fields),
  });
}

function cookieOf(response) {
  const cookie = response.headers.get('set-cookie');
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  return cookie.split(';')[0];
}

test('owner registers locally, signs out, and signs back in after restart', async (t) => {
  const rootDir = await mkdtemp(path.join(tmpdir(), 'scanner-account-'));
  let ui = await start(rootDir);
  t.after(async () => { await ui.close(); await rm(rootDir, { recursive: true, force: true }); });

  const entry = await ui.request('/', { headers: { Accept: 'text/html' } });
  assert.match(await entry.text(), /Đăng ký/);
  assert.equal((await ui.request('/api/health')).status, 200);
  assert.equal((await ui.request('/api/bootstrap')).status, 401);
  const csrf = await formToken(ui, '/register');
  const registration = { csrf, username: 'Owner', password, confirmation: password };
  assert.equal((await submit(ui, '/register', { ...registration, csrf: '' })).status, 403);
  assert.equal((await submit(ui, '/register', { ...registration, confirmation: 'different' })).status, 400);
  assert.equal((await submit(ui, '/register', { ...registration, password: 'short', confirmation: 'short' })).status, 400);
  const signups = await Promise.all([submit(ui, '/register', registration), submit(ui, '/register', registration)]);
  assert.deepEqual(signups.map((response) => response.status).sort(), [303, 409]);
  const signup = signups.find((response) => response.status === 303);
  const cookie = cookieOf(signup);
  const raw = await readFile(ui.accountFile, 'utf8');
  assert.ok(!raw.includes(password));
  const record = JSON.parse(raw);
  assert.equal(record.username, 'owner');
  assert.match(record.salt, /^[a-f0-9]{32}$/);
  assert.match(record.hash, /^[a-f0-9]{128}$/);
  assert.equal((await submit(ui, '/register', { ...registration, username: 'second' })).status, 409);

  const html = await (await ui.request('/', { headers: { Cookie: cookie } })).text();
  const sessionToken = html.match(/name="session-token" content="([a-f0-9]+)"/)[1];
  assert.match(html, /Đăng xuất/);
  const sessionHeaders = { Cookie: cookie, 'X-Session-Token': sessionToken };
  assert.equal((await ui.request('/api/bootstrap', { headers: sessionHeaders })).status, 200);
  assert.equal((await ui.request('/api/logout', { method: 'POST', headers: sessionHeaders })).status, 403);
  const logout = await ui.request('/api/logout', { method: 'POST', headers: { ...sessionHeaders, Origin: ui.origin } });
  assert.equal(logout.status, 200);
  assert.match(logout.headers.get('set-cookie'), /Max-Age=0/);
  assert.equal((await ui.request('/api/bootstrap', { headers: sessionHeaders })).status, 401);

  await ui.close();
  ui = await start(rootDir);
  const nextCsrf = await formToken(ui);
  assert.equal((await submit(ui, '/login', { csrf: nextCsrf, username: 'owner', password: 'incorrect' })).status, 401);
  const login = await submit(ui, '/login', { csrf: nextCsrf, username: 'OWNER', password });
  assert.equal(login.status, 303);
  assert.match(await (await ui.request('/', { headers: { Cookie: cookieOf(login) } })).text(), /Kiểm tra bảo mật/);
});

test('public origin can sign in with the owner account but cannot register through the proxy', async (t) => {
  const rootDir = await mkdtemp(path.join(tmpdir(), 'scanner-account-'));
  const publicOrigin = 'https://scanner.ngrok-free.dev';
  const ui = await start(rootDir, { origin: publicOrigin });
  t.after(async () => { await ui.close(); await rm(rootDir, { recursive: true, force: true }); });
  const proxy = { 'X-Forwarded-Host': new URL(publicOrigin).host, Origin: publicOrigin };
  assert.equal((await ui.request('/register', { headers: proxy })).status, 403);
  assert.equal((await submit(ui, '/register', {}, proxy)).status, 403);
  assert.equal((await ui.request('/register', { headers: { 'X-Forwarded-For': '192.0.2.3' } })).status, 403);
  assert.equal((await ui.request('/api/health', { headers: proxy })).status, 401);
  const csrf = await formToken(ui, '/register');
  const signup = await submit(ui, '/register', { csrf, username: 'owner', password, confirmation: password });
  assert.equal(signup.status, 303);
  const publicCsrf = await formToken(ui, '/login', proxy);
  const login = await submit(ui, '/login', { csrf: publicCsrf, username: 'owner', password }, proxy);
  assert.equal(login.status, 303);
  assert.match(login.headers.get('set-cookie'), /; Secure/);
  assert.match(await (await ui.request('/', { headers: { ...proxy, Cookie: cookieOf(login) } })).text(), /Kiểm tra bảo mật/);
  assert.equal((await ui.request('/', { headers: { Cookie: cookieOf(login) } })).status, 401);
});

test('password attempts are bounded for each login surface', async (t) => {
  const rootDir = await mkdtemp(path.join(tmpdir(), 'scanner-account-'));
  const publicOrigin = 'https://scanner.ngrok-free.dev';
  const ui = await start(rootDir, { origin: publicOrigin });
  t.after(async () => { await ui.close(); await rm(rootDir, { recursive: true, force: true }); });
  const proxy = { 'X-Forwarded-Host': new URL(publicOrigin).host, Origin: publicOrigin };
  const csrf = await formToken(ui, '/login', proxy);
  const bad = { csrf, username: 'unknown', password: 'incorrect' };
  for (let i = 0; i < 10; i++) assert.equal((await submit(ui, '/login', bad, proxy)).status, 401);
  assert.equal((await submit(ui, '/login', bad, proxy)).status, 429);
  assert.equal((await submit(ui, '/login', bad)).status, 401);
});
