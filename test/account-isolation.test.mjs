import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { access, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { zipSync, strToU8 } from 'fflate';
import { createUiServer } from '../src/ui-server.mjs';

const ownerPassword = 'synthetic owner password';
const memberPassword = 'synthetic member password';
const payload = (code) => ({ upload: { archive: { content: Buffer.from(zipSync({ 'app.js': strToU8(code) })).toString('base64') } } });

async function start(rootDir) {
  const server = createUiServer({ rootDir, accountFile: path.join(rootDir, '.scanner-auth', 'owner.json'), reportRetentionMs: 0 });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = 'http://127.0.0.1:' + server.address().port;
  const request = (route, options = {}) => fetch(origin + route, { redirect: 'manual', ...options });
  const csrf = async (route) => (await (await request(route, { headers: { Accept: 'text/html' } })).text()).match(/name="csrf" value="([a-f0-9]+)"/)[1];
  const form = (route, fields) => request(route, { method: 'POST', headers: { Origin: origin }, body: new URLSearchParams(fields) });
  async function client(cookie) {
    const token = (await (await request('/', { headers: { Cookie: cookie } })).text()).match(/name="session-token" content="([a-f0-9]+)"/)[1];
    const headers = { Cookie: cookie, 'X-Session-Token': token, Origin: origin, 'Content-Type': 'application/json' };
    return {
      get: (route) => request(route, { headers }),
      post: (route, data) => request(route, { method: 'POST', headers, body: JSON.stringify(data) }),
    };
  }
  return {
    origin, request, client,
    async register(username, password) {
      const response = await form('/register', { csrf: await csrf('/register'), username, password, confirmation: password });
      assert.equal(response.status, 303);
      return response.headers.get('set-cookie').split(';')[0];
    },
    async login(username, password) {
      const response = await form('/login', { csrf: await csrf('/login'), username, password });
      return response.status === 303 ? response.headers.get('set-cookie').split(';')[0] : null;
    },
    close: () => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }),
  };
}

async function scan(user, code) {
  const response = await user.post('/api/upload', payload(code));
  assert.equal(response.status, 202);
  const { id } = await response.json();
  for (let i = 0; i < 200; i++) {
    const job = await (await user.get(`/api/jobs/${id}`)).json();
    if (job.status === 'done') return { id, job };
    assert.notEqual(job.status, 'failed', job.error);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('scan did not finish');
}

test('each account sees only its own scans, across restarts and after account removal', async (t) => {
  const rootDir = await mkdtemp(path.join(tmpdir(), 'scanner-isolation-'));
  let ui = await start(rootDir);
  t.after(async () => { await ui.close(); await rm(rootDir, { recursive: true, force: true }); });

  const owner = await ui.client(await ui.register('owner', ownerPassword));
  assert.deepEqual(await (await owner.get('/api/me')).json(), { username: 'owner', role: 'admin', canManageUsers: true });

  // Owner invites a member; weak or duplicate input is refused.
  assert.equal((await owner.post('/api/users', { username: 'member', password: 'short' })).status, 400);
  const created = await owner.post('/api/users', { username: 'Member', password: memberPassword });
  assert.equal(created.status, 201);
  const memberId = (await created.json()).id;
  assert.equal((await owner.post('/api/users', { username: 'member', password: memberPassword })).status, 409);
  assert.equal((await owner.post('/api/users', { username: 'owner', password: memberPassword })).status, 409);
  const accountsFile = await readFile(path.join(rootDir, '.scanner-auth', 'users.json'), 'utf8');
  assert.ok(!accountsFile.includes(memberPassword));

  const member = await ui.client(await ui.login('member', memberPassword));
  assert.equal((await (await member.get('/api/me')).json()).role, 'user');
  assert.equal((await member.get('/api/users')).status, 403);
  assert.equal((await member.post('/api/users', { username: 'intruder', password: memberPassword })).status, 403);

  const ownerScan = await scan(owner, 'eval(req.query.owner);');
  const memberScan = await scan(member, 'eval(req.query.member);');

  // History is filtered by the session's account.
  assert.deepEqual((await (await owner.get('/api/history')).json()).map((job) => job.id), [ownerScan.id]);
  assert.deepEqual((await (await member.get('/api/history')).json()).map((job) => job.id), [memberScan.id]);
  assert.ok(!JSON.stringify(await (await owner.get('/api/history')).json()).includes('ownerId'));

  // Another account's scan is indistinguishable from a scan that does not exist.
  const unknown = randomUUID();
  for (const [user, foreign] of [[member, ownerScan.id], [owner, memberScan.id]]) {
    const jobResponse = await user.get(`/api/jobs/${foreign}`);
    const missingResponse = await user.get(`/api/jobs/${unknown}`);
    assert.equal(jobResponse.status, 404);
    assert.deepEqual(await jobResponse.json(), await missingResponse.json());
    for (const format of ['json', 'html', 'txt']) {
      const file = await user.get(`/api/reports/${foreign}/${format}`);
      assert.equal(file.status, 404);
      assert.deepEqual(await file.json(), await (await user.get(`/api/reports/${unknown}/${format}`)).json());
    }
  }
  const ownReport = await (await member.get(`/api/reports/${memberScan.id}/json`)).text();
  assert.match(ownReport, /req\.query\.member|member/);
  assert.doesNotMatch(ownReport, /req\.query\.owner/);

  // Reports are stored per account and history survives a restart.
  await access(path.join(rootDir, '.scanner-reports', 'user-owner', ownerScan.id, 'meta.json'));
  await access(path.join(rootDir, '.scanner-reports', `user-${memberId}`, memberScan.id, 'report.json'));
  await ui.close();
  ui = await start(rootDir);
  const ownerAgain = await ui.client(await ui.login('owner', ownerPassword));
  const memberAgain = await ui.client(await ui.login('member', memberPassword));
  assert.deepEqual((await (await ownerAgain.get('/api/history')).json()).map((job) => job.id), [ownerScan.id]);
  assert.deepEqual((await (await memberAgain.get('/api/history')).json()).map((job) => job.id), [memberScan.id]);
  assert.equal((await memberAgain.get(`/api/reports/${memberScan.id}/json`)).status, 200);
  assert.equal((await memberAgain.get(`/api/jobs/${ownerScan.id}`)).status, 404);

  // Removing a member ends their sessions and deletes their reports.
  assert.equal((await ownerAgain.post('/api/users/' + randomUUID() + '/delete', {})).status, 404);
  assert.equal((await ownerAgain.post(`/api/users/${memberId}/delete`, {})).status, 200);
  assert.equal((await memberAgain.get('/api/history')).status, 401);
  assert.equal(await ui.login('member', memberPassword), null);
  await assert.rejects(access(path.join(rootDir, '.scanner-reports', `user-${memberId}`)));
  assert.deepEqual((await (await ownerAgain.get('/api/users')).json()).map((user) => user.username), ['owner']);
});

test('one account cannot queue a second scan while its first is pending', async (t) => {
  const rootDir = await mkdtemp(path.join(tmpdir(), 'scanner-isolation-'));
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const server = createUiServer({ rootDir, reportRetentionMs: 0, semgrepRunner: async (files) => { await gate; return { status: 'complete', scanned: files.length, findings: [] }; } });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => { release(); await new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }); await rm(rootDir, { recursive: true, force: true }); });
  const origin = 'http://127.0.0.1:' + server.address().port;
  const token = (await (await fetch(origin)).text()).match(/name="session-token" content="([a-f0-9]+)"/)[1];
  const post = (data) => fetch(origin + '/api/upload', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Session-Token': token, Origin: origin }, body: JSON.stringify(data) });
  assert.equal((await post({ ...payload('eval(x)'), sourceAnalysis: 'deep' })).status, 202);
  assert.equal((await post(payload('eval(y)'))).status, 409);
});
