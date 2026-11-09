import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createUiServer } from '../src/ui-server.mjs';
import { isManagedReportName, pruneReports, resolveRetentionMs } from '../src/report-retention.mjs';

const DAY = 24 * 60 * 60 * 1000;
const OLD_UUID = '11111111-2222-3333-4444-555555555555';
const NEW_UUID = '66666666-7777-8888-9999-aaaaaaaaaaaa';
const OLD_CLI = '2026-01-01T00-00-00-000Z';

async function fixture(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'scanner-retention-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const reports = path.join(root, '.scanner-reports');
  const now = Date.now();
  for (const [name, age] of [[OLD_UUID, 10 * DAY], [NEW_UUID, 1 * DAY], [OLD_CLI, 30 * DAY], ['sample', 30 * DAY]]) {
    const dir = path.join(reports, name);
    await mkdir(dir, { recursive: true });
    await writeFile(path.join(dir, 'report.json'), '{}');
    const when = new Date(now - age);
    await utimes(dir, when, when);
  }
  return { root, reports, now };
}

test('resolveRetentionMs uses 7 days by default and validates input', () => {
  assert.equal(resolveRetentionMs(undefined), 7 * DAY);
  assert.equal(resolveRetentionMs('0'), 0);
  assert.equal(resolveRetentionMs('1.5'), 1.5 * DAY);
  for (const bad of ['-1', 'abc', '366']) assert.throws(() => resolveRetentionMs(bad));
});

test('only SourceAudit-created report names are managed', () => {
  assert.ok(isManagedReportName(OLD_UUID));
  assert.ok(isManagedReportName(OLD_CLI));
  for (const name of ['sample', '..', 'node_modules', `${OLD_UUID}x`]) assert.ok(!isManagedReportName(name));
});

test('pruneReports removes expired managed folders and keeps the rest', async (t) => {
  const { reports, now } = await fixture(t);
  const removed = await pruneReports(reports, { maxAgeMs: 7 * DAY, now });
  assert.deepEqual(removed.sort(), [OLD_CLI, OLD_UUID].sort());
  assert.deepEqual((await readdir(reports)).sort(), [NEW_UUID, 'sample'].sort());
});

test('pruneReports is a no-op when disabled or the folder is missing', async (t) => {
  const { reports, root } = await fixture(t);
  assert.deepEqual(await pruneReports(reports, { maxAgeMs: 0 }), []);
  assert.equal((await readdir(reports)).length, 4);
  assert.deepEqual(await pruneReports(path.join(root, 'missing'), { maxAgeMs: DAY }), []);
});

test('UI server sweeps expired reports on disk', async (t) => {
  const { root, reports } = await fixture(t);
  const server = createUiServer({ rootDir: root, reportRetentionMs: 7 * DAY });
  t.after(() => server.close());
  await server.sweepReports();
  assert.deepEqual((await readdir(reports)).sort(), [NEW_UUID, 'sample'].sort());
});
