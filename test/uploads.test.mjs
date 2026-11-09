import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { zipSync, strToU8 } from 'fflate';
import { prepareZipUpload } from '../src/uploads.mjs';
import { scanSource } from '../src/source.mjs';

const content = (text) => Buffer.from(text).toString('base64');
const zipContent = (entries) => Buffer.from(zipSync(entries)).toString('base64');

test('ZIP preserves relative locations and scans common web formats', async (t) => {
  const upload = await prepareZipUpload(zipContent({
    'project/app.ts': strToU8('eval(req.query.code);'),
    'project/style.scss': strToU8('body { color: red; }'),
    'project/page.astro': strToU8('<h1>Hello</h1>'),
  }));
  t.after(() => rm(upload.rootDir, { recursive: true, force: true }));
  const report = await scanSource(upload.rootDir);
  assert.equal(report.stats.filesScanned, 3);
  assert.equal(report.findings[0].location.file, 'project/app.ts');
  assert.deepEqual(report.stats.formats, { '.ts': 1, '.astro': 1, '.scss': 1 });
});
test('ZIP upload is extracted with bounded output and dependency exclusions', async (t) => {
  const upload = await prepareZipUpload(zipContent({
    'app/server.py': strToU8('eval(input())'),
    'app/node_modules/skip.js': strToU8('eval(input)'),
  }));
  t.after(() => rm(upload.rootDir, { recursive: true, force: true }));
  assert.equal(upload.files, 1);
  assert.match(await readFile(path.join(upload.rootDir, 'app', 'server.py'), 'utf8'), /eval/);
});
test('upload rejects escaping paths, duplicate paths, invalid archives and excessive expansion', async () => {
  for (const name of ['../outside.js', '/tmp/outside.js', 'C:\\outside.js', 'a/../../outside.js', 'a\\..\\outside.js', 'a/CON.js']) {
    await assert.rejects(prepareZipUpload(zipContent({ [name]: strToU8('eval(input)') })));
  }
  await assert.rejects(prepareZipUpload(zipContent({ 'a.js': strToU8('a'), 'A.js': strToU8('b') })));
  await assert.rejects(prepareZipUpload(content('not zip')));
  await assert.rejects(prepareZipUpload('%%%bad-base64'));
  await assert.rejects(prepareZipUpload(zipContent({})));
  const large = zipContent({ 'large.js': strToU8('x'.repeat(2000)) });
  await assert.rejects(prepareZipUpload(large, { maxTotalBytes: 1000, maxFileBytes: 5000 }));
});
