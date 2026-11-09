import { createUiServer } from './src/ui-server.mjs';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('./', import.meta.url));
let publicAccess;
try { publicAccess = JSON.parse(await readFile(path.join(root, '.ui-public.json'), 'utf8')); }
catch (error) {
  if (error.code !== 'ENOENT') { console.error('Không đọc được cấu hình public .ui-public.json.'); process.exit(1); }
}
let server;
try {
  server = createUiServer({ rootDir: root, publicAccess, accountFile: path.join(root, '.scanner-auth', 'owner.json') });
} catch {
  console.error('Cấu hình giao diện không hợp lệ. Kiểm tra origin HTTPS và thông tin đăng nhập public nếu có.');
  process.exit(1);
}
let retried = false;
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE' && !retried) { retried = true; server.listen(0, '127.0.0.1'); }
  else { console.error('Không mở được giao diện local.'); process.exitCode = 1; }
});
server.on('listening', async () => {
  const url = `http://127.0.0.1:${server.address().port}`;
  await writeFile(path.join(root, '.ui-session.json'), JSON.stringify({ url, pid: process.pid, ...(publicAccess ? { publicUrl: new URL(publicAccess.origin).origin } : {}) }), { mode: 0o600 });
  console.log(`SrcAudit UI: ${url}`);
});
server.listen(8787, '127.0.0.1');
