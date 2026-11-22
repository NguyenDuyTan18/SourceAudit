import { createUiServer } from './src/ui-server.mjs';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const sourceDir = fileURLToPath(new URL('./', import.meta.url));
const rootDir = path.resolve(process.env.SRCAUDIT_DATA_DIR || sourceDir);
const accountFile = path.join(rootDir, '.scanner-auth', 'owner.json');
const inContainer = process.env.SRCAUDIT_CONTAINER === '1';
const remoteEnabled = process.env.SRCAUDIT_ENABLE_REMOTE === '1';
const internalPort = 8787;
const bindHost = inContainer ? '0.0.0.0' : '127.0.0.1';

async function containerGateway() {
  const routes = await readFile('/proc/net/route', 'utf8');
  for (const line of routes.split('\n').slice(1)) {
    const [, destination, gateway, flags] = line.trim().split(/\s+/);
    if (destination === '00000000' && /^[0-9A-F]{8}$/i.test(gateway) && (Number.parseInt(flags, 16) & 3) === 3) {
      return [...Buffer.from(gateway, 'hex')].reverse().join('.');
    }
  }
  throw new Error('No IPv4 container gateway found. Start SrcAudit on a Docker bridge network.');
}

let server, publicAccess, containerAccess;
try {
  if (inContainer && remoteEnabled) throw new Error('Container mode supports local access only.');
  if (inContainer) containerAccess = {
    port: Number(process.env.SRCAUDIT_PORT ?? internalPort), gateway: await containerGateway(),
  };
  if (remoteEnabled) publicAccess = JSON.parse(await readFile(path.join(rootDir, '.ui-public.json'), 'utf8'));
  const localOwnerWorkspace = !remoteEnabled && await access(accountFile).then(() => true, (error) => {
    if (error.code !== 'ENOENT') throw error;
    return false;
  });
  await mkdir(rootDir, { recursive: true });
  server = createUiServer({ rootDir, publicAccess, accountFile: remoteEnabled ? accountFile : undefined, localOwnerWorkspace, containerAccess });
} catch (error) {
  const reason = remoteEnabled && !inContainer ? 'Check .ui-public.json and the HTTPS origin.' : error.message;
  console.error('Could not configure SrcAudit. ' + reason);
  process.exit(1);
}

let retried = false;
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE' && !inContainer && !retried) {
    retried = true;
    server.listen(0, bindHost);
  } else {
    console.error('Could not start the SrcAudit server.', error.code);
    process.exitCode = 1;
  }
});
server.on('listening', async () => {
  const url = `http://127.0.0.1:${containerAccess?.port ?? server.address().port}`;
  try {
    await writeFile(path.join(rootDir, '.ui-session.json'), JSON.stringify({ url, pid: process.pid, ...(publicAccess ? { publicUrl: new URL(publicAccess.origin).origin } : {}) }), { mode: 0o600 });
    console.log(`SrcAudit UI: ${url}`);
  } catch {
    console.error('Could not write the SrcAudit session file. Check the data directory permissions.');
    process.exitCode = 1;
    server.close();
  }
});
server.listen(internalPort, bindHost);
