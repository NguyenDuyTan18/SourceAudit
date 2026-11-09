import http from 'node:http';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { readFile, readdir, writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanSource, SOURCE_RULES, SUPPORTED_SOURCE_EXTENSIONS } from './source.mjs';
import { prepareZipUpload, ZipInputError } from './uploads.mjs';
import { writeReports, renderHtml, renderText, finishReport } from './report.mjs';
import { KNOWLEDGE, importWriteup, loadWriteups, enrichReport } from './knowledge.mjs';
import { corpusStats, searchCorpus } from './corpus.mjs';
import { createAccountStore, normalizeOwnerUsername, OWNER_ID, validOwnerPassword, validOwnerUsername } from './owner-account.mjs';
import { isUserReportFolder, pruneReports, resolveRetentionMs } from './report-retention.mjs';

const RETENTION_SWEEP_MS = 60 * 60 * 1000;
const MAX_JOBS_PER_USER = 20;
const MAX_QUEUE = 10;
const JOB_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

const WEB = fileURLToPath(new URL('../web/', import.meta.url));
const ZIP_MODULE = fileURLToPath(import.meta.resolve('fflate/browser'));
class InputError extends Error { constructor(status, message) { super(message); this.status = status; } }

function readJson(request, limit) {
  if (!/^application\/json(?:;|$)/i.test(request.headers['content-type'] ?? '')) throw new InputError(415, 'Cần gửi dữ liệu JSON.');
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0; let rejected = false;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) { rejected = true; reject(new InputError(413, 'Dữ liệu nhập vượt giới hạn.')); }
      else if (!rejected) chunks.push(chunk);
    });
    request.on('error', () => reject(new InputError(400, 'Không nhận được dữ liệu.')));
    request.on('end', () => {
      if (rejected) return;
      try {
        const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
        resolve(value);
      } catch { reject(new InputError(400, 'Dữ liệu JSON không hợp lệ.')); }
    });
  });
}

function readLoginForm(request) {
  if (!/^application\/x-www-form-urlencoded(?:;|$)/i.test(request.headers['content-type'] ?? '')) throw new InputError(415, 'Biểu mẫu đăng nhập không hợp lệ.');
  return new Promise((resolve, reject) => {
    const chunks = []; let size = 0; let rejected = false;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > 4096) { rejected = true; reject(new InputError(413, 'Biểu mẫu đăng nhập vượt giới hạn.')); }
      else if (!rejected) chunks.push(chunk);
    });
    request.on('error', () => reject(new InputError(400, 'Không nhận được biểu mẫu đăng nhập.')));
    request.on('end', () => { if (!rejected) resolve(new URLSearchParams(Buffer.concat(chunks).toString('utf8'))); });
  });
}

export function createUiServer({ rootDir, semgrepRunner, publicAccess, accountFile, reportRetentionMs } = {}) {
  const retentionMs = reportRetentionMs ?? resolveRetentionMs();
  const accounts = accountFile ? createAccountStore(path.resolve(accountFile)) : undefined;
  let publicEndpoint;
  let authenticationHash;
  if (publicAccess !== undefined) {
    try {
      const endpoint = new URL(publicAccess.origin);
      const legacyCredentials = publicAccess.username !== undefined || publicAccess.password !== undefined;
      if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.pathname !== '/' || endpoint.search || endpoint.hash ||
          (!accounts && !legacyCredentials)) {
        throw new Error();
      }
      if (legacyCredentials) {
        if (typeof publicAccess.username !== 'string' || !/^[A-Za-z0-9_.-]{1,64}$/.test(publicAccess.username) ||
            typeof publicAccess.password !== 'string' || publicAccess.password.length < 20 ||
            Buffer.byteLength(publicAccess.password) > 256 || /[\x00-\x1f\x7f]/.test(publicAccess.password)) throw new Error();
        authenticationHash = createHash('sha256').update(Buffer.from(`${publicAccess.username}:${publicAccess.password}`, 'utf8').toString('base64')).digest();
      }
      publicEndpoint = endpoint;
    } catch { throw new Error('Cấu hình public không hợp lệ. Kiểm tra origin HTTPS và thông tin đăng nhập cũ nếu có.'); }
  }
  const root = path.resolve(rootDir ?? fileURLToPath(new URL('../', import.meta.url)));
  const token = randomBytes(24).toString('hex');
  const loginCsrf = randomBytes(24).toString('hex');
  const accessSessions = new Map();
  const loginAttempts = new Map();
  let passwordWork = 0;
  const legacyIdentity = { userId: 'legacy', username: publicAccess?.username ?? 'legacy', role: 'user' };
  const localIdentity = { userId: 'local', username: 'local', role: 'user' };
  const matchesLegacy = (value) => Boolean(authenticationHash &&
    timingSafeEqual(authenticationHash, createHash('sha256').update(value).digest()));
  async function runPasswordWork(work) {
    if (passwordWork >= 2) throw new InputError(429, 'Đang xử lý đăng nhập. Hãy thử lại sau.');
    passwordWork++;
    try { return await work(); }
    finally { passwordWork--; }
  }
  // Every scan belongs to exactly one account (ownerId). Ids come from the server-side session only.
  const jobs = new Map();
  const queue = [];
  let running = false;
  const knowledgeDir = path.join(root, 'knowledge-local');
  const reportsDir = path.join(root, '.scanner-reports');
  const userDir = (ownerId) => path.join(reportsDir, `user-${ownerId}`);
  const jobDir = (job) => path.join(userDir(job.ownerId), job.id);
  const ownedJob = (id, identity) => {
    const job = jobs.get(id);
    // Someone else's scan is reported exactly like a missing one, so ids cannot be probed.
    return job && job.ownerId === identity.userId ? job : undefined;
  };
  function publicJob(job) {
    const { ownerId, ...view } = job;
    if (job.status === 'queued') {
      const ahead = queue.findIndex((entry) => entry.job === job);
      view.stage = ahead > 0 ? `Đang chờ ${ahead} lượt kiểm tra phía trước…` : 'Đang chờ đến lượt…';
    }
    return view;
  }
  async function readJobReport(job) {
    try { return JSON.parse(await readFile(path.join(jobDir(job), 'report.json'), 'utf8')); }
    catch { return undefined; }
  }
  async function persistMeta(job) {
    await mkdir(jobDir(job), { recursive: true });
    const { stage, ...meta } = job;
    await writeFile(path.join(jobDir(job), 'meta.json'), JSON.stringify(meta), { mode: 0o600 });
  }
  async function forgetJob(job) {
    jobs.delete(job.id);
    await rm(jobDir(job), { recursive: true, force: true }).catch(() => {});
  }
  async function trimHistory(ownerId) {
    const finished = [...jobs.values()].filter((job) => job.ownerId === ownerId && job.finishedAt)
      .sort((a, b) => a.startedAt.localeCompare(b.startedAt));
    for (const job of finished.slice(0, Math.max(0, finished.length - MAX_JOBS_PER_USER))) await forgetJob(job);
  }
  // Restore each account's finished scans from disk so history survives restarts.
  async function loadPersisted() {
    let folders;
    try { folders = await readdir(reportsDir, { withFileTypes: true }); } catch { return; }
    const restored = [];
    for (const folder of folders) {
      if (!folder.isDirectory() || !isUserReportFolder(folder.name)) continue;
      let entries;
      try { entries = await readdir(path.join(reportsDir, folder.name), { withFileTypes: true }); } catch { continue; }
      for (const entry of entries) {
        if (!entry.isDirectory() || !JOB_ID.test(entry.name)) continue;
        try {
          const meta = JSON.parse(await readFile(path.join(reportsDir, folder.name, entry.name, 'meta.json'), 'utf8'));
          if (meta?.id !== entry.name || `user-${meta.ownerId}` !== folder.name ||
              !['done', 'failed'].includes(meta.status) || typeof meta.startedAt !== 'string') continue;
          restored.push(meta);
        } catch { /* folders without valid metadata are left to retention */ }
      }
    }
    restored.sort((a, b) => a.startedAt.localeCompare(b.startedAt));
    for (const job of restored) if (!jobs.has(job.id)) jobs.set(job.id, job);
  }
  const loaded = loadPersisted();
  // Drop finished jobs (in memory) and report folders (on disk) older than the retention period.
  async function sweepReports(now = Date.now()) {
    if (!retentionMs) return;
    await loaded;
    for (const [id, job] of jobs) {
      if (job.finishedAt && now - Date.parse(job.finishedAt) > retentionMs) jobs.delete(id);
    }
    try { await pruneReports(reportsDir, { maxAgeMs: retentionMs, now }); } catch { /* retried on next sweep */ }
  }
  function pump() {
    if (running || !queue.length) return;
    const entry = queue.shift();
    running = true;
    void runJob(entry).catch(() => {});
  }
  function startJob(data, identity) {
    const { upload, label } = data;
    const content = upload?.archive?.content;
    if (Object.keys(data).some((key) => !['upload', 'label', 'sourceAnalysis'].includes(key)) ||
        typeof content !== 'string' || !content ||
        Object.keys(upload).length !== 1 || Object.keys(upload.archive).length !== 1) {
      throw new InputError(400, 'Chỉ nhận một tệp ZIP mã nguồn.');
    }
    const sourceAnalysis = data.sourceAnalysis ?? 'quick';
    if (!['quick', 'deep'].includes(sourceAnalysis)) throw new InputError(400, 'Chọn quét nhanh hoặc phân tích sâu.');
    if ([...jobs.values()].some((job) => job.ownerId === identity.userId && ['queued', 'running'].includes(job.status))) {
      throw new InputError(409, 'Một lần kiểm tra đang chạy. Hãy chờ kết quả trước khi bắt đầu lần khác.');
    }
    if (queue.length >= MAX_QUEUE) throw new InputError(503, 'Hàng đợi kiểm tra đang đầy. Hãy thử lại sau ít phút.');
    const job = { id: randomUUID(), ownerId: identity.userId, mode: 'upload', sourceAnalysis, status: 'queued', startedAt: new Date().toISOString() };
    jobs.set(job.id, job);
    queue.push({ job, content, label, sourceAnalysis });
    pump();
    return job.id;
  }
  async function runJob({ job, content, label, sourceAnalysis }) {
    job.status = 'running'; job.stage = 'Đang kiểm tra tệp ZIP…';
    {
      let uploaded;
      try {
        await mkdir(knowledgeDir, { recursive: true });
        const outputDir = jobDir(job);
        const writeups = await loadWriteups(knowledgeDir);
        uploaded = await prepareZipUpload(content);
        job.stage = sourceAnalysis === 'deep' ? 'Semgrep đang phân tích mã nguồn…' : 'Đang quét mã nguồn…';
        const report = await scanSource(uploaded.rootDir, {
          analysis: sourceAnalysis, semgrepRunner,
        });
        const archiveName = typeof label === 'string' ? label.split(/[/\\]/).at(-1).replace(/[\x00-\x1f]/g, '').slice(0, 160) : '';
        report.target = 'Upload: ' + (archiveName || 'source.zip');
        report.stats.uploadedFiles = uploaded.files;
        report.errors.push(...uploaded.warnings);
        finishReport(report);
        enrichReport(report, writeups);
        await writeReports(report, outputDir);
        job.target = report.target;
        job.count = report.findings.length;
        job.scanStatus = report.status;
      } catch (error) {
        job.status = 'failed';
        job.error = error instanceof ZipInputError ? error.message
          : uploaded ? 'Lượt quét bị gián đoạn. Kiểm tra quyền ghi báo cáo hoặc thử lại với một mẫu nhỏ.'
            : 'Không đọc được nội dung ZIP. Hãy nén lại thư mục hoặc dùng chế độ Tải thư mục.';
      } finally {
        if (uploaded) {
          try { await rm(uploaded.rootDir, { recursive: true, force: true }); }
          catch { job.status = 'failed'; job.error = 'Không xóa được source upload tạm. Kiểm tra quyền thư mục tạm của Windows.'; }
        }
        delete job.stage;
        if (job.status === 'running') job.status = 'done';
        job.finishedAt = new Date().toISOString();
        // Let the next queued scan start while this one's metadata is written.
        running = false; pump();
      }
      if (!jobs.has(job.id) || (accounts && !(await isLiveAccount(job.ownerId)))) {
        // The account was removed while this scan ran: discard its output.
        await forgetJob(job);
        return;
      }
      try { await persistMeta(job); } catch { /* history for this scan lasts until restart */ }
      await trimHistory(job.ownerId);
    }
  }
  async function isLiveAccount(ownerId) {
    if (ownerId === 'legacy' || ownerId === 'local') return true;
    try { return await accounts.exists(ownerId); } catch { return true; }
  }

  const server = http.createServer(async (request, response) => {
    const send = (status, value, type = 'application/json; charset=utf-8', extra = {}) => {
      response.writeHead(status, { 'Content-Type': type, ...extra });
      response.end(type.startsWith('application/json') ? JSON.stringify(value) : value);
    };
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Referrer-Policy', 'no-referrer');
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; form-action 'self'");
    const localHost = `127.0.0.1:${server.address().port}`;
    const localhost = `localhost:${server.address().port}`;
    const host = request.headers.host;
    const forwardedHost = request.headers['x-forwarded-host'];
    const isLocalHost = host === localHost || host === localhost;
    const isPublicHost = publicEndpoint && host === publicEndpoint.host;
    const origin = publicEndpoint && (isPublicHost || forwardedHost === publicEndpoint.host) ? publicEndpoint.origin : `http://${host}`;
    try {
      if ((!isLocalHost && !isPublicHost) || (forwardedHost !== undefined && forwardedHost !== publicEndpoint?.host)) {
        throw new InputError(403, 'Tên miền chưa được cho phép. Hãy dùng địa chỉ local hoặc tên miền public đã cấu hình.');
      }
      const url = new URL(request.url, origin);
      const route = url.pathname;
      // External links may open the home page; API calls still require the local origin and session.
      const homeNavigation = request.method === 'GET' && route === '/' &&
        request.headers['sec-fetch-mode'] === 'navigate' && request.headers['sec-fetch-dest'] === 'document';
      if (url.origin !== origin ||
          (request.headers.origin && request.headers.origin !== origin) ||
          (request.headers['sec-fetch-site'] === 'cross-site' && !homeNavigation)) {
        throw new InputError(403, 'Nguồn yêu cầu không hợp lệ. Hãy tải lại giao diện từ địa chỉ đã cấu hình.');
      }
      const directLocal = isLocalHost && ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(request.socket.remoteAddress) &&
        !['forwarded', 'via', 'x-real-ip', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'x-forwarded-port']
          .some((name) => request.headers[name] !== undefined);
      if (accounts && directLocal && request.method === 'GET' && route === '/api/health') {
        return send(200, { application: 'security-scanner-ui' });
      }
      const secure = origin.startsWith('https:');
      const cookieName = secure ? '__Host-scanner-access' : 'scanner-local-access';
      const cookieHeader = (value, age) =>
        `${cookieName}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${secure ? '; Secure' : ''}`;
      const cookie = (request.headers.cookie ?? '').split(';').map((part) => part.trim())
        .find((part) => part.startsWith(cookieName + '='))?.slice(cookieName.length + 1);
      const session = accessSessions.get(cookie);
      const signedIn = session?.origin === origin && session.expiresAt > Date.now();
      if (accounts || authenticationHash) {
        const sendAuth = async (status, registration = false, message = '', registrationLink = false) => {
          const nonce = randomBytes(16).toString('base64');
          response.setHeader('Referrer-Policy', 'same-origin');
          response.setHeader('Content-Security-Policy', `default-src 'none'; style-src 'nonce-${nonce}'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`);
          const title = registration ? 'Đăng ký tài khoản' : 'Đăng nhập';
          const confirmation = registration
            ? '<label for="password-confirmation">Nhập lại mật khẩu</label><input id="password-confirmation" name="confirmation" type="password" autocomplete="new-password" minlength="15" maxlength="256" required>'
            : '';
          const link = registration ? '<a href="/login">Về đăng nhập</a>'
            : registrationLink ? '<a href="/register">Đăng ký tài khoản</a>' : '';
          const html = (await readFile(path.join(WEB, 'login.html'), 'utf8'))
            .replace('__STYLE_NONCE__', nonce).replace('__LOGIN_CSRF__', loginCsrf)
            .replaceAll('__AUTH_TITLE__', title).replace('__AUTH_ACTION__', registration ? '/register' : '/login')
            .replace('__AUTH_DESCRIPTION__', registration
              ? 'Tạo tài khoản chủ cho ứng dụng. Mật khẩu cần ít nhất 15 ký tự.'
              : 'Nhập tài khoản để mở ứng dụng kiểm tra bảo mật.')
            .replace('__PASSWORD_AUTOCOMPLETE__', registration ? 'new-password' : 'current-password')
            .replace('__PASSWORD_MINLENGTH__', registration ? 'minlength="15"' : '')
            .replace('__AUTH_CONFIRMATION__', confirmation).replace('__AUTH_LINK__', link)
            .replace('__LOGIN_ERROR__', message);
          return send(status, html, 'text/html; charset=utf-8');
        };
        const canRegister = async () => accounts && directLocal && !(await accounts.hasOwner());
        const readAuthForm = async () => {
          if (request.headers.origin !== origin) throw new InputError(403, 'Nguồn đăng nhập không hợp lệ.');
          const form = await readLoginForm(request);
          if (form.get('csrf') !== loginCsrf) throw new InputError(403, 'Phiên đăng nhập đã đổi. Hãy tải lại trang.');
          return form;
        };
        const signIn = (identity) => {
          if (signedIn) accessSessions.delete(cookie);
          for (const [id, session] of accessSessions) if (session.expiresAt <= Date.now()) accessSessions.delete(id);
          if (accessSessions.size >= 100) accessSessions.delete(accessSessions.keys().next().value);
          const id = randomBytes(32).toString('hex');
          accessSessions.set(id, { origin, expiresAt: Date.now() + 8 * 60 * 60 * 1000, ...identity });
          return send(303, '', 'text/plain; charset=utf-8', { Location: '/', 'Set-Cookie': cookieHeader(id, 28800) });
        };
        if (route === '/register' && ['GET', 'POST'].includes(request.method)) {
          if (!accounts || !directLocal) throw new InputError(403, 'Đăng ký tài khoản chỉ thực hiện trực tiếp trên máy chạy ứng dụng.');
          if (await accounts.hasOwner()) return await sendAuth(409, false, 'Tài khoản chủ đã được tạo. Hãy đăng nhập.');
          if (request.method === 'GET') return await sendAuth(200, true);
          const form = await readAuthForm();
          const username = normalizeOwnerUsername(form.get('username'));
          const password = form.get('password');
          if (!validOwnerUsername(username) || !validOwnerPassword(password)) {
            return await sendAuth(400, true, 'Tên đăng nhập cần 3–64 ký tự gồm chữ, số, dấu chấm, gạch dưới hoặc gạch ngang. Mật khẩu cần ít nhất 15 ký tự và tối đa 256 byte.');
          }
          if (password !== form.get('confirmation')) return await sendAuth(400, true, 'Hai mật khẩu chưa khớp.');
          if (authenticationHash && username === normalizeOwnerUsername(publicAccess.username)) {
            return await sendAuth(400, true, 'Chọn tên khác với tài khoản ngrok đã cấu hình.');
          }
          const created = await runPasswordWork(() => accounts.register(username, password));
          if (!created) return await sendAuth(409, false, 'Tài khoản chủ đã được tạo. Hãy đăng nhập.');
          return signIn({ userId: OWNER_ID, username, role: 'admin' });
        }
        if (request.method === 'POST' && route === '/login') {
          const form = await readAuthForm();
          const bucket = secure ? 'public' : 'local';
          const now = Date.now();
          let attempts = loginAttempts.get(bucket);
          if (!attempts || attempts.until <= now) {
            attempts = { count: 0, until: now + 60_000 };
            loginAttempts.set(bucket, attempts);
          }
          if (attempts.count >= 10) return await sendAuth(429, false, 'Thử đăng nhập quá nhiều lần. Hãy thử lại sau một phút.');
          attempts.count++;
          const submitted = Buffer.from(`${form.get('username') ?? ''}:${form.get('password') ?? ''}`, 'utf8').toString('base64');
          const identity = matchesLegacy(submitted) ? legacyIdentity : accounts ? await runPasswordWork(() =>
            accounts.verify(normalizeOwnerUsername(form.get('username')), form.get('password'))) : null;
          if (!identity) return await sendAuth(401, false, 'Tên đăng nhập hoặc mật khẩu không đúng.', await canRegister());
          loginAttempts.delete(bucket);
          return signIn(identity);
        }
        const credentials = /^Basic ([A-Za-z0-9+/]+={0,2})$/i.exec(request.headers.authorization ?? '')?.[1] ?? '';
        const authorized = signedIn || matchesLegacy(credentials);
        if (authorized && request.method === 'GET' && route === '/login') {
          return send(303, '', 'text/plain; charset=utf-8', { Location: '/' });
        }
        if (!authorized) {
          if (request.method === 'GET' && (route === '/login' || (route === '/' && (homeNavigation || request.headers.accept?.includes('text/html'))))) {
            const registrationLink = await canRegister();
            return await sendAuth(200, !authenticationHash && route === '/' && registrationLink, '', registrationLink);
          }
          const headers = authenticationHash ? { 'WWW-Authenticate': 'Basic realm="SecurityScanner", charset="UTF-8"' } : {};
          return send(401, { error: 'Cần đăng nhập SecurityScanner.' }, 'application/json; charset=utf-8', headers);
        }
      }
      // Who is asking: always derived from the server-side session, never from request data.
      const identity = signedIn ? { userId: session.userId, username: session.username, role: session.role }
        : (accounts || authenticationHash) ? legacyIdentity : localIdentity;
      if (request.method === 'GET' && route === '/api/health') return send(200, { application: 'security-scanner-ui' });
      if (request.method === 'GET' && route === '/fflate-browser.js') {
        return send(200, await readFile(ZIP_MODULE), 'text/javascript; charset=utf-8');
      }
      if (request.method === 'GET' && ['/', '/app.js', '/style.css'].includes(route)) {
        const file = route === '/' ? 'index.html' : route.slice(1);
        const body = (await readFile(path.join(WEB, file), 'utf8'))
          .replace('__SESSION_TOKEN__', token).replace('__LOGOUT_VISIBILITY__', signedIn ? '' : 'hidden');
        return send(200, body, file.endsWith('.html') ? 'text/html; charset=utf-8' : file.endsWith('.js') ? 'text/javascript; charset=utf-8' : 'text/css; charset=utf-8');
      }
      if (route.startsWith('/api/') && request.headers['x-session-token'] !== token) throw new InputError(403, 'Phiên giao diện không hợp lệ. Hãy tải lại trang.');
      if (request.method === 'POST' && route === '/api/logout') {
        if (!signedIn || request.headers.origin !== origin) throw new InputError(403, 'Phiên đăng xuất không hợp lệ.');
        accessSessions.delete(cookie);
        return send(200, { signedOut: true }, 'application/json; charset=utf-8', { 'Set-Cookie': cookieHeader('', 0) });
      }
      if (request.method === 'GET' && route === '/api/bootstrap') return send(200, { uploadSchema: 1, sourceRules: SOURCE_RULES, sourceExtensions: SUPPORTED_SOURCE_EXTENSIONS, knowledge: KNOWLEDGE, corpus: corpusStats() });
      if (request.method === 'GET' && route === '/api/knowledge') {
        const query = url.searchParams.get('q') || '';
        const kind = url.searchParams.get('kind') || 'all';
        if (query.length > 300 || !['all', 'cwe', 'owasp', 'advisory', 'asvs', 'api', 'kev', 'curated'].includes(kind)) throw new InputError(400, 'Bộ lọc thư viện không hợp lệ.');
        if (kind === 'curated') {
          const results = KNOWLEDGE.filter((entry) => [entry.name, entry.id, ...entry.cwes].join(' ').toLowerCase().includes(query.toLowerCase()));
          return send(200, { results, total: results.length, page: 1, pages: results.length ? 1 : 0 });
        }
        return send(200, searchCorpus(query, { kind, page: url.searchParams.get('page') }));
      }
      if (request.method === 'GET' && route === '/api/me') {
        return send(200, { username: identity.username, role: identity.role, canManageUsers: Boolean(accounts) && identity.role === 'admin' });
      }
      if (route === '/api/users' || route.startsWith('/api/users/')) {
        if (!accounts || identity.role !== 'admin') throw new InputError(403, 'Chỉ tài khoản chủ được quản lý tài khoản.');
        if (request.method === 'GET' && route === '/api/users') return send(200, await accounts.listUsers());
        if (request.method === 'POST' && route === '/api/users') {
          const data = await readJson(request, 4096);
          const username = normalizeOwnerUsername(typeof data.username === 'string' ? data.username : '');
          if (!validOwnerUsername(username) || !validOwnerPassword(data.password)) {
            throw new InputError(400, 'Tên đăng nhập cần 3–64 ký tự gồm chữ, số, dấu chấm, gạch dưới hoặc gạch ngang. Mật khẩu cần ít nhất 15 ký tự và tối đa 256 byte.');
          }
          if (authenticationHash && username === normalizeOwnerUsername(publicAccess.username)) throw new InputError(409, 'Tên đăng nhập đã được dùng.');
          const created = await runPasswordWork(() => accounts.createUser(username, data.password));
          if (created === 'taken') throw new InputError(409, 'Tên đăng nhập đã được dùng.');
          if (created === 'full') throw new InputError(409, 'Đã đạt số tài khoản tối đa.');
          return send(201, created);
        }
        const matchDelete = route.match(/^\/api\/users\/([a-f0-9-]{36})\/delete$/);
        if (request.method === 'POST' && matchDelete) {
          const userId = matchDelete[1];
          if (!(await accounts.deleteUser(userId))) throw new InputError(404, 'Không tìm thấy tài khoản.');
          for (const [id, entry] of accessSessions) if (entry.userId === userId) accessSessions.delete(id);
          for (let i = queue.length - 1; i >= 0; i--) if (queue[i].job.ownerId === userId) queue.splice(i, 1);
          for (const [id, job] of jobs) if (job.ownerId === userId && job.status !== 'running') jobs.delete(id);
          await rm(userDir(userId), { recursive: true, force: true }).catch(() => {});
          return send(200, { deleted: true });
        }
        return send(404, { error: 'Không tìm thấy nội dung.' });
      }
      if (['/api/history', '/api/upload'].includes(route) || route.startsWith('/api/jobs/') || route.startsWith('/api/reports/')) await loaded;
      if (request.method === 'GET' && route === '/api/history') {
        return send(200, [...jobs.values()].filter((job) => job.ownerId === identity.userId)
          .sort((a, b) => b.startedAt.localeCompare(a.startedAt)).map(publicJob));
      }
      const matchJob = route.match(/^\/api\/jobs\/([a-f0-9-]{36})$/);
      if (request.method === 'GET' && matchJob) {
        const job = ownedJob(matchJob[1], identity);
        if (!job) throw new InputError(404, 'Không tìm thấy lần kiểm tra.');
        const report = job.status === 'done' ? await readJobReport(job) : undefined;
        if (job.status === 'done' && !report) throw new InputError(404, 'Không tìm thấy lần kiểm tra.');
        return send(200, { ...publicJob(job), ...(report ? { report } : {}) });
      }
      const matchFile = route.match(/^\/api\/reports\/([a-f0-9-]{36})\/(json|html|txt)$/);
      if (request.method === 'GET' && matchFile) {
        const job = ownedJob(matchFile[1], identity);
        const report = job?.status === 'done' ? await readJobReport(job) : undefined;
        if (!report) throw new InputError(404, 'Báo cáo chưa sẵn sàng.');
        const format = matchFile[2];
        const body = format === 'json' ? JSON.stringify(report, null, 2) : format === 'html' ? renderHtml(report) : renderText(report);
        return send(200, body, 'application/octet-stream', { 'Content-Disposition': `attachment; filename="security-report.${format}"` });
      }
      if (request.method === 'POST' && route === '/api/upload') {
        const data = await readJson(request, 30 * 1024 * 1024);
        return send(202, { id: startJob(data, identity) });
      }
      if (request.method === 'POST' && route === '/api/writeups') {
        const data = await readJson(request, 1024 * 1024 + 4096);
        if (typeof data.text !== 'string' || !data.text.trim() || Buffer.byteLength(data.text) > 1024 * 1024) throw new InputError(400, 'Nhập ghi chú/write-up từ 1 byte đến 1 MiB.');
        const temporary = await mkdtemp(path.join(tmpdir(), 'scanner-note-'));
        try {
          const input = path.join(temporary, 'notes.md');
          await writeFile(input, data.text, { mode: 0o600 });
          const imported = await importWriteup(input, knowledgeDir);
          return send(200, { topics: imported.topics, references: imported.references, id: imported.id });
        } finally { await rm(temporary, { force: true, recursive: true }); }
      }
      return send(404, { error: 'Không tìm thấy nội dung.' });
    } catch (error) {
      if (!response.headersSent) send(error instanceof InputError ? error.status : 500, { error: error instanceof InputError ? error.message : 'Không xử lý được yêu cầu. Kiểm tra quyền đọc/ghi rồi thử lại.' });
    }
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000;
  if (retentionMs) {
    void sweepReports();
    const sweeper = setInterval(() => void sweepReports(), Math.min(RETENTION_SWEEP_MS, retentionMs));
    sweeper.unref();
    server.on('close', () => clearInterval(sweeper));
  }
  server.sweepReports = sweepReports;
  return server;
}
