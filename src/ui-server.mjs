import http from 'node:http';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { readFile, readdir, writeFile, mkdir, mkdtemp, rm, rename, lstat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SOURCE_RULES, SUPPORTED_SOURCE_EXTENSIONS } from './source.mjs';
import { scanUpload, runScanWorker } from './scan-job.mjs';
import { renderHtml, renderText } from './report.mjs';
import { renderSarif } from './sarif.mjs';
import { KNOWLEDGE, importWriteup, WriteupLimitError } from './knowledge.mjs';
import { corpusStats, searchCorpus } from './corpus.mjs';
import { createAccountStore, normalizeOwnerUsername, OWNER_ID, validOwnerPassword, validOwnerUsername } from './owner-account.mjs';
import { isUserReportFolder, pruneReports, resolveRetentionMs } from './report-retention.mjs';
import { MAX_ZIP_BYTES, MIB } from './scan-scope.mjs';

const RETENTION_SWEEP_MS = 60 * 60 * 1000;
const MAX_JOBS_PER_USER = 20;
const MAX_QUEUE = 10;
const MAX_ARCHIVE_BASE64 = Math.ceil(MAX_ZIP_BYTES / 3) * 4;
const UPLOAD_BODY_BYTES = MAX_ARCHIVE_BASE64 + 16 * 1024;
const META_RESERVE = 8192;
const JOB_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

const WEB = fileURLToPath(new URL('../web/', import.meta.url));
const ZIP_MODULE = fileURLToPath(import.meta.resolve('fflate/browser'));
class InputError extends Error { constructor(status, message) { super(message); this.status = status; } }
const storageFull = 'Đã hết hạn mức lưu trữ của tài khoản. Xóa báo cáo cũ rồi thử lại.';

async function directories(directory) {
  try { return await readdir(directory, { withFileTypes: true }); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
}

async function atomicJobFile(directory, name, body) {
  const target = path.join(directory, name);
  const temporary = target + '.tmp';
  try {
    await writeFile(temporary, body, { mode: 0o600, flush: true });
    await rename(temporary, target);
  } finally {
    await rm(temporary, { force: true }).catch(() => {});
  }
}

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
    request.on('aborted', () => reject(new InputError(400, 'Yêu cầu đã bị ngắt.')));
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

export function createUiServer({
  rootDir, semgrepRunner, publicAccess, accountFile, localOwnerWorkspace = false, reportRetentionMs,
  accountStorageBytes = Number(process.env.SRCAUDIT_ACCOUNT_STORAGE_MIB ?? 128) * 1024 * 1024,
} = {}) {
  const retentionMs = reportRetentionMs ?? resolveRetentionMs();
  if (!Number.isSafeInteger(accountStorageBytes) || accountStorageBytes <= META_RESERVE) throw new Error('Hạn mức lưu trữ tài khoản không hợp lệ.');
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
  const localIdentity = { userId: localOwnerWorkspace ? OWNER_ID : 'local', username: 'local', role: 'user' };
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
  const uploads = new Map();
  const uploadRequests = new Set();
  const writeupImports = new Map();
  let activeJob;
  let activeWork;
  let closing = false;
  const knowledgeRoot = path.join(root, 'knowledge-local');
  const knowledgeDir = (ownerId) => ownerId === 'local' ? knowledgeRoot : path.join(knowledgeRoot, 'user-' + ownerId);
  const reportsDir = path.join(root, '.scanner-reports');
  const userDir = (ownerId) => path.join(reportsDir, `user-${ownerId}`);
  const jobDir = (job) => path.join(userDir(job.ownerId), job.id);
  const ownedJob = (id, identity) => {
    const job = jobs.get(id);
    // Someone else's scan is reported exactly like a missing one, so ids cannot be probed.
    return job && job.ownerId === identity.userId ? job : undefined;
  };
  function publicJob(job) {
    const { ownerId, label, ...view } = job;
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
    const { stage, label, ...meta } = job;
    await atomicJobFile(jobDir(job), 'meta.json', JSON.stringify(meta));
  }
  async function forgetJob(job) {
    await rm(jobDir(job), { recursive: true, force: true });
    jobs.delete(job.id);
  }
  async function trimHistory(ownerId) {
    const finished = [...jobs.values()].filter((job) => job.ownerId === ownerId && job.finishedAt)
      .sort((a, b) => a.startedAt.localeCompare(b.startedAt));
    for (const job of finished.slice(0, Math.max(0, finished.length - MAX_JOBS_PER_USER))) await forgetJob(job).catch(() => {});
  }
  const validStoredJob = (job, id, ownerId) => job?.id === id && job.ownerId === ownerId && Number.isFinite(Date.parse(job.startedAt));
  async function readPending(directory, id, ownerId) {
    const file = path.join(directory, 'input.json');
    const stat = await lstat(file);
    if (!stat.isFile() || stat.size > UPLOAD_BODY_BYTES) return undefined;
    const { job, content } = JSON.parse(await readFile(file, 'utf8'));
    if (validStoredJob(job, id, ownerId) && job.status === 'queued' && ['quick', 'deep'].includes(job.sourceAnalysis) &&
        typeof job.label === 'string' && job.label.length <= 160 && typeof content === 'string' && content.length <= MAX_ARCHIVE_BASE64) return job;
  }
  async function loadPersisted() {
    const restored = [];
    for (const folder of await directories(reportsDir)) {
      if (!folder.isDirectory() || !isUserReportFolder(folder.name)) continue;
      const ownerId = folder.name.slice(5);
      if (accounts && !(await isLiveAccount(ownerId))) continue;
      if (!accounts && ownerId !== (authenticationHash ? legacyIdentity.userId : localIdentity.userId)) continue;
      for (const entry of await directories(userDir(ownerId))) {
        if (!entry.isDirectory() || !JOB_ID.test(entry.name)) continue;
        const directory = path.join(userDir(ownerId), entry.name);
        try {
          const meta = JSON.parse(await readFile(path.join(directory, 'meta.json'), 'utf8'));
          if (validStoredJob(meta, entry.name, ownerId) && ['done', 'failed'].includes(meta.status)) {
            restored.push(meta);
            await rm(path.join(directory, 'input.json'), { force: true }).catch(() => {});
            continue;
          }
        } catch { /* A pending record may exist before the report metadata. */ }
        const pending = await readPending(directory, entry.name, ownerId).catch(() => undefined);
        if (pending) restored.push(pending);
      }
    }
    restored.sort((a, b) => a.startedAt.localeCompare(b.startedAt));
    for (const job of restored) {
      jobs.set(job.id, job);
      if (job.status === 'queued') queue.push(job);
    }
  }
  async function usedStorage(ownerId, exclude) {
    let bytes = 0;
    for (const entry of await directories(userDir(ownerId))) {
      if (!entry.isDirectory() || !JOB_ID.test(entry.name) || entry.name === exclude) continue;
      const directory = path.join(userDir(ownerId), entry.name);
      for (const file of await directories(directory)) {
        if (!file.isFile()) continue;
        const stat = await lstat(path.join(directory, file.name)).catch((error) => {
          if (error.code !== 'ENOENT') throw error;
        });
        if (stat?.isFile()) bytes += stat.size;
      }
    }
    return bytes;
  }
  const loaded = loadPersisted();
  void loaded.then(pump, () => {});
  // Drop finished jobs (in memory) and report folders (on disk) older than the retention period.
  async function sweepReports(now = Date.now()) {
    if (!retentionMs) return;
    await loaded;
    for (const [id, job] of jobs) {
      if (job.finishedAt && now - Date.parse(job.finishedAt) > retentionMs) jobs.delete(id);
    }
    const excluded = new Set([...jobs.values()].filter(({ status }) => status === 'queued' || status === 'running').map(jobDir));
    try { await pruneReports(reportsDir, { maxAgeMs: retentionMs, now, excluded }); } catch { /* retried on next sweep */ }
  }
  function pump() {
    if (closing || activeWork || !queue.length) return;
    const job = queue.shift();
    activeJob = job;
    activeWork = runJob(job).catch(() => {
      job.status = 'failed';
      job.error = 'Không thể lưu trạng thái lượt quét. Kiểm tra dung lượng và quyền ghi.';
      job.finishedAt = new Date().toISOString();
      delete job.stage;
    }).finally(() => { activeJob = undefined; activeWork = undefined; pump(); });
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
    if (content.length > MAX_ARCHIVE_BASE64) throw new InputError(413, `Tệp ZIP vượt giới hạn ${MAX_ZIP_BYTES / MIB} MiB.`);
    if ([...jobs.values()].some((job) => job.ownerId === identity.userId && ['queued', 'running'].includes(job.status))) {
      throw new InputError(409, 'Một lần kiểm tra đang chạy. Hãy chờ kết quả trước khi bắt đầu lần khác.');
    }
    if (queue.length + uploads.size >= MAX_QUEUE) throw new InputError(503, 'Hàng đợi kiểm tra đang đầy. Hãy thử lại sau ít phút.');
    const cleanLabel = typeof label === 'string' ? label.split(/[/\\]/).at(-1).replace(/[\x00-\x1f]/g, '').slice(0, 160) : '';
    const job = { id: randomUUID(), ownerId: identity.userId, mode: 'upload', sourceAnalysis, status: 'queued', startedAt: new Date().toISOString(), label: cleanLabel || 'source.zip' };
    jobs.set(job.id, job);
    const work = enqueue(job, content).finally(() => uploads.delete(job.ownerId));
    uploads.set(job.ownerId, work);
    return work;
  }
  async function enqueue(job, content) {
    try {
      const body = JSON.stringify({ job, content });
      if (await usedStorage(job.ownerId) + Buffer.byteLength(body) + META_RESERVE > accountStorageBytes) throw new InputError(413, storageFull);
      if (accounts && !(await isLiveAccount(job.ownerId))) throw new InputError(401, 'Tài khoản không còn hoạt động.');
      await mkdir(jobDir(job), { recursive: true, mode: 0o700 });
      await atomicJobFile(jobDir(job), 'input.json', body);
      queue.push(job);
      pump();
      return job.id;
    } catch (error) {
      jobs.delete(job.id);
      await forgetJob(job).catch(() => {});
      throw error;
    }
  }
  async function runJob(job) {
    job.status = 'running'; job.stage = 'Đang kiểm tra tệp ZIP…';
    const directory = jobDir(job);
    const inputFile = path.join(directory, 'input.json');
    const input = await lstat(inputFile);
    const maxReportBytes = accountStorageBytes - await usedStorage(job.ownerId, job.id) - input.size - META_RESERVE;
    // Semgrep on Windows needs a short path for its own temporary configuration.
    const engineWorkspace = job.sourceAnalysis === 'deep'
      ? path.join(tmpdir(), 'sg-' + Buffer.from(job.id.replaceAll('-', ''), 'hex').toString('base64url'))
      : undefined;
    const cleanEngine = () => engineWorkspace
      ? rm(engineWorkspace, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 }) : undefined;
    const options = { directory, engineWorkspace, knowledgeDir: knowledgeDir(job.ownerId), maxReportBytes };
    const onStage = (stage) => { job.stage = stage; };
    await cleanEngine();
    const result = maxReportBytes <= 0 ? { error: storageFull } : semgrepRunner
      ? await scanUpload(options, onStage, semgrepRunner) : await runScanWorker(options, onStage);
    await cleanEngine();
    if (accounts && !(await isLiveAccount(job.ownerId))) {
      await forgetJob(job);
      return;
    }
    await rm(path.join(directory, 'work'), { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
    if (result.error) {
      for (const name of ['report.json', 'report.sarif', 'report.html', 'report.txt']) await rm(path.join(directory, name), { force: true });
    }
    const completed = { ...job, ...result, status: result.error ? 'failed' : 'done', finishedAt: new Date().toISOString() };
    await persistMeta(completed);
    await rm(inputFile, { force: true });
    Object.assign(job, completed);
    delete job.stage;
    await trimHistory(job.ownerId);
  }
  async function isLiveAccount(ownerId) {
    if (ownerId === 'legacy' || ownerId === 'local') return true;
    return accounts.exists(ownerId);
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
      if (!accounts && !authenticationHash && !directLocal) {
        throw new InputError(403, 'Chế độ cục bộ chỉ nhận kết nối trực tiếp từ máy này.');
      }
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
      if (request.method === 'GET' && route === '/scan-scope.js') {
        return send(200, await readFile(new URL('./scan-scope.mjs', import.meta.url)), 'text/javascript; charset=utf-8');
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
        if (query.length > 300 || !['all', 'cwe', 'owasp', 'advisory', 'asvs', 'api', 'kev', 'curated', 'research', 'reference'].includes(kind)) throw new InputError(400, 'Bộ lọc thư viện không hợp lệ.');
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
          await Promise.allSettled([uploads.get(userId), writeupImports.get(userId)]);
          for (let i = queue.length - 1; i >= 0; i--) if (queue[i].ownerId === userId) queue.splice(i, 1);
          if (activeJob?.ownerId === userId) await activeWork;
          for (const [id, job] of jobs) if (job.ownerId === userId && job.status !== 'running') jobs.delete(id);
          await rm(userDir(userId), { recursive: true, force: true }).catch(() => {});
          await rm(knowledgeDir(userId), { recursive: true, force: true }).catch(() => {});
          return send(200, { deleted: true });
        }
        return send(404, { error: 'Không tìm thấy nội dung.' });
      }
      if (['/api/history', '/api/upload'].includes(route) || route.startsWith('/api/jobs/') || route.startsWith('/api/reports/')) await loaded;
      if (request.method === 'GET' && route === '/api/history') {
        return send(200, [...jobs.values()].filter((job) => job.ownerId === identity.userId)
          .sort((a, b) => b.startedAt.localeCompare(a.startedAt)).map(publicJob));
      }
      const deleteJob = route.match(/^\/api\/jobs\/([a-f0-9-]{36})\/delete$/);
      if (request.method === 'POST' && deleteJob) {
        const job = ownedJob(deleteJob[1], identity);
        if (!job) throw new InputError(404, 'Không tìm thấy lần kiểm tra.');
        if (!job.finishedAt) throw new InputError(409, 'Chờ lượt quét kết thúc trước khi xóa.');
        await forgetJob(job);
        return send(200, { deleted: true });
      }
      const matchJob = route.match(/^\/api\/jobs\/([a-f0-9-]{36})$/);
      if (request.method === 'GET' && matchJob) {
        const job = ownedJob(matchJob[1], identity);
        if (!job) throw new InputError(404, 'Không tìm thấy lần kiểm tra.');
        const report = job.status === 'done' ? await readJobReport(job) : undefined;
        if (job.status === 'done' && !report) throw new InputError(404, 'Không tìm thấy lần kiểm tra.');
        return send(200, { ...publicJob(job), ...(report ? { report } : {}) });
      }
      const matchFile = route.match(/^\/api\/reports\/([a-f0-9-]{36})\/(json|html|txt|sarif)$/);
      if (request.method === 'GET' && matchFile) {
        const job = ownedJob(matchFile[1], identity);
        const report = job?.status === 'done' ? await readJobReport(job) : undefined;
        if (!report) throw new InputError(404, 'Báo cáo chưa sẵn sàng.');
        const format = matchFile[2];
        const body = format === 'json' ? JSON.stringify(report, null, 2) : format === 'sarif' ? JSON.stringify(renderSarif(report), null, 2) : format === 'html' ? renderHtml(report) : renderText(report);
        return send(200, body, 'application/octet-stream', { 'Content-Disposition': `attachment; filename="security-report.${format}"` });
      }
      if (request.method === 'POST' && route === '/api/upload') {
        if (uploadRequests.has(identity.userId)) throw new InputError(409, 'Một tệp ZIP của tài khoản đang được nhận.');
        if (uploadRequests.size >= 4) throw new InputError(503, 'Đang nhận nhiều tệp ZIP. Hãy thử lại sau.');
        uploadRequests.add(identity.userId);
        try {
          const data = await readJson(request, UPLOAD_BODY_BYTES);
          return send(202, { id: await startJob(data, identity) });
        } finally { uploadRequests.delete(identity.userId); }
      }
      if (request.method === 'POST' && route === '/api/writeups') {
        const data = await readJson(request, 1024 * 1024 + 4096);
        if (typeof data.text !== 'string' || !data.text.trim() || Buffer.byteLength(data.text) > 1024 * 1024) throw new InputError(400, 'Nhập ghi chú/write-up từ 1 byte đến 1 MiB.');
        if (writeupImports.has(identity.userId)) throw new InputError(409, 'Đang nhập một write-up khác.');
        const work = (async () => {
          if (accounts && !(await isLiveAccount(identity.userId))) throw new InputError(401, 'Tài khoản không còn hoạt động.');
          const temporary = await mkdtemp(path.join(tmpdir(), 'scanner-note-'));
          try {
            const input = path.join(temporary, 'notes.md');
            await writeFile(input, data.text, { mode: 0o600 });
            return await importWriteup(input, knowledgeDir(identity.userId), { maxEntries: 100 });
          } finally { await rm(temporary, { force: true, recursive: true }); }
        })();
        writeupImports.set(identity.userId, work);
        try {
          const imported = await work;
          return send(200, { topics: imported.topics, references: imported.references, id: imported.id });
        } catch (error) {
          if (error instanceof WriteupLimitError) throw new InputError(413, error.message);
          throw error;
        } finally { writeupImports.delete(identity.userId); }
      }
      return send(404, { error: 'Không tìm thấy nội dung.' });
    } catch (error) {
      if (!response.headersSent) send(error instanceof InputError ? error.status : 500, { error: error instanceof InputError ? error.message : 'Không xử lý được yêu cầu. Kiểm tra quyền đọc/ghi rồi thử lại.' });
    }
  });
  server.requestTimeout = 15000; server.headersTimeout = 10000;
  server.on('close', () => { closing = true; });
  if (retentionMs) {
    const sweep = () => { void sweepReports().catch(() => {}); };
    sweep();
    const sweeper = setInterval(sweep, Math.min(RETENTION_SWEEP_MS, retentionMs));
    sweeper.unref();
    server.on('close', () => clearInterval(sweeper));
  }
  server.sweepReports = sweepReports;
  return server;
}
