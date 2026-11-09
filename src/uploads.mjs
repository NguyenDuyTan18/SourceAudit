import { Unzip, UnzipInflate } from 'fflate';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { isSupportedSourceFile } from './source.mjs';

const SKIP = new Set(['node_modules', '.git', '.venv', 'venv', 'vendor', 'dist', 'build', 'coverage', '.next', '__pycache__']);
export class ZipInputError extends Error {}

function cleanPath(input) {
  if (typeof input !== 'string' || !input || input.length > 512 || /[\x00-\x1f:]/.test(input)) throw new ZipInputError('Tên file upload không hợp lệ.');
  const name = input.replaceAll('\\', '/');
  const pieces = name.split('/');
  if (name.startsWith('/') || pieces.some((piece) => !piece || piece === '.' || piece === '..' || /[. ]$/.test(piece) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(piece))) throw new ZipInputError('Đường dẫn upload vượt phạm vi hoặc không hợp lệ.');
  return name;
}
function decode(value, maxBytes) {
  if (typeof value !== 'string' || value.length > Math.ceil(maxBytes / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4) throw new ZipInputError('Dữ liệu upload không hợp lệ hoặc quá lớn.');
  const buffer = Buffer.from(value, 'base64');
  if (buffer.length > maxBytes) throw new ZipInputError('Upload vượt giới hạn dung lượng.');
  return buffer;
}

export async function prepareZipUpload(content, limits = {}) {
  const maxFileBytes = limits.maxFileBytes ?? 1024 * 1024;
  const maxTotalBytes = limits.maxTotalBytes ?? 20 * 1024 * 1024;
  const maxFiles = limits.maxFiles ?? 2000;
  const files = new Map(); const warnings = []; let total = 0;
  const accept = (name) => !name.split('/').some((piece) => SKIP.has(piece)) && isSupportedSourceFile(name);
  function add(name, buffer) {
    const key = name.toLowerCase();
    if (files.has(key)) throw new ZipInputError('File upload trùng tên.');
    if (files.size >= maxFiles || total + buffer.length > maxTotalBytes) throw new ZipInputError('Upload vượt giới hạn file hoặc tổng dung lượng.');
    total += buffer.length; files.set(key, { name, buffer });
  }
  const archive = decode(content, 20 * 1024 * 1024);
  if (archive.length < 22 || archive.readUInt32LE(0) !== 0x04034b50) throw new ZipInputError('File ZIP không hợp lệ.');
  let eocd = -1;
  for (let offset = archive.length - 22; offset >= Math.max(0, archive.length - 65557); offset--) {
    if (archive.readUInt32LE(offset) === 0x06054b50 && offset + 22 + archive.readUInt16LE(offset + 20) === archive.length) { eocd = offset; break; }
  }
  if (eocd < 0 || archive.readUInt16LE(eocd + 4) || archive.readUInt16LE(eocd + 6) || archive.readUInt16LE(eocd + 10) > 10000) throw new ZipInputError('ZIP thiếu dữ liệu, ZIP nhiều phần hoặc quá nhiều file.');
  let openFiles = 0;
  const unzip = new Unzip((entry) => {
    if (entry.name.endsWith('/')) { cleanPath(entry.name.slice(0, -1)); return; }
    const name = cleanPath(entry.name);
    if (!accept(name)) return;
    if (entry.originalSize !== undefined && entry.originalSize > maxFileBytes) { warnings.push(`File upload vượt giới hạn ${maxFileBytes} byte: ${name}`); return; }
    openFiles++; const chunks = []; let size = 0;
    entry.ondata = (error, chunk, final) => {
      if (error) throw new ZipInputError('Không giải nén được file trong ZIP.');
      size += chunk.length;
      if (size > maxFileBytes || total + size > maxTotalBytes) { entry.terminate(); throw new ZipInputError('ZIP giải nén vượt giới hạn dung lượng.'); }
      chunks.push(Buffer.from(chunk));
      if (final) { add(name, Buffer.concat(chunks)); openFiles--; }
    };
    entry.start();
  });
  unzip.register(UnzipInflate);
  // Small compressed chunks prevent a large expansion before the output check.
  for (let offset = 0; offset < archive.length; offset += 1024) unzip.push(archive.subarray(offset, offset + 1024), offset + 1024 >= archive.length);
  if (openFiles) throw new ZipInputError('ZIP có file chưa giải nén hoàn tất.');
  if (!files.size) throw new ZipInputError('Không có file source được hỗ trợ trong upload.');
  const rootDir = await mkdtemp(path.join(tmpdir(), 'scanner-source-'));
  try {
    for (const { name, buffer } of files.values()) {
      const destination = path.resolve(rootDir, ...name.split('/'));
      const relative = path.relative(rootDir, destination);
      if (relative.startsWith('..') || path.isAbsolute(relative)) throw new ZipInputError('Đường dẫn vượt thư mục upload.');
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, buffer, { mode: 0o600, flag: 'wx' });
    }
    return { rootDir, files: files.size, bytes: total, warnings };
  } catch (error) { await rm(rootDir, { recursive: true, force: true }); throw error; }
}
