import { Unzip, UnzipInflate } from 'fflate';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { isSupportedSourceFile } from './source.mjs';
import { isTestPath, MAX_SOURCE_FILE_BYTES, MAX_SOURCE_FILES, MAX_SOURCE_TOTAL_BYTES, MAX_ZIP_BYTES } from './scan-scope.mjs';

const SKIP = new Set(['node_modules', '.git', '.venv', 'venv', 'vendor', 'dist', 'build', 'coverage', '.next', '__pycache__']);
export class ZipInputError extends Error {}

function cleanPath(input) {
  if (typeof input !== 'string' || !input || input.length > 512 || /[\x00-\x1f:]/.test(input)) throw new ZipInputError('Invalid upload file name.');
  const name = input.replaceAll('\\', '/');
  const pieces = name.split('/');
  if (name.startsWith('/') || pieces.some((piece) => !piece || piece === '.' || piece === '..' || /[. ]$/.test(piece) || /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(piece))) throw new ZipInputError('The upload path is out of range or invalid.');
  return name;
}
function decode(value, maxBytes) {
  if (typeof value !== 'string' || value.length > Math.ceil(maxBytes / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length % 4) throw new ZipInputError('The upload data is invalid or too large.');
  const buffer = Buffer.from(value, 'base64');
  if (buffer.length > maxBytes) throw new ZipInputError('Upload exceeds the size limit.');
  return buffer;
}

export async function prepareZipUpload(content, limits = {}) {
  const maxFileBytes = limits.maxFileBytes ?? MAX_SOURCE_FILE_BYTES;
  const maxTotalBytes = limits.maxTotalBytes ?? MAX_SOURCE_TOTAL_BYTES;
  const maxFiles = limits.maxFiles ?? MAX_SOURCE_FILES;
  const files = new Map(); const warnings = []; let total = 0;
  const accept = (name) => !isTestPath(name) && !name.split('/').some((piece) => SKIP.has(piece)) && isSupportedSourceFile(name);
  function add(name, buffer) {
    const key = name.toLowerCase();
    if (files.has(key)) throw new ZipInputError('File upload trùng tên.');
    if (files.size >= maxFiles || total + buffer.length > maxTotalBytes) throw new ZipInputError('Upload exceeds the file count or total size limit.');
    total += buffer.length; files.set(key, { name, buffer });
  }
  const archive = decode(content, MAX_ZIP_BYTES);
  if (archive.length < 22 || archive.readUInt32LE(0) !== 0x04034b50) throw new ZipInputError('Invalid ZIP file.');
  let eocd = -1;
  for (let offset = archive.length - 22; offset >= Math.max(0, archive.length - 65557); offset--) {
    if (archive.readUInt32LE(offset) === 0x06054b50 && offset + 22 + archive.readUInt16LE(offset + 20) === archive.length) { eocd = offset; break; }
  }
  if (eocd < 0 || archive.readUInt16LE(eocd + 4) || archive.readUInt16LE(eocd + 6) || archive.readUInt16LE(eocd + 10) > 10000) throw new ZipInputError('The ZIP is incomplete, split across files or contains too many entries.');
  let openFiles = 0;
  const unzip = new Unzip((entry) => {
    if (entry.name.endsWith('/')) { cleanPath(entry.name.slice(0, -1)); return; }
    const name = cleanPath(entry.name);
    if (!accept(name)) return;
    if (entry.originalSize !== undefined && entry.originalSize > maxFileBytes) { warnings.push(`File exceeds the ${maxFileBytes}-byte limit: ${name}`); return; }
    openFiles++; const chunks = []; let size = 0;
    entry.ondata = (error, chunk, final) => {
      if (error) throw new ZipInputError('Could not extract a file from the ZIP archive.');
      size += chunk.length;
      if (size > maxFileBytes || total + size > maxTotalBytes) { entry.terminate(); throw new ZipInputError('Extracted files exceed the size limit.'); }
      chunks.push(Buffer.from(chunk));
      if (final) { add(name, Buffer.concat(chunks)); openFiles--; }
    };
    entry.start();
  });
  unzip.register(UnzipInflate);
  // Small compressed chunks prevent a large expansion before the output check.
  for (let offset = 0; offset < archive.length; offset += 1024) unzip.push(archive.subarray(offset, offset + 1024), offset + 1024 >= archive.length);
  if (openFiles) throw new ZipInputError('The ZIP archive contains incomplete file entries.');
  if (!files.size) throw new ZipInputError('The upload contains no supported source files.');
  const rootDir = await mkdtemp(path.join(limits.temporaryDirectory ?? tmpdir(), 'scanner-source-'));
  try {
    for (const { name, buffer } of files.values()) {
      const destination = path.resolve(rootDir, ...name.split('/'));
      const relative = path.relative(rootDir, destination);
      if (relative.startsWith('..') || path.isAbsolute(relative)) throw new ZipInputError('The archive contains a path outside the upload directory.');
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, buffer, { mode: 0o600, flag: 'wx' });
    }
    return { rootDir, files: files.size, bytes: total, warnings };
  } catch (error) { await rm(rootDir, { recursive: true, force: true }); throw error; }
}
