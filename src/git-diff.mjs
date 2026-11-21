import { execFile } from 'node:child_process';
import { lstat } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);
// Refs are passed to git as arguments, never through a shell; still reject option-like
// values and characters git does not allow in ref names (git-check-ref-format).
const REF = /^(?!-)[A-Za-z0-9_][A-Za-z0-9_./@^~{}+-]{0,199}$/;

export const pathKey = (absolute) => {
  const resolved = path.resolve(absolute);
  return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
};

export class DiffError extends Error {}

async function git(cwd, args) {
  try {
    const { stdout } = await run('git', args, { cwd, timeout: 30_000, maxBuffer: 32 * 1024 * 1024, windowsHide: true, encoding: 'utf8' });
    return stdout;
  } catch (error) {
    if (error?.code === 'ENOENT') throw new DiffError('Không tìm thấy git trên PATH; --diff cần git.');
    throw new DiffError('git không xử lý được --diff. Kiểm tra mục tiêu nằm trong repo git và ref tồn tại (CI cần fetch đủ lịch sử, ví dụ fetch-depth: 0).');
  }
}

/**
 * Files added, copied, modified or renamed since the merge base of `ref` and HEAD,
 * including uncommitted and untracked (non-ignored) files. Returns absolute path keys.
 */
export async function changedFiles(target, ref) {
  if (typeof ref !== 'string' || !REF.test(ref) || ref.includes('..') || ref.endsWith('.lock')) throw new DiffError('--diff nhận một tên nhánh, tag hoặc commit hợp lệ, ví dụ origin/main.');
  const resolved = path.resolve(target);
  const cwd = (await lstat(resolved)).isDirectory() ? resolved : path.dirname(resolved);
  const top = (await git(cwd, ['rev-parse', '--show-toplevel'])).trim();
  const base = (await git(cwd, ['merge-base', '--end-of-options', ref, 'HEAD'])).trim();
  if (!/^[0-9a-f]{40,64}$/.test(base)) throw new DiffError('Không xác định được merge-base cho --diff.');
  const tracked = await git(top, ['diff', '--name-only', '-z', '--no-renames', '--diff-filter=ACMRT', base, '--']);
  const untracked = await git(top, ['ls-files', '--others', '--exclude-standard', '--full-name', '-z']);
  const files = new Set();
  for (const name of [...tracked.split('\0'), ...untracked.split('\0')]) if (name) files.add(pathKey(path.join(top, name)));
  return { base, files };
}
