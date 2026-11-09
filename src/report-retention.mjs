import { lstat, readdir, rm } from 'node:fs/promises';
import path from 'node:path';

const DAY_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_RETENTION_DAYS = 7;
export const MAX_RETENTION_DAYS = 365;

// Only directories created by SrcAudit itself are eligible for deletion:
// UI jobs use a UUID, CLI default runs use an ISO timestamp with ':' and '.' replaced.
const MANAGED_NAME = /^(?:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}|\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)$/;

// Per-account folders: user-owner, user-local, user-legacy or user-<uuid>.
const USER_FOLDER = /^user-(?:owner|local|legacy|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/;

export function isManagedReportName(name) {
  return MANAGED_NAME.test(name);
}

export function isUserReportFolder(name) {
  return USER_FOLDER.test(name);
}

/**
 * Resolve the retention period in milliseconds.
 * `SRCAUDIT_REPORT_RETENTION_DAYS=0` disables automatic deletion.
 */
export function resolveRetentionMs(value = process.env.SRCAUDIT_REPORT_RETENTION_DAYS) {
  if (value === undefined || value === '') return DEFAULT_RETENTION_DAYS * DAY_MS;
  const days = Number(value);
  if (!Number.isFinite(days) || days < 0 || days > MAX_RETENTION_DAYS) {
    throw new Error(`SRCAUDIT_REPORT_RETENTION_DAYS phải là số từ 0 đến ${MAX_RETENTION_DAYS}.`);
  }
  return days * DAY_MS;
}

/**
 * Delete report directories under `reportsDir` (and one level inside each `user-*` folder)
 * older than `maxAgeMs`.
 * Symlinks, files and directories with names SrcAudit did not create are left untouched.
 * Returns the names of removed directories.
 */
export async function pruneReports(reportsDir, { maxAgeMs, now = Date.now() } = {}) {
  if (!maxAgeMs || maxAgeMs <= 0) return [];
  let entries;
  try { entries = await readdir(reportsDir, { withFileTypes: true }); }
  catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  const removed = [];
  for (const entry of entries) {
    if (entry.isDirectory() && isUserReportFolder(entry.name)) {
      const nested = await pruneReports(path.join(reportsDir, entry.name), { maxAgeMs, now });
      removed.push(...nested.map((name) => `${entry.name}/${name}`));
      continue;
    }
    if (!entry.isDirectory() || !isManagedReportName(entry.name)) continue;
    const target = path.join(reportsDir, entry.name);
    try {
      const info = await lstat(target);
      if (!info.isDirectory() || now - info.mtimeMs <= maxAgeMs) continue;
      await rm(target, { recursive: true, force: true });
      removed.push(entry.name);
    } catch {
      // A report that cannot be inspected or removed is retried on the next sweep.
    }
  }
  return removed;
}
