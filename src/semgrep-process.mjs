import { execFile } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';

const execute = promisify(execFile);

async function executeWindows(executable, args, { timeout, ...options }) {
  const execution = execute(executable, args, options);
  const { child } = execution;
  let termination;
  const timer = setTimeout(() => {
    if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
    // A Python launcher and the Semgrep core can outlive the original process.
    const taskkill = path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'taskkill.exe');
    termination = execute(taskkill, ['/PID', String(child.pid), '/T', '/F'], { windowsHide: true, timeout: 5000 })
      .catch(() => { child.kill(); });
  }, timeout);
  try {
    const result = await execution;
    if (!termination) return result;
  } catch (error) {
    if (!termination) throw error;
  } finally {
    clearTimeout(timer);
  }
  await termination;
  throw Object.assign(new Error('Semgrep subprocess timed out.'), { killed: true });
}

export const runSemgrepProcess = process.platform === 'win32' ? executeWindows : execute;
