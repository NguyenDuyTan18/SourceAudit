import { existsSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./python-precision.py', import.meta.url));
const reviewedRules = new Set([
  'srcaudit-python-lxml-xpath-injection', 'srcaudit-python-request-file-path',
  'srcaudit-python-request-dynamic-code', 'srcaudit-python-flask-open-redirect',
  'srcaudit-python-flask-html-response', 'srcaudit-python-sax-external-entities',
  'srcaudit-python-ldap-injection', 'srcaudit-python-weak-hashlib',
]);
const reasons = new Set(['python-constant', 'python-resolved-root', 'python-xpath-delimiter', 'python-https-allowlist', 'python-hmac-digest-factory']);

function substitute(text, replacements) {
  const lines = text.split('\n');
  const ordered = [...replacements].sort(([lineA, startA], [lineB, startB]) => lineB - lineA || startB - startA);
  let lastLine = 0;
  let lastStart = 0;
  for (const [line, start, end, literal] of ordered) {
    if (![line, start, end].every(Number.isSafeInteger) || line < 1 || line > lines.length ||
        start < 0 || end <= start || (line === lastLine && end > lastStart) ||
        typeof literal !== 'string' || !/^[\x20-\x7e]{1,4100}$/.test(literal)) return undefined;
    const original = Buffer.from(lines[line - 1]);
    if (end > original.length || !/^[A-Za-z_]\w*$/.test(original.subarray(start, end).toString())) return undefined;
    lines[line - 1] = Buffer.concat([original.subarray(0, start), Buffer.from(literal), original.subarray(end)]).toString();
    lastLine = line;
    lastStart = start;
  }
  return lines.join('\n');
}

async function recheckPaths(proposals, findings, staged, pythonFiles, { executable, workspace, env, args, run }) {
  if (!proposals.length) return undefined;
  const directory = path.join(workspace, 'python-review');
  await mkdir(directory);
  const copies = new Map();
  let bytes = 0;
  for (const [index, replacements] of proposals.slice(0, 64)) {
    const finding = findings[index];
    if (finding.ruleId !== 'srcaudit-python-request-file-path' ||
        !replacements.every((part) => Array.isArray(part) && part.length === 4)) continue;
    const source = staged.get(pythonFiles.get(finding.location.file));
    const text = substitute(source.text, replacements);
    if (text === undefined || bytes + Buffer.byteLength(text) > 12 * 1024 * 1024) continue;
    const target = path.join(directory, index + '.py');
    await writeFile(target, text, { mode: 0o600, flag: 'wx' });
    copies.set(target, index);
    bytes += Buffer.byteLength(text);
  }
  if (!copies.size) return undefined;
  const { stdout } = await run(executable, [...args.slice(0, -1), 'python-review'], {
    cwd: workspace, env, timeout: 25_000, maxBuffer: 4 * 1024 * 1024, windowsHide: true,
  });
  const output = JSON.parse(stdout);
  if (!Array.isArray(output?.errors) || output.errors.length ||
      !Array.isArray(output.results) || !Array.isArray(output.paths?.scanned)) return undefined;
  const pathWarnings = new Map();
  for (const { path: file, check_id: ruleId, start } of output.results) {
    if (typeof file !== 'string' || ruleId !== 'srcaudit-python-request-file-path') continue;
    const target = path.resolve(workspace, file);
    if (!pathWarnings.has(target)) pathWarnings.set(target, new Set());
    pathWarnings.get(target).add(start?.line);
  }
  const verified = new Map();
  const scanned = new Set();
  for (const file of output.paths.scanned) {
    if (typeof file !== 'string') continue;
    const target = path.resolve(workspace, file);
    const index = copies.get(target);
    if (index === undefined) continue;
    scanned.add(target);
    if (!pathWarnings.get(target)?.has(findings[index].location.line)) {
      verified.set(index, 'python-constant-path-recheck');
    }
  }
  if (scanned.size) return { verified, status: scanned.size === proposals.length ? 'complete' : 'partial' };
}

export async function reviewPythonFindings(result, staged, settings) {
  const { executable, workspace, env, run } = settings;
  const pythonFiles = new Map([...staged].filter(([, entry]) => entry.language === 'Python')
    .map(([temporary, entry]) => [entry.file, temporary]));
  const byFile = Object.create(null);
  const eligible = new Set();
  for (const [index, { ruleId, location }] of result.findings.entries()) {
    const temporary = pythonFiles.get(location.file);
    if (!temporary || !reviewedRules.has(ruleId)) continue;
    (byFile[temporary] ??= []).push([index, location.line, location.column, ruleId]);
    eligible.add(index);
  }
  if (!eligible.size) return result;
  const sibling = path.isAbsolute(executable)
    ? path.join(path.dirname(executable), process.platform === 'win32' ? 'python.exe' : 'python3') : undefined;
  const local = sibling && existsSync(sibling);
  const windows = process.platform === 'win32';
  const python = local ? sibling : windows ? 'py.exe' : 'python3';
  const launcher = !local && windows ? ['-3'] : [];
  const input = path.join(workspace, 'python-precision.json');
  try {
    await writeFile(input, JSON.stringify(byFile), { mode: 0o600, flag: 'wx' });
    const { stdout } = await run(python, [...launcher, '-I', '-S', '-B', script, input], {
      cwd: workspace, env, timeout: 12_000, maxBuffer: 512 * 1024, windowsHide: true,
    });
    const decisions = new Map();
    const proposals = [];
    for (const [index, result] of JSON.parse(stdout)) {
      if (!eligible.has(index)) throw new Error('Invalid Python review index');
      if (reasons.has(result)) decisions.set(index, result);
      else if (Array.isArray(result) && result.length) proposals.push([index, result]);
      else throw new Error('Invalid Python review output');
    }
    let recheck;
    try {
      recheck = await recheckPaths(proposals, result.findings, staged, pythonFiles, settings);
      if (recheck) for (const [index, reason] of recheck.verified) decisions.set(index, reason);
    } catch { /* Keep every candidate when the second Semgrep pass fails. */ }
    const counts = Object.create(null);
    for (const reason of decisions.values()) counts[reason] = (counts[reason] ?? 0) + 1;
    result.pythonPrecision = { status: 'complete', filtered: decisions.size, reasons: counts,
      ...(proposals.length ? { pathRecheck: recheck?.status ?? 'unavailable' } : {}) };
    result.findings = result.findings.filter((_, index) => !decisions.has(index));
  } catch {
    result.pythonPrecision = { status: 'unavailable', filtered: 0 };
  }
  return result;
}
