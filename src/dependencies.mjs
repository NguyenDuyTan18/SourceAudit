import semver from 'semver';
import * as pep440 from '@renovatebot/pep440';
import { CORPUS, knownExploited } from './corpus.mjs';

const normalize = (ecosystem, name) => ecosystem === 'pip' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name.toLowerCase();
const advisoryIndex = new Map();
for (const advisory of CORPUS.advisories) for (const vulnerability of advisory.vulnerabilities) {
  const key = vulnerability.ecosystem + ':' + normalize(vulnerability.ecosystem, vulnerability.name);
  if (!advisoryIndex.has(key)) advisoryIndex.set(key, []);
  advisoryIndex.get(key).push({ advisory, vulnerability });
}

const requirements = /^requirements(?:[.-].*)?\.txt$/i;
const manifestNames = new Set([
  'package-lock.json', 'npm-shrinkwrap.json', 'package.json', 'yarn.lock', 'pnpm-lock.yaml',
  'Pipfile.lock', 'composer.lock', 'Gemfile.lock', 'go.mod', 'pom.xml', 'packages.lock.json', 'poetry.lock',
]);
export const isDependencyManifest = (filename) => manifestNames.has(filename) || requirements.test(filename);

function composerStable(version) {
  if (!/^v?\d{1,9}(?:\.\d{1,9}){0,3}$/.test(version)) return undefined;
  const parts = version.replace(/^v/, '').split('.').map(Number);
  return Array.from({ length: 4 }, (_, i) => parts[i] ?? 0);
}

function matchComposer(version, range) {
  const installed = composerStable(version);
  if (!installed) return null;
  let matches = true;
  for (const term of range.split(',')) {
    const match = term.trim().match(/^(<=|>=|==|=|<|>)?\s*(\S+)$/);
    const limit = match && composerStable(match[2]);
    if (!limit) return null;
    const index = installed.findIndex((part, i) => part !== limit[i]);
    const order = index < 0 ? 0 : installed[index] - limit[index];
    const [lower, upper, equal] = [order < 0, order > 0, order === 0];
    const comparisons = { '<': lower, '>': upper, '<=': lower || equal, '>=': upper || equal, '=': equal, '==': equal };
    matches &&= comparisons[match[1] ?? '='];
  }
  return matches;
}

export function matchVersion(ecosystem, version, range) {
  if (typeof version !== 'string' || typeof range !== 'string' || version.length > 200 || range.length > 2000) return null;
  try {
    if (ecosystem === 'npm') {
      const normalized = range.replaceAll(',', ' ');
      if (!semver.valid(version) || !semver.validRange(normalized)) return null;
      return semver.satisfies(version, normalized);
    }
    if (ecosystem === 'pip') {
      if (!pep440.valid(version) || !pep440.validRange(range)) return null;
      return pep440.satisfies(version, range);
    }
    if (ecosystem === 'composer') return matchComposer(version, range);
  } catch { return null; }
  return null;
}

const unquote = (value) => value.trim().replace(/^["']|["']$/g, '');
// `@scope/name@range` → `@scope/name`; also strips Yarn Berry protocols (`name@npm:^1.0.0`).
const packageName = (spec) => {
  const at = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
  return at > 0 ? spec.slice(0, at) : undefined;
};

/**
 * yarn.lock v1 (`version "1.2.3"`) and Yarn Berry v2+ (`version: 1.2.3`).
 * Each entry header lists one or more specs sharing a resolved version.
 */
export function parseYarnLock(text) {
  const entries = []; let current;
  for (const [index, raw] of String(text).split(/\r?\n/).entries()) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    if (!/^\s/.test(raw)) {
      current = undefined;
      if (!raw.endsWith(':') || raw.startsWith('__metadata')) continue;
      const spec = unquote(raw.slice(0, -1).split(/,\s*/)[0]);
      const protocol = spec.slice((packageName(spec)?.length ?? 0) + 1);
      current = { name: packageName(spec), local: /^(?:workspace|link|portal|file|exec|git\+?|https?):/.test(protocol) };
      continue;
    }
    const version = current && raw.match(/^\s{2}version:?\s+(.+)$/);
    if (version) { entries.push({ ...current, version: unquote(version[1]), line: index + 1 }); current = undefined; }
  }
  return entries;
}

/**
 * pnpm-lock.yaml keys under `packages:` (and `snapshots:` in v9):
 * v5 `/name/1.2.3_peer`, v6 `/name@1.2.3(peer@1)`, v9 `name@1.2.3`.
 */
export function parsePnpmLock(text) {
  const entries = []; let section;
  for (const [index, raw] of String(text).split(/\r?\n/).entries()) {
    if (/^\S/.test(raw)) { section = raw.replace(/:\s*$/, ''); continue; }
    if (section !== 'packages' && section !== 'snapshots') continue;
    const header = raw.match(/^ {2}(\S.*):\s*$/);
    if (!header) continue;
    // Drop v6/v9 peer suffix `(...)` and v5 peer suffix `/1.2.3_peer@x`.
    const key = unquote(header[1]).replace(/^\//, '').replace(/\(.*$/, '').replace(/(\/\d[^/_]*)_.*$/, '$1');
    let name; let version;
    const at = key.indexOf('@', key.startsWith('@') ? 1 : 0);
    if (at > 0) { name = key.slice(0, at); version = key.slice(at + 1); }
    else {
      const slash = key.lastIndexOf('/');
      if (slash > 0) { name = key.slice(0, slash); version = key.slice(slash + 1); }
    }
    // Tarball, git and file: dependencies carry no registry version.
    if (!version || /[:/]/.test(version) || /^(?:file|link|git|https?):/.test(key)) { entries.push({ line: index + 1 }); continue; }
    entries.push({ name, version, line: index + 1 });
  }
  return entries;
}

export function extractDependencies(filename, text) {
  const result = { packages: [], unresolved: 0, unsupported: 0, recognized: true };
  const add = (ecosystem, name, version, pointer) => {
    if (typeof name !== 'string' || typeof version !== 'string' || result.packages.length >= 10000) { result.unresolved++; return; }
    const valid = ecosystem === 'npm' ? semver.valid(version) : ecosystem === 'pip' ? pep440.valid(version) : composerStable(version);
    if (!valid) { result.unresolved++; return; }
    if (!result.packages.some((entry) => entry.ecosystem === ecosystem && entry.name === name && entry.version === version)) result.packages.push({ ecosystem, name, version, pointer });
  };
  if (filename === 'package-lock.json' || filename === 'npm-shrinkwrap.json') {
    const data = JSON.parse(text);
    if (data.packages && typeof data.packages === 'object') {
      for (const [key, entry] of Object.entries(data.packages)) {
        if (!key.includes('node_modules/') || !entry || entry.link) continue;
        const name = entry.name || key.slice(key.lastIndexOf('node_modules/') + 13);
        add('npm', name, entry.version, '/packages/' + key.replaceAll('~', '~0').replaceAll('/', '~1'));
      }
    } else {
      const visit = (dependencies, prefix = '/dependencies', depth = 0) => {
        if (depth > 20) { result.unresolved++; return; }
        for (const [name, entry] of Object.entries(dependencies || {})) {
          if (!entry || typeof entry !== 'object') continue;
          add('npm', name, entry.version, prefix + '/' + name);
          if (entry.dependencies) visit(entry.dependencies, prefix + '/' + name + '/dependencies', depth + 1);
        }
      };
      visit(data.dependencies);
    }
  } else if (requirements.test(filename)) {
    for (const [index, line] of text.split(/\r?\n/).entries()) {
      const clean = line.trim(); if (!clean || clean.startsWith('#')) continue;
      const match = clean.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)==([A-Za-z0-9.!+_-]+)(?:\s+#.*)?$/);
      if (match) add('pip', match[1], match[2], `line:${index + 1}`); else result.unresolved++;
    }
  } else if (filename === 'Pipfile.lock') {
    const data = JSON.parse(text);
    for (const group of ['default', 'develop']) for (const [name, entry] of Object.entries(data[group] || {})) {
      if (entry.markers || !entry.version?.startsWith('==')) result.unresolved++;
      else add('pip', name, entry.version.slice(2), '/' + group + '/' + name);
    }
  } else if (filename === 'package.json') {
    const data = JSON.parse(text);
    result.unresolved = Object.keys(data.dependencies || {}).length + Object.keys(data.devDependencies || {}).length;
  } else if (filename === 'yarn.lock') {
    for (const entry of parseYarnLock(text)) {
      if (entry.local) continue;
      if (!entry.name) { result.unresolved++; continue; }
      add('npm', entry.name, entry.version, `line:${entry.line}`);
    }
  } else if (filename === 'pnpm-lock.yaml') {
    for (const entry of parsePnpmLock(text)) {
      if (!entry.name) { result.unresolved++; continue; }
      add('npm', entry.name, entry.version, `line:${entry.line}`);
    }
  } else if (filename === 'composer.lock') {
    const data = JSON.parse(text);
    if (!Array.isArray(data?.packages) && !Array.isArray(data?.['packages-dev'])) throw new Error('Invalid Composer lockfile');
    for (const group of ['packages', 'packages-dev']) {
      if (!Array.isArray(data[group])) continue;
      for (const [index, entry] of data[group].entries()) add('composer', entry?.name, entry?.version, '/' + group + '/' + index);
    }
  } else if (isDependencyManifest(filename)) result.unsupported = 1;
  else result.recognized = false;
  return result;
}

export function dependencyFindings(packages, file) {
  const findings = []; let unassessedRanges = 0;
  for (const dependency of packages) {
    const matched = new Set();
    for (const { advisory, vulnerability } of advisoryIndex.get(dependency.ecosystem + ':' + normalize(dependency.ecosystem, dependency.name)) || []) {
      const affected = matchVersion(dependency.ecosystem, dependency.version, vulnerability.range);
      if (affected === null) { unassessedRanges++; continue; }
      if (!affected || matched.has(advisory.id)) continue;
      matched.add(advisory.id);
      const location = { file, pointer: dependency.pointer };
      if (dependency.pointer.startsWith('line:')) location.line = Number(dependency.pointer.slice(5));
      findings.push({ ruleId: 'DEP-' + advisory.id, title: `${advisory.cve || advisory.id}: ${advisory.name}`, severity: ['critical', 'high', 'medium', 'low'].includes(advisory.severity) ? advisory.severity : 'info', confidence: 'high', status: 'version-match', cwe: advisory.cwes[0] || 'CWE-1395', location,
        evidence: `${dependency.ecosystem} ${dependency.name}@${dependency.version}; JSON pointer/vị trí: ${dependency.pointer}; phạm vi advisory: ${vulnerability.range}.`,
        impact: 'Phiên bản ghi trong dependency manifest khớp advisory đã được GitHub review. Chưa xác minh package được triển khai, đường gọi có thể tiếp cận hay điều kiện khai thác.',
        remediation: vulnerability.fixed ? `Đánh giá cập nhật ${dependency.name} lên bản vá ${vulnerability.fixed} hoặc bản còn được hỗ trợ; kiểm tra toàn bộ advisory và test tương thích.` : 'Chưa có bản vá trong snapshot; xem advisory để chọn biện pháp giảm thiểu hoặc thay dependency.',
        reference: advisory.references[0], advisory: { id: advisory.id, cve: advisory.cve, ecosystem: dependency.ecosystem, package: dependency.name, version: dependency.version, affectedRange: vulnerability.range, fixed: vulnerability.fixed, updatedAt: advisory.updatedAt, description: advisory.description, references: advisory.references, kev: knownExploited(advisory.cve) ? { dateAdded: knownExploited(advisory.cve).dateAdded, reference: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', scope: 'CVE được CISA ghi nhận khai thác ngoài thực tế; không chứng minh mục tiêu local đã bị khai thác.' } : undefined } });
    }
  }
  return { findings, unassessedRanges };
}
