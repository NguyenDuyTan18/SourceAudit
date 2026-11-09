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
  } catch { return null; }
  return null;
}

export function extractDependencies(filename, text) {
  const result = { packages: [], unresolved: 0, unsupported: 0, recognized: true };
  const add = (ecosystem, name, version, pointer) => {
    if (typeof name !== 'string' || typeof version !== 'string' || result.packages.length >= 10000) { result.unresolved++; return; }
    const valid = ecosystem === 'npm' ? semver.valid(version) : pep440.valid(version);
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
  } else if (/^requirements(?:[.-].*)?\.txt$/i.test(filename)) {
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
  } else if (['composer.lock', 'Gemfile.lock', 'go.mod', 'pom.xml', 'packages.lock.json', 'poetry.lock', 'yarn.lock', 'pnpm-lock.yaml'].includes(filename)) result.unsupported = 1;
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
