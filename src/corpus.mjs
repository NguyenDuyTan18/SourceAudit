import { readFileSync } from 'node:fs';

const base = JSON.parse(readFileSync(new URL('../data/corpus.json', import.meta.url), 'utf8'));
let extension = {};
try { extension = JSON.parse(readFileSync(new URL('../data/extensions.json', import.meta.url), 'utf8')); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
const advisoryMap = new Map(base.advisories.map((entry) => [entry.id, entry]));
for (const entry of extension.advisories || []) {
  const previous = advisoryMap.get(entry.id);
  if (!previous || String(entry.updatedAt) >= String(previous.updatedAt)) advisoryMap.set(entry.id, entry);
}
export const CORPUS = { ...base, advisories: [...advisoryMap.values()], asvs: extension.asvs || [], api: extension.api || [], kev: extension.kev || [], extension };
const cweIndex = new Map(CORPUS.weaknesses.map((entry) => [entry.id, entry]));
const kevIndex = new Map(CORPUS.kev.map((entry) => [entry.cve, entry]));
const requirementIndex = new Map(CORPUS.asvs.map((entry) => [entry.id, entry]));
const entries = [...CORPUS.weaknesses, ...CORPUS.wstg, ...CORPUS.advisories, ...CORPUS.asvs, ...CORPUS.api, ...CORPUS.kev];
const normalize = (value) => String(value).toLowerCase().normalize('NFKD').replace(/\p{Diacritic}/gu, '');
const searchable = entries.map((entry) => normalize([entry.id, entry.cve, entry.name, entry.description, ...(entry.cwes || []), ...(entry.vulnerabilities || []).map((v) => v.name)].join(' ')));

export function corpusStats() {
  return { cwe: CORPUS.weaknesses.length, owasp: CORPUS.wstg.length, advisories: CORPUS.advisories.length, asvs: CORPUS.asvs.length, api: CORPUS.api.length, kev: CORPUS.kev.length, total: entries.length, builtAt: extension.builtAt || CORPUS.builtAt, baseBuiltAt: CORPUS.builtAt, cweVersion: CORPUS.cweVersion, wstgVersion: CORPUS.wstgVersion, asvsVersion: extension.asvsVersion, apiVersion: extension.apiVersion, kevVersion: extension.kevVersion, selection: CORPUS.selection + (extension.selection ? ' Extensions: ' + extension.selection : ''), sourceErrors: CORPUS.errors.length + (extension.errors || []).length };
}
export function contextForCwe(id) { return cweIndex.get(id); }
export function knownExploited(cve) { return kevIndex.get(cve); }
export function verificationRequirements(ids = []) { return ids.map((id) => requirementIndex.get(id)).filter(Boolean); }
export function searchCorpus(query = '', { kind = 'all', page = 1, pageSize = 25 } = {}) {
  const terms = normalize(query).trim().split(/\s+/).filter(Boolean).slice(0, 12);
  const results = entries.filter((entry, i) => (kind === 'all' || entry.kind === kind) && terms.every((term) => searchable[i].includes(term)));
  const size = Math.min(50, Math.max(1, Number(pageSize) || 25));
  const current = Math.min(Math.max(1, Number(page) || 1), Math.max(1, Math.ceil(results.length / size)));
  return { total: results.length, page: current, pages: Math.ceil(results.length / size), results: results.slice((current - 1) * size, current * size) };
}

export function relatedContext(cwe) {
  const weakness = contextForCwe(cwe);
  const tests = CORPUS.wstg.filter((entry) => entry.cwes.includes(cwe)).slice(0, 4);
  const examples = CORPUS.advisories.filter((entry) => entry.cwes.includes(cwe)).slice(0, 3);
  const apiScenarios = CORPUS.api.filter((entry) => entry.cwes.includes(cwe)).slice(0, 3);
  return { weakness, tests, examples, apiScenarios };
}
