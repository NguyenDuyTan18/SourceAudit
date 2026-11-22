// Pure scoring helpers shared by scripts/benchmark.mjs and its tests.

// A finding counts for a benchmark category when its CWE is the category CWE or a
// closely related child/parent used by SrcAudit rules (e.g. weak hash 328 vs 327).
export const CWE_ALIASES = {
  'CWE-22': ['CWE-22', 'CWE-23', 'CWE-36'],
  'CWE-79': ['CWE-79', 'CWE-80'],
  'CWE-94': ['CWE-94', 'CWE-95'],
  'CWE-327': ['CWE-327', 'CWE-326'],
  'CWE-328': ['CWE-328', 'CWE-327', 'CWE-916'],
  'CWE-330': ['CWE-330', 'CWE-338'],
  'CWE-614': ['CWE-614', 'CWE-1004'],
};
const accepted = (cwe) => CWE_ALIASES[cwe] ?? [cwe];
const ratio = (a, b) => (b ? Number((a / b).toFixed(4)) : null);

/** Parses an OWASP Benchmark expectedresults CSV: `name,category,true|false,cwe`. */
export function parseExpectedResults(text) {
  const cases = [];
  for (const line of String(text).split(/\r?\n/)) {
    if (!line.trim() || line.startsWith('#')) continue;
    const [name, category, real, cwe] = line.split(',').map((part) => part.trim());
    if (!/^[A-Za-z0-9_]+$/.test(name) || !['true', 'false'].includes(real) || !/^\d+$/.test(cwe)) throw new Error(`Invalid expected-results row: ${line.slice(0, 80)}`);
    cases.push({ name, category, real: real === 'true', cwe: `CWE-${cwe}` });
  }
  return cases;
}

/**
 * OWASP-style scoring: each test case is one file with one expected category.
 * Positive = the scanner reports a finding of an accepted CWE in that file.
 * Score = TPR - FPR (Youden index), as in the OWASP Benchmark scorecard.
 */
export function scoreLabeled(cases, findings, fileOf) {
  const byFile = new Map();
  for (const finding of findings) {
    const name = fileOf(finding.location?.file ?? '');
    if (!name) continue;
    if (!byFile.has(name)) byFile.set(name, []);
    byFile.get(name).push(finding);
  }
  const categories = {}; const rules = {};
  const falsePositiveCases = [];
  const rule = (id) => (rules[id] ??= { tp: 0, fp: 0, offCategory: 0 });
  for (const item of cases) {
    const bucket = (categories[item.category] ??= { cwe: item.cwe, tp: 0, fp: 0, fn: 0, tn: 0 });
    const hits = byFile.get(item.name) ?? [];
    const relevant = hits.filter((finding) => accepted(item.cwe).includes(finding.cwe));
    if (relevant.length) bucket[item.real ? 'tp' : 'fp']++;
    else bucket[item.real ? 'fn' : 'tn']++;
    const ruleIds = [...new Set(relevant.map((f) => f.ruleId))].sort();
    if (!item.real && ruleIds.length) {
      falsePositiveCases.push({ name: item.name, category: item.category, cwe: item.cwe, ruleIds });
    }
    for (const id of ruleIds) rule(id)[item.real ? 'tp' : 'fp']++;
    for (const id of new Set(hits.filter((f) => !relevant.includes(f)).map((f) => f.ruleId))) rule(id).offCategory++;
  }
  const totals = { tp: 0, fp: 0, fn: 0, tn: 0 };
  for (const bucket of Object.values(categories)) {
    for (const key of Object.keys(totals)) totals[key] += bucket[key];
    bucket.tpr = ratio(bucket.tp, bucket.tp + bucket.fn) ?? 0;
    bucket.fpr = ratio(bucket.fp, bucket.fp + bucket.tn) ?? 0;
    bucket.precision = ratio(bucket.tp, bucket.tp + bucket.fp);
    bucket.score = Number((bucket.tpr - bucket.fpr).toFixed(4));
  }
  for (const entry of Object.values(rules)) entry.precision = ratio(entry.tp, entry.tp + entry.fp);
  const scores = Object.values(categories).map((bucket) => bucket.score);
  return {
    cases: cases.length,
    overall: {
      ...totals,
      tpr: ratio(totals.tp, totals.tp + totals.fn) ?? 0,
      fpr: ratio(totals.fp, totals.fp + totals.tn) ?? 0,
      precision: ratio(totals.tp, totals.tp + totals.fp),
      score: scores.length ? Number((scores.reduce((a, b) => a + b, 0) / scores.length).toFixed(4)) : 0,
    },
    categories: sortKeys(categories),
    rules: sortKeys(rules),
    falsePositiveCases,
  };
}

/** Internal vulnerable/fixed pairs: the fixed variant must stay silent for the pair's CWE. */
export function scorePairs(pairs, findings, filename) {
  const rules = {}; const missed = []; const falsePositives = [];
  let detected = 0; let flagged = 0;
  const rule = (id) => (rules[id] ??= { tp: 0, fp: 0 });
  for (const item of pairs) {
    const hits = (variant) => findings.filter((f) => f.location?.file === filename(item, variant) && f.cwe === item.cwe);
    const vulnerable = hits('vulnerable'); const fixed = hits('fixed');
    if (vulnerable.length) detected++; else missed.push(item.name);
    if (fixed.length) { flagged++; falsePositives.push(item.name); }
    for (const id of new Set(vulnerable.map((f) => f.ruleId))) rule(id).tp++;
    for (const id of new Set(fixed.map((f) => f.ruleId))) rule(id).fp++;
  }
  for (const entry of Object.values(rules)) entry.precision = ratio(entry.tp, entry.tp + entry.fp);
  return {
    cases: pairs.length,
    overall: { detected, falsePositives: flagged, tpr: ratio(detected, pairs.length) ?? 0, fpr: ratio(flagged, pairs.length) ?? 0, score: Number(((detected - flagged) / (pairs.length || 1)).toFixed(4)) },
    rules: sortKeys(rules), missed, falsePositiveCases: falsePositives,
  };
}

/** Findings on code assumed free of the reported issue; every hit is a false-positive candidate. */
export function scoreClean(findings, filesScanned, lines) {
  const rules = {};
  for (const finding of findings) rules[finding.ruleId] = (rules[finding.ruleId] ?? 0) + 1;
  // "Actionable" excludes info-level findings (placeholders, dev-only config), which never fail CI.
  const actionable = findings.filter((f) => f.severity !== 'info').length;
  const perKloc = (n) => (lines ? Number((n / (lines / 1000)).toFixed(3)) : 0);
  return { filesScanned, lines, overall: { findings: findings.length, perKloc: perKloc(findings.length), actionable, actionablePerKloc: perKloc(actionable) }, rules: sortKeys(rules) };
}

function sortKeys(object) {
  return Object.fromEntries(Object.entries(object).sort(([a], [b]) => a.localeCompare(b)));
}

/**
 * Returns human-readable regressions of `current` against `baseline` (same shape as
 * the benchmark output). Improvements never fail; `tolerance` absorbs rounding noise.
 */
export function regressions(current, baseline, tolerance = 0.005) {
  const problems = [];
  for (const [key, base] of Object.entries(baseline ?? {})) {
    const now = current[key];
    if (!now) { problems.push(`${key}: Missing results for a baseline entry.`); continue; }
    if (base.overall.score !== undefined && now.overall.score < base.overall.score - tolerance) problems.push(`${key}: score ${now.overall.score} < baseline ${base.overall.score}`);
    if (base.overall.tpr !== undefined && now.overall.tpr < base.overall.tpr - tolerance) problems.push(`${key}: TPR ${now.overall.tpr} < baseline ${base.overall.tpr}`);
    if (base.overall.fpr !== undefined && now.overall.fpr > base.overall.fpr + tolerance) problems.push(`${key}: FPR ${now.overall.fpr} > baseline ${base.overall.fpr}`);
    if (base.overall.perKloc !== undefined && now.overall.perKloc > base.overall.perKloc + tolerance) problems.push(`${key}: ${now.overall.perKloc} warnings/KLOC exceed baseline ${base.overall.perKloc}`);
    if (base.overall.actionablePerKloc !== undefined && now.overall.actionablePerKloc > base.overall.actionablePerKloc + tolerance) problems.push(`${key}: ${now.overall.actionablePerKloc} actionable warnings/KLOC exceed baseline ${base.overall.actionablePerKloc}`);
    for (const [category, entry] of Object.entries(base.categories ?? {})) {
      const nowEntry = now.categories?.[category];
      if (nowEntry && nowEntry.score < entry.score - tolerance) problems.push(`${key}/${category}: score ${nowEntry.score} < baseline ${entry.score}`);
    }
  }
  return problems;
}
