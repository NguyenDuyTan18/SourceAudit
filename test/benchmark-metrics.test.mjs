import test from 'node:test';
import assert from 'node:assert/strict';
import { parseExpectedResults, regressions, scoreClean, scoreLabeled, scorePairs } from '../scripts/benchmark-metrics.mjs';

const finding = (file, cwe, ruleId = 'R', severity = 'high') => ({ ruleId, cwe, severity, location: { file } });

test('expected results parser accepts OWASP format and rejects malformed rows', () => {
  const cases = parseExpectedResults('# header\nBenchmarkTest00001,sqli,true,89\r\nBenchmarkTest00002,hash,false,328\n');
  assert.deepEqual(cases, [
    { name: 'BenchmarkTest00001', category: 'sqli', real: true, cwe: 'CWE-89' },
    { name: 'BenchmarkTest00002', category: 'hash', real: false, cwe: 'CWE-328' },
  ]);
  assert.throws(() => parseExpectedResults('a b,sqli,maybe,89'), /Invalid expected-results row/);
});

test('labeled scoring computes confusion matrix, Youden score, aliases and per-rule precision', () => {
  const cases = parseExpectedResults('T1,sqli,true,89\nT2,sqli,false,89\nT3,sqli,true,89\nT4,sqli,false,89\nT5,hash,true,328\n');
  const findings = [finding('a/T1.java', 'CWE-89', 'SQL'), finding('a/T2.java', 'CWE-89', 'SQL'), finding('a/T5.java', 'CWE-327', 'HASH'), finding('a/T4.java', 'CWE-79', 'XSS')];
  const result = scoreLabeled(cases, findings, (file) => file.split('/').at(-1).replace(/\..*$/, ''));
  assert.deepEqual(result.categories.sqli, { cwe: 'CWE-89', tp: 1, fp: 1, fn: 1, tn: 1, tpr: 0.5, fpr: 0.5, precision: 0.5, score: 0 });
  assert.equal(result.categories.hash.tp, 1, 'CWE-327 counts for the weak-hash category');
  assert.deepEqual(result.rules.SQL, { tp: 1, fp: 1, offCategory: 0, precision: 0.5 });
  assert.equal(result.rules.XSS.offCategory, 1);
  assert.equal(result.overall.score, 0.5);
  assert.deepEqual(result.falsePositiveCases, [
    { name: 'T2', category: 'sqli', cwe: 'CWE-89', ruleIds: ['SQL'] },
  ]);
});

test('pair, clean scoring and regression check', () => {
  const pairs = [{ name: 'a', cwe: 'CWE-78' }, { name: 'b', cwe: 'CWE-89' }];
  const filename = (item, variant) => `${item.name}-${variant}.js`;
  const result = scorePairs(pairs, [finding('a-vulnerable.js', 'CWE-78', 'SH'), finding('a-fixed.js', 'CWE-78', 'SH'), finding('b-fixed.js', 'CWE-79')], filename);
  assert.deepEqual(result.overall, { detected: 1, falsePositives: 1, tpr: 0.5, fpr: 0.5, score: 0 });
  assert.deepEqual(result.missed, ['b']);
  assert.deepEqual(result.rules.SH, { tp: 1, fp: 1, precision: 0.5 });
  const clean = scoreClean([finding('x', 'CWE-1', 'A'), finding('y', 'CWE-1', 'A', 'info')], 2, 2000);
  assert.deepEqual(clean.overall, { findings: 2, perKloc: 1, actionable: 1, actionablePerKloc: 0.5 });
  const baseline = { 'x:quick': { overall: { score: 0.5, tpr: 0.5, fpr: 0.1 }, categories: { sqli: { score: 0.4 } } }, 'c:quick': { overall: { perKloc: 1, actionablePerKloc: 0.5 } } };
  assert.deepEqual(regressions({ 'x:quick': { overall: { score: 0.6, tpr: 0.6, fpr: 0.05 }, categories: { sqli: { score: 0.45 } } }, 'c:quick': { overall: { perKloc: 0.2, actionablePerKloc: 0.1 } } }, baseline), []);
  const problems = regressions({ 'x:quick': { overall: { score: 0.3, tpr: 0.5, fpr: 0.3 }, categories: { sqli: { score: 0.1 } } } }, baseline);
  assert.equal(problems.length, 4);
  assert.match(problems.join('\n'), /c:quick: Missing results/);
});
