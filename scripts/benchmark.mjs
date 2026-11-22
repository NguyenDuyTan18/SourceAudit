#!/usr/bin/env node
// Accuracy benchmark for SrcAudit.
//
//   node scripts/benchmark.mjs --fetch                 # download external datasets (pinned commits)
//   node scripts/benchmark.mjs                         # quick mode, every available suite
//   node scripts/benchmark.mjs --mode deep             # Semgrep mode
//   node scripts/benchmark.mjs --check benchmarks/baseline.json
//   node scripts/benchmark.mjs --update-baseline benchmarks/baseline.json
//
// Suites:
//   internal      vulnerable/fixed pairs from scripts/benchmark-cases.mjs
//   owasp-java    OWASP Benchmark Java 1.2 (2740 labeled cases)
//   owasp-python  OWASP Benchmark Python 0.1 (1230 labeled cases)
//   clean-js / clean-py   popular projects; every finding is a false-positive candidate
//   python-precision / python-holdout / python-coverage   focused pairs for deep mode
//
// Datasets are read as text only and live under .scanner-tools/benchmarks (git-ignored).
// OWASP Benchmark is GPL-2.0; it is downloaded on demand and never vendored.
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanSource } from '../src/source.mjs';
import { pathKey } from '../src/git-diff.mjs';
import { pairs } from './benchmark-cases.mjs';
import { pythonPrecisionCases, pythonPrecisionHoldout } from './semgrep-python-precision-cases.mjs';
import { pythonCoverageCases } from './semgrep-python-coverage-cases.mjs';
import { parseExpectedResults, regressions, scoreClean, scoreLabeled, scorePairs } from './benchmark-metrics.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const dataDir = path.join(root, '.scanner-tools', 'benchmarks');

export const DATASETS = {
  'owasp-java': { repo: 'OWASP-Benchmark/BenchmarkJava', commit: 'db99977cbf6b30236089a691136d718aa7bb6935', dir: 'BenchmarkJava', paths: ['/expectedresults-1.2.csv', '/LICENSE', '/src/main/java/org/owasp/benchmark/testcode/'], expected: 'expectedresults-1.2.csv', code: 'src/main/java/org/owasp/benchmark/testcode' },
  'owasp-python': { repo: 'OWASP-Benchmark/BenchmarkPython', commit: 'f1291485808b66e20ddb6b01b10dc71b3df8c8ba', dir: 'BenchmarkPython', paths: ['/expectedresults-0.1.csv', '/LICENSE', '/testcode/'], expected: 'expectedresults-0.1.csv', code: 'testcode' },
  'clean-express': { repo: 'expressjs/express', commit: '43fca52d28a422c8be48fd489cbd4f2d6152bab6', dir: 'express', paths: ['/lib/', '/index.js'], code: '.' },
  'clean-koa': { repo: 'koajs/koa', commit: 'b7ead6f7a2bb56e2948b1c5e1cca77483e89c885', dir: 'koa', paths: ['/lib/'], code: '.' },
  'clean-axios': { repo: 'axios/axios', commit: '4ee8d46fc463770b8f5da718d5449a5b027b2c08', dir: 'axios', paths: ['/lib/'], code: '.' },
  'clean-flask': { repo: 'pallets/flask', commit: '49943b5a94413a530761350f04e896f76e8d620e', dir: 'flask', paths: ['/src/'], code: '.' },
  'clean-requests': { repo: 'psf/requests', commit: '3c7baaa05ab4aa49cc819ce3a819d260de19c157', dir: 'requests', paths: ['/src/'], code: '.' },
  'reference-setup-node': { repo: 'actions/setup-node', commit: '66f83c8206e0997178c8fd7bf1da9efccf5dd388', dir: 'actions-setup-node', paths: ['/.github/workflows/', '/LICENSE'], code: '.' },
  'reference-setup-python': { repo: 'actions/setup-python', commit: '5043d30437de73e5e7500b5c41676e0c30aa54f2', dir: 'actions-setup-python', paths: ['/.github/workflows/', '/LICENSE'], code: '.' },
  'reference-checkout': { repo: 'actions/checkout', commit: 'f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a', dir: 'actions-checkout', paths: ['/.github/workflows/', '/LICENSE'], code: '.' },
};
const SUITES = { internal: [], 'owasp-java': ['owasp-java'], 'owasp-python': ['owasp-python'], 'clean-js': ['clean-express', 'clean-koa', 'clean-axios'], 'clean-py': ['clean-flask', 'clean-requests'] };
const REFERENCE_SUITES = { 'workflow-reference': ['reference-setup-node', 'reference-setup-python', 'reference-checkout'] };
const PYTHON_SUITES = {
  'python-precision': pythonPrecisionCases,
  'python-holdout': pythonPrecisionHoldout,
  'python-coverage': pythonCoverageCases,
};

function parseArgs(argv) {
  const options = { mode: 'quick', suites: Object.keys(SUITES) };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = () => { const next = argv[++i]; if (!next || next.startsWith('--')) throw new Error(`Missing value for ${arg}`); return next; };
    if (arg === '--fetch') options.fetch = true;
    else if (arg === '--mode') options.mode = value();
    else if (arg === '--suite') options.suites = value().split(',');
    else if (arg === '--json') options.json = value();
    else if (arg === '--check') options.check = value();
    else if (arg === '--update-baseline') options.update = value();
    else throw new Error(`Unknown option: ${arg}`);
  }
  if (!['quick', 'deep'].includes(options.mode)) throw new Error('--mode must be quick or deep.');
  for (const suite of options.suites) if (!Object.hasOwn(SUITES, suite) && !Object.hasOwn(PYTHON_SUITES, suite) && !Object.hasOwn(REFERENCE_SUITES, suite)) throw new Error(`Unknown suite: ${suite}`);
  return options;
}

function git(cwd, ...args) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8', env: { ...process.env, MSYS_NO_PATHCONV: '1', GIT_TERMINAL_PROMPT: '0' } });
  if (result.status !== 0) throw new Error(`git ${args[0]} failed: ${result.stderr.trim().slice(0, 300)}`);
  return result.stdout.trim();
}

async function fetchDataset(name) {
  const dataset = DATASETS[name];
  const target = path.join(dataDir, dataset.dir);
  if (!existsSync(path.join(target, '.git'))) {
    await mkdir(target, { recursive: true });
    git(target, 'init', '-q');
    git(target, 'remote', 'add', 'origin', `https://github.com/${dataset.repo}.git`);
  }
  git(target, 'sparse-checkout', 'set', '--no-cone', ...dataset.paths);
  git(target, 'fetch', '-q', '--depth', '1', '--filter=blob:none', 'origin', dataset.commit);
  git(target, 'checkout', '-q', '--detach', dataset.commit);
  console.error(`Downloaded ${name} @ ${dataset.commit.slice(0, 12)}`);
}

function datasetPath(name) {
  const dataset = DATASETS[name];
  const target = path.join(dataDir, dataset.dir);
  if (!existsSync(path.join(target, '.git'))) return undefined;
  const head = git(target, 'rev-parse', 'HEAD');
  if (head !== dataset.commit) throw new Error(`${name}: local commit ${head.slice(0, 12)} differs from expected ${dataset.commit.slice(0, 12)}. Run with --fetch.`);
  return target;
}

const scanOptions = (mode) => ({ analysis: mode, maxFiles: 20000, maxFindings: 1_000_000, gitignore: false });
const requireComplete = (report, suite) => {
  if (report.status !== 'complete') throw new Error(suite + ' scan not completed: ' + report.errors.slice(0, 3).join(' | '));
};

async function runPairs(mode, samples = pairs) {
  const folder = await mkdtemp(path.join(tmpdir(), 'srcaudit-bench-'));
  try {
    const filename = (item, variant) => item.name + '-' + variant + (item.target ? '/' + item.target : '.' + item.ext);
    for (const item of samples) for (const variant of ['vulnerable', 'fixed']) {
      const destination = path.join(folder, filename(item, variant));
      await mkdir(path.dirname(destination), { recursive: true });
      await writeFile(destination, item[variant], { flag: 'wx' });
    }
    const report = await scanSource(folder, scanOptions(mode));
    requireComplete(report, 'internal');
    return { ...scorePairs(samples, report.findings, filename), stats: filterStats(report) };
  } finally { await rm(folder, { recursive: true, force: true }); }
}

async function runLabeled(name, mode) {
  const target = datasetPath(name);
  if (!target) return undefined;
  const dataset = DATASETS[name];
  const cases = parseExpectedResults(await readFile(path.join(target, dataset.expected), 'utf8'));
  const code = path.join(target, dataset.code);
  const reports = [];
  if (mode === 'deep' && cases.length > 450) {
    // Keep each Semgrep run below the application's per-run timeout on slower hosts.
    const extension = name === 'owasp-java' ? '.java' : '.py';
    for (let offset = 0; offset < cases.length; offset += 450) {
      const batch = cases.slice(offset, offset + 450);
      const onlyFiles = new Set(batch.map(({ name: file }) => pathKey(path.join(code, file + extension))));
      const report = await scanSource(code, { ...scanOptions(mode), onlyFiles });
      requireComplete(report, name + ' (' + offset + ')');
      if (report.stats.sourceAnalysis.scanned !== batch.length) throw new Error(name + ' did not scan every file in the batch.');
      reports.push(report);
    }
  } else {
    const report = await scanSource(code, scanOptions(mode));
    requireComplete(report, name);
    reports.push(report);
  }
  const fileOf = (file) => path.posix.basename(file).replace(/\.[^.]+$/, '');
  const stats = reports.length === 1 ? filterStats(reports[0]) : {
    batches: reports.length,
    ...(reports.some(({ stats }) => stats.sourceAnalysis?.pythonPrecision)
      ? { pythonPrecision: reports.map(({ stats }) => stats.sourceAnalysis?.pythonPrecision ?? null) } : {}),
  };
  return { dataset: `${dataset.repo}@${dataset.commit.slice(0, 12)}`, status: 'complete', ...scoreLabeled(cases, reports.flatMap(({ findings }) => findings), fileOf), stats };
}

async function runClean(names, mode) {
  const findings = []; let files = 0; let lines = 0; const datasets = [];
  for (const name of names) {
    const target = datasetPath(name);
    if (!target) return undefined;
    const report = await scanSource(path.join(target, DATASETS[name].code), scanOptions(mode));
    requireComplete(report, name);
    findings.push(...report.findings.map((f) => ({ ...f, location: { ...f.location, file: `${name}/${f.location.file}` } })));
    files += report.stats.filesScanned;
    lines += report.stats.linesScanned ?? 0;
    datasets.push(`${DATASETS[name].repo}@${DATASETS[name].commit.slice(0, 12)}`);
  }
  return { datasets, ...scoreClean(findings, files, lines), samples: findings.slice(0, 40).map((f) => `${f.ruleId} ${f.location.file}:${f.location.line}`) };
}

function filterStats({ stats }) {
  const pythonPrecision = stats.sourceAnalysis?.pythonPrecision;
  return {
    ...(stats.astFilter ? { astFilter: stats.astFilter } : {}),
    ...(stats.contextFilter ? { contextFilter: stats.contextFilter } : {}),
    ...(pythonPrecision ? { pythonPrecision } : {}),
  };
}

function printSummary(results) {
  const rows = [];
  for (const [key, result] of Object.entries(results)) {
    const o = result.overall;
    rows.push({ suite: key, 'cases/files': result.cases ?? result.filesScanned, TPR: o.tpr ?? '', FPR: o.fpr ?? '', precision: o.precision ?? '', score: o.score ?? '', 'findings/KLOC': o.perKloc ?? '', 'actionable/KLOC': o.actionablePerKloc ?? '' });
  }
  console.table(rows);
  for (const [key, result] of Object.entries(results)) {
    if (!result.categories) continue;
    console.log(`\n${key} by weakness (score = TPR - FPR):`);
    console.table(Object.fromEntries(Object.entries(result.categories).map(([name, c]) => [name, { cwe: c.cwe, TP: c.tp, FP: c.fp, FN: c.fn, TN: c.tn, TPR: c.tpr, FPR: c.fpr, score: c.score }])));
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const wanted = new Set(options.suites.flatMap((suite) => SUITES[suite] ?? REFERENCE_SUITES[suite] ?? []));
  if (options.fetch) for (const name of wanted) await fetchDataset(name);
  const results = {};
  for (const suite of options.suites) {
    const key = `${suite}:${options.mode}`;
    const result = suite === 'internal' || PYTHON_SUITES[suite] ? await runPairs(options.mode, PYTHON_SUITES[suite])
      : suite.startsWith('clean') || REFERENCE_SUITES[suite] ? await runClean(SUITES[suite] ?? REFERENCE_SUITES[suite], options.mode)
        : await runLabeled(SUITES[suite][0], options.mode);
    if (result) results[key] = result;
    else console.error(`Skip ${suite}: No data, run with --fetch.`);
  }
  printSummary(results);
  if (options.json) await writeFile(options.json, JSON.stringify(results, null, 2) + '\n');
  if (options.update) {
    const file = path.resolve(options.update);
    const previous = existsSync(file) ? JSON.parse(await readFile(file, 'utf8')) : {};
    const slim = Object.fromEntries(Object.entries(results).map(([key, r]) => [key, { overall: r.overall, ...(r.categories ? { categories: Object.fromEntries(Object.entries(r.categories).map(([c, v]) => [c, { score: v.score, tpr: v.tpr, fpr: v.fpr }])) } : {}) }]));
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, JSON.stringify({ ...previous, ...slim }, null, 2) + '\n');
    console.log(`\nUpdated baseline: ${options.update}`);
  }
  if (options.check) {
    const baseline = JSON.parse(await readFile(path.resolve(options.check), 'utf8'));
    const scoped = Object.fromEntries(Object.entries(baseline).filter(([key]) => key in results || options.suites.includes(key.split(':')[0]) && key.endsWith(':' + options.mode)));
    const problems = regressions(results, scoped);
    if (problems.length) { console.error('\nBenchmark results regressed relative to the baseline:\n- ' + problems.join('\n- ')); process.exitCode = 1; }
    else console.log('\nBenchmark results meet the baseline.');
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { console.error('Error: ' + error.message); process.exitCode = 2; });
}
