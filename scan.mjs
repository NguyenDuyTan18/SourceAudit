#!/usr/bin/env node
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { changedFiles, DiffError } from './src/git-diff.mjs';
import { applyBaseline } from './src/triage.mjs';
import { scanSource, SOURCE_RULES } from './src/source.mjs';
import { MAX_SOURCE_FILE_BYTES, MIB } from './src/scan-scope.mjs';
import { renderText, writeReports, SEVERITIES } from './src/report.mjs';
import { pruneReports, resolveRetentionMs } from './src/report-retention.mjs';
import { searchKnowledge, importWriteup, loadCustomRules, loadWriteups, enrichReport } from './src/knowledge.mjs';

const HELP = `SrcAudit — Static source code analysis (Node.js >= 22).

Scan and export HTML, JSON, text and SARIF reports:
  node scan.mjs --src "D:\\path\\to\\source" --out ./reports/run-2
  node scan.mjs --src ./app --deep
  node scan.mjs "D:\\path\\to\\source"

Find rules and add review references:
  node scan.mjs --list-rules
  node scan.mjs --knowledge sqli
  node scan.mjs --import-writeup ./notes.md --knowledge-dir ./knowledge-local
  node scan.mjs --src ./app --rules ./examples/custom-rules.json --knowledge-dir ./knowledge-local

Options:
  --max-bytes N    Per-file limit, default ${MAX_SOURCE_FILE_BYTES / MIB} MiB (100..${MAX_SOURCE_FILE_BYTES} bytes)
  --max-files N    Source file limit, default 2000, maximum 20000
  --deep           Run Semgrep CE analysis
  --fail-on LEVEL  Exit 1 at or above critical, high, medium, low or info
  --out DIR        Report directory (default: .scanner-reports/<timestamp> under the data directory)
  --baseline FILE  Show new findings relative to an earlier report.json
  --diff REF       Scan files changed since the Git merge base of REF and HEAD
  --no-gitignore   Include files excluded by .gitignore
  --include-tests  Include test files and directories
  --help           Show this help

Suppress a finding with an inline rule ID and reason:
  db.query(sql); // srcaudit-ignore SRC-SQL -- SQL is a fixed internal query

For the default report directory, SRCAUDIT_REPORT_RETENTION_DAYS controls retention
(seven days by default, zero disables cleanup).

Exit 0: scan completed. Exit 1: a finding met --fail-on. Exit 2: invalid input or incomplete scan.
Scan only code you own or are authorized to review.
`;

function parseArgs(args) {
  const values = new Set(['src', 'out', 'max-bytes', 'max-files', 'fail-on', 'rules', 'knowledge', 'import-writeup', 'knowledge-dir', 'baseline', 'diff']);
  const flags = new Set(['help', 'list-rules', 'deep', 'no-gitignore', 'include-tests']);
  const options = {};
  let positional;
  for (let i = 0; i < args.length; i++) {
    if (!args[i].startsWith('--')) {
      if (positional) throw new Error('Provide only one source path.');
      positional = args[i]; continue;
    }
    const key = args[i].slice(2);
    if (Object.hasOwn(options, key)) throw new Error(`Duplicate option: --${key}`);
    if (flags.has(key)) options[key] = true;
    else if (values.has(key)) {
      const value = args[++i];
      if (!value || value.startsWith('--')) throw new Error(`Missing value for --${key}.`);
      options[key] = value;
    } else throw new Error(`Unknown option: --${key}`);
  }
  if (positional) {
    if (options.src) throw new Error('Provide the source path either as a positional argument or with --src.');
    options.src = positional;
  }
  if (options.src && /^[a-z][a-z\d+.-]+:\/\//i.test(options.src.trim())) throw new Error('--src requires a local path.');
  const numeric = { 'max-bytes': [100, MAX_SOURCE_FILE_BYTES], 'max-files': [1, 20000] };
  for (const [key, [min, max]] of Object.entries(numeric)) {
    if (options[key] !== undefined) {
      const value = Number(options[key]);
      if (!Number.isInteger(value) || value < min || value > max) throw new Error(`--${key} must be the integer ${min}..${max}.`);
      options[key] = value;
    }
  }
  if (options['fail-on'] && !SEVERITIES.includes(options['fail-on'])) throw new Error('Invalid severity for --fail-on.');
  if (!options.help && ['src', 'knowledge', 'list-rules', 'import-writeup'].filter((key) => options[key] !== undefined).length !== 1) throw new Error('Select one operation: --src, --knowledge, --list-rules or --import-writeup.');
  if (options.deep && (!options.src || options.rules)) throw new Error('--deep requires --src and uses the bundled Semgrep rules.');
  if ((options.baseline || options.diff || options['no-gitignore'] || options['include-tests']) && !options.src) throw new Error('--baseline, --diff, --no-gitignore and --include-tests require --src.');
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) { console.log(HELP); return; }
  if (options['list-rules']) { console.log(JSON.stringify({ source: SOURCE_RULES }, null, 2)); return; }
  if (options.knowledge !== undefined) { console.log(JSON.stringify(searchKnowledge(options.knowledge), null, 2)); return; }
  const dataRoot = process.env.SRCAUDIT_DATA_DIR || '.';
  const knowledgeDir = options['knowledge-dir'] ? path.resolve(options['knowledge-dir'])
    : process.env.SRCAUDIT_DATA_DIR ? path.resolve(dataRoot, 'knowledge-local') : undefined;
  if (options['import-writeup']) { console.log(JSON.stringify(await importWriteup(options['import-writeup'], knowledgeDir ?? 'knowledge-local'), null, 2)); return; }
  if (options.rules && !options.src) throw new Error('--rules requires --src.');
  const reportsDir = path.resolve(dataRoot, '.scanner-reports');
  const outDir = path.resolve(options.out ?? path.join(reportsDir, new Date().toISOString().replace(/[:.]/g, '-')));
  const customRules = options.rules ? await loadCustomRules(options.rules) : [];
  const writeups = await loadWriteups(knowledgeDir, { allowMissing: !options['knowledge-dir'] });
  let baseline;
  if (options.baseline) {
    try { baseline = JSON.parse(await readFile(path.resolve(options.baseline), 'utf8')); } catch { baseline = undefined; }
    if (!Array.isArray(baseline?.findings) || (baseline.findings.length && !baseline.findings.some((f) => typeof f?.fingerprint === 'string'))) {
      console.error('Error: --baseline requires a SrcAudit report.json with finding fingerprints.');
      process.exitCode = 2; return;
    }
  }
  let diff;
  try { diff = options.diff ? await changedFiles(options.src, options.diff) : undefined; }
  catch (error) { if (error instanceof DiffError) { console.error('Error: ' + error.message); process.exitCode = 2; return; } throw error; }
  const report = await scanSource(options.src, {
    analysis: options.deep ? 'deep' : 'quick', maxFiles: options['max-files'], maxFileBytes: options['max-bytes'],
    customRules, excludePaths: [outDir, ...(knowledgeDir ? [knowledgeDir] : [])],
    gitignore: !options['no-gitignore'],
    includeTests: options['include-tests'],
    ...(diff ? { onlyFiles: diff.files, diffInfo: { ref: options.diff, mergeBase: diff.base } } : {}),
  });
  if (baseline) applyBaseline(report, baseline, path.basename(options.baseline));
  enrichReport(report, writeups);
  if (!options.out) await pruneReports(reportsDir, { maxAgeMs: resolveRetentionMs() });
  const files = await writeReports(report, outDir);
  console.log(renderText(report));
  console.log(`\nHTML report: ${files.html}\nJSON report: ${files.json}\nText report: ${files.text}\nSARIF report: ${files.sarif}`);
  if (report.status !== 'complete') process.exitCode = 2;
  else if (options['fail-on'] && report.findings.some((f) => SEVERITIES.indexOf(f.severity) <= SEVERITIES.indexOf(options['fail-on']))) process.exitCode = 1;
}

main().catch(() => {
  // Filesystem errors can contain sensitive paths.
  console.error('Error: Could not complete the operation. Check paths, permissions and options. Run node scan.mjs --help for usage.');
  process.exitCode = 2;
});
