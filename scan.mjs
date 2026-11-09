#!/usr/bin/env node
import path from 'node:path';
import { scanSource, SOURCE_RULES } from './src/source.mjs';
import { renderText, writeReports, SEVERITIES } from './src/report.mjs';
import { pruneReports, resolveRetentionMs } from './src/report-retention.mjs';
import { searchKnowledge, importWriteup, loadCustomRules, loadWriteups, enrichReport } from './src/knowledge.mjs';

const HELP = `SrcAudit — Phân tích tĩnh mã nguồn (Node.js >= 22).

Quét và xuất report.txt, report.json, report.html:
  node scan.mjs --src "D:\\path\\to\\source" --out ./reports/run-2
  node scan.mjs --src ./app --deep
  node scan.mjs "D:\\path\\to\\source"

Tra cứu và bổ sung input:
  node scan.mjs --list-rules
  node scan.mjs --knowledge sqli
  node scan.mjs --import-writeup ./notes.md --knowledge-dir ./knowledge-local
  node scan.mjs --src ./app --rules ./examples/custom-rules.json --knowledge-dir ./knowledge-local

Tùy chọn:
  --max-bytes N       Giới hạn mỗi file, mặc định 1048576 (100..10485760)
  --max-files N       Giới hạn file source, mặc định 2000, tối đa 20000
  --deep              Phân tích luồng bằng Semgrep: JS/TS, Python, PHP, Java, Go và C#
  --fail-on LEVEL    Exit 1 khi có severity >= critical/high/medium/low/info
  --out DIR          Thư mục báo cáo (mặc định .scanner-reports/<timestamp>)

Báo cáo trong .scanner-reports/ cũ hơn SRCAUDIT_REPORT_RETENTION_DAYS ngày
(mặc định 7, đặt 0 để tắt) được tự xóa khi dùng thư mục mặc định.
  --help             Hướng dẫn

Exit 0: hoàn tất (vẫn có thể có phát hiện); 1: đạt ngưỡng --fail-on;
Exit 2: input lỗi hoặc phạm vi kiểm tra không hoàn tất.
Chỉ kiểm tra hệ thống thuộc quyền sở hữu hoặc được phép kiểm thử.
Quét nhanh dò mẫu mã nguồn. Quét sâu dùng Semgrep CE.
`;

function parseArgs(args) {
  const values = new Set(['src', 'out', 'max-bytes', 'max-files', 'fail-on', 'rules', 'knowledge', 'import-writeup', 'knowledge-dir']);
  const flags = new Set(['help', 'list-rules', 'deep']);
  const options = {};
  let positional;
  for (let i = 0; i < args.length; i++) {
    if (!args[i].startsWith('--')) {
      if (positional) throw new Error('Chỉ nhận một mục tiêu mỗi lần.');
      positional = args[i]; continue;
    }
    const key = args[i].slice(2);
    if (Object.hasOwn(options, key)) throw new Error(`Tùy chọn lặp: --${key}`);
    if (flags.has(key)) options[key] = true;
    else if (values.has(key)) {
      const value = args[++i];
      if (!value || value.startsWith('--')) throw new Error(`Thiếu giá trị --${key}`);
      options[key] = value;
    } else throw new Error(`Tùy chọn không hỗ trợ: --${key}`);
  }
  if (positional) {
    if (options.src) throw new Error('Không kết hợp mục tiêu vị trí với --src.');
    options.src = positional;
  }
  if (options.src && /^[a-z][a-z\d+.-]+:\/\//i.test(options.src.trim())) throw new Error('--src nhận đường dẫn mã nguồn trên máy.');
  const numeric = { 'max-bytes': [100, 10485760], 'max-files': [1, 20000] };
  for (const [key, [min, max]] of Object.entries(numeric)) {
    if (options[key] !== undefined) {
      const value = Number(options[key]);
      if (!Number.isInteger(value) || value < min || value > max) throw new Error(`--${key} phải là số nguyên ${min}..${max}.`);
      options[key] = value;
    }
  }
  if (options['fail-on'] && !SEVERITIES.includes(options['fail-on'])) throw new Error('--fail-on không hợp lệ.');
  if (!options.help && ['src', 'knowledge', 'list-rules', 'import-writeup'].filter((key) => options[key] !== undefined).length !== 1) throw new Error('Chọn đúng một thao tác: --src, --knowledge, --list-rules, --import-writeup.');
  if (options.deep && (!options.src || options.rules)) throw new Error('--deep cần --src và chỉ dùng các rule Semgrep tích hợp.');
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) { console.log(HELP); return; }
  if (options['list-rules']) { console.log(JSON.stringify({ source: SOURCE_RULES }, null, 2)); return; }
  if (options.knowledge !== undefined) { console.log(JSON.stringify(searchKnowledge(options.knowledge), null, 2)); return; }
  const knowledgeDir = options['knowledge-dir'] ? path.resolve(options['knowledge-dir']) : undefined;
  if (options['import-writeup']) { console.log(JSON.stringify(await importWriteup(options['import-writeup'], knowledgeDir ?? 'knowledge-local'), null, 2)); return; }
  if (options.rules && !options.src) throw new Error('--rules hiện chỉ áp dụng cho source.');
  const outDir = path.resolve(options.out ?? path.join('.scanner-reports', new Date().toISOString().replace(/[:.]/g, '-')));
  const customRules = options.rules ? await loadCustomRules(options.rules) : [];
  const writeups = await loadWriteups(knowledgeDir);
  const report = await scanSource(options.src, {
    analysis: options.deep ? 'deep' : 'quick', maxFiles: options['max-files'], maxFileBytes: options['max-bytes'],
    customRules, excludePaths: [outDir, ...(knowledgeDir ? [knowledgeDir] : [])],
  });
  enrichReport(report, writeups);
  if (!options.out) await pruneReports(path.resolve('.scanner-reports'), { maxAgeMs: resolveRetentionMs() });
  const files = await writeReports(report, outDir);
  console.log(renderText(report));
  console.log(`\nBáo cáo HTML: ${files.html}\nBáo cáo JSON: ${files.json}\nBáo cáo TXT: ${files.text}`);
  if (report.status !== 'complete') process.exitCode = 2;
  else if (options['fail-on'] && report.findings.some((f) => SEVERITIES.indexOf(f.severity) <= SEVERITIES.indexOf(options['fail-on']))) process.exitCode = 1;
}

main().catch(() => {
  // Filesystem errors can contain sensitive paths.
  console.error('Lỗi: input/tùy chọn không hợp lệ hoặc không đọc/ghi được dữ liệu. Chạy node scan.mjs --help; kiểm tra đường dẫn, quyền và giới hạn tùy chọn.');
  process.exitCode = 2;
});
