import { fork } from 'node:child_process';
import { mkdir, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanSource } from './source.mjs';
import { runSemgrep } from './semgrep.mjs';
import { prepareZipUpload, ZipInputError } from './uploads.mjs';
import { finishReport, ReportSizeError, writeReports } from './report.mjs';
import { enrichReport, loadWriteups } from './knowledge.mjs';

const workerFile = fileURLToPath(import.meta.url);
const interrupted = { error: 'Tiến trình quét bị gián đoạn hoặc vượt giới hạn thời gian.' };

export async function scanUpload({ directory, engineWorkspace, knowledgeDir, maxReportBytes }, onStage, semgrepRunner) {
  const workspace = path.join(directory, 'work');
  let uploaded;
  try {
    await rm(workspace, { recursive: true, force: true });
    await mkdir(workspace);
    const { content, job } = JSON.parse(await readFile(path.join(directory, 'input.json'), 'utf8'));
    uploaded = await prepareZipUpload(content, { temporaryDirectory: workspace });
    onStage(job.sourceAnalysis === 'deep' ? 'Semgrep và bộ kiểm tra dependency đang phân tích…' : 'Đang quét mã nguồn…');
    const report = await scanSource(uploaded.rootDir, {
      analysis: job.sourceAnalysis,
      semgrepRunner: semgrepRunner ?? ((files) => runSemgrep(files, { workspaceDirectory: engineWorkspace })),
    });
    report.target = 'Upload: ' + job.label;
    report.stats.uploadedFiles = uploaded.files;
    report.errors.push(...uploaded.warnings);
    finishReport(report);
    const writeups = await loadWriteups(knowledgeDir).catch((error) => {
      if (error.code === 'ENOENT') return [];
      throw error;
    });
    enrichReport(report, writeups, { maxWriteups: 3, maxReferences: 3 });
    await writeReports(report, directory, { maxTotalBytes: maxReportBytes });
    return { target: report.target, count: report.findings.length, scanStatus: report.status };
  } catch (error) {
    return { error: error instanceof ZipInputError || error instanceof ReportSizeError ? error.message
      : uploaded ? 'Lượt quét bị gián đoạn. Kiểm tra quyền ghi báo cáo hoặc thử lại với một mẫu nhỏ.'
        : 'Không đọc được nội dung ZIP. Hãy nén lại thư mục hoặc dùng chế độ Tải thư mục.' };
  }
}

export function runScanWorker(options, onStage) {
  return new Promise((resolve) => {
    const allowed = new Set(['PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'SYSTEMDRIVE', 'LANG', 'LC_ALL', 'SECURITYSCANNER_SEMGREP_EXE']);
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => allowed.has(key.toUpperCase())));
    const child = fork(workerFile, [], {
      cwd: path.dirname(workerFile), env, execArgv: [], stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
      windowsHide: true, timeout: 180_000,
    });
    let result;
    child.on('message', (message) => {
      if (typeof message.stage === 'string') onStage(message.stage);
      else if (message.result) result = message.result;
    });
    child.once('error', () => resolve(interrupted));
    child.once('exit', (code) => resolve(code === 0 && result ? result : interrupted));
    child.send(options, (error) => { if (error) child.kill(); });
  });
}

if (process.send && process.argv[1] === workerFile) {
  process.once('disconnect', () => process.exit(1));
  process.once('message', async (options) => {
    const result = await scanUpload(options, (stage) => process.send({ stage }));
    process.send({ result }, (error) => process.exit(error ? 1 : 0));
  });
}
