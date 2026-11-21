# SrcAudit quickstart

SrcAudit scans local source code and dependency lockfiles. It runs on Windows, Linux and macOS with Node.js 22 or later. Install Semgrep CE separately if you need deep scanning.

## Install and open the interface

```sh
git clone https://github.com/NguyenDuyTan18/SourceAudit.git
cd SourceAudit
npm ci --ignore-scripts
npm start
```

Open the loopback address printed by the server. Pick a source directory or ZIP archive, choose **Quét nhanh** for a quick scan, and select **Bắt đầu kiểm tra**. On Windows, `Start-UI.cmd` opens the interface after dependencies are installed. If PowerShell blocks `npm.ps1`, use `npm.cmd` with the same arguments.

## Try the CLI

```sh
node scan.mjs --src ./examples/demo-src --out ./.scanner-reports/first-scan
```

Open `report.html` in the output directory. The same scan writes JSON, text and SARIF. Use `node scan.mjs --help` for options. Exit code `0` means the selected scan completed. `--fail-on high` returns code `1` when a finding reaches the threshold. Code `2` indicates invalid input or an incomplete scan.

## Enable deep scanning

Install Semgrep CE 1.184.0 into the project's virtual environment, or make `semgrep` available on `PATH`. The project [README](../README.md#cài-semgrep-ce-tùy-chọn) gives the Windows and Unix install commands. Select **Phân tích sâu bằng Semgrep** in the interface or add `--deep` to the CLI command.

## Read and share results

- Findings show a location, evidence, conditions to review, and remediation. Check the scan status and its scope before interpreting an empty result.
- Normal scanning runs on your machine. Initial installation, knowledge refresh, and downloading benchmark datasets use the network. Review reports before sharing them because project paths and file context can be sensitive.
- For CI, start with the [SARIF workflow example](ci/github-code-scanning.yml). Use `--diff` or `--baseline` if the workflow only needs new findings.
- See [benchmark results](testing/accuracy.md) for measured precision and recall on labeled datasets, and the [security policy](../SECURITY.md) for reporting vulnerabilities in SrcAudit itself.
