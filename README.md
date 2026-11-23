# SrcAudit

[Tiếng Việt](README.vi.md)

SrcAudit is a local static application security testing tool. It scans source code and dependency lockfiles, then reports locations, redacted evidence and remediation guidance.

[Docker quickstart](#run-with-docker-compose) · [Node.js setup](#run-directly-with-nodejs) · [Scan coverage](#scan-modes) · [CLI and CI](#cli-and-ci) · [Contributing](#verification-and-contributions)

## Run with Docker Compose

Install Docker with Compose v2. Docker Desktop includes both on Windows, macOS and Linux. The image includes Node.js and Semgrep CE.

```sh
git clone https://github.com/NguyenDuyTan18/SourceAudit.git
cd SourceAudit
docker compose up --build -d
```

Open [http://127.0.0.1:8787](http://127.0.0.1:8787). Choose **Upload ZIP** or **Upload folder**, select **Quick scan** or **Deep scan with Semgrep**, and select **Start scan**. Try the bundled `examples/demo-src` directory. The browser sends the selected source to the local container. Initial image builds download dependencies. Scans use bundled rules and advisory snapshots.

The Compose service publishes on the host loopback address. It starts without registration or sign-in. Reports, scan history and imported write-up indexes persist in the `srcaudit-data` volume when you stop or recreate the container.

| Task | Command |
| --- | --- |
| Check status | `docker compose ps` |
| Read logs | `docker compose logs srcaudit` |
| Stop the app and keep its data | `docker compose down` |
| Rebuild after updating the checkout | `docker compose up --build -d` |

If port 8787 is busy, add `SRCAUDIT_PORT=8797` to a local `.env` file and open [http://127.0.0.1:8797](http://127.0.0.1:8797) after starting Compose. Running `docker compose down --volumes` permanently removes the Compose data volume, including stored reports and notes.

### Docker CLI

Run a bundled demo using the same image as the web app.

```sh
docker compose run --rm srcaudit node scan.mjs --src /app/examples/demo-src --deep --out /var/lib/srcaudit/demo-report
docker compose cp srcaudit:/var/lib/srcaudit/demo-report ./demo-report
```

The copy command uses the running web container to read the shared volume. Open `demo-report/report.html`. To scan a host directory from the CLI, bind mount it read-only. Run this example from the checkout in PowerShell or a POSIX shell.

```sh
docker compose run --rm --volume "${PWD}/examples/demo-src:/input:ro" srcaudit node scan.mjs --src /input --deep
```

Replace `${PWD}/examples/demo-src` with the absolute source directory. CLI output without `--out` is stored under `/var/lib/srcaudit/.scanner-reports/` in Docker.

## Run directly with Node.js

Install Node.js 22 or later. From the checkout, run:

```sh
npm ci --ignore-scripts
npm start
```

Open the loopback address shown in the terminal. On Windows, `Start-UI.cmd` opens the browser after dependency installation. If PowerShell blocks `npm.ps1`, use `npm.cmd`.

### Install Semgrep CE for native Deep Scan

On Windows:

```powershell
py -m venv .scanner-tools/semgrep
.\.scanner-tools\semgrep\Scripts\python.exe -m pip install semgrep==1.184.0
```

On Linux or macOS:

```sh
python3 -m venv .scanner-tools/semgrep
./.scanner-tools/semgrep/bin/python -m pip install semgrep==1.184.0
```

SrcAudit checks `SECURITYSCANNER_SEMGREP_EXE`, the bundled virtual environment path, then `semgrep` on `PATH`. [Semgrep CE installation](https://semgrep.dev/docs/getting-started/quickstart-ce)

### Optional native remote access

Native starts in local mode. An existing owner can continue using their previous local history. To use remote access on a native install, set `SRCAUDIT_ENABLE_REMOTE=1`, create a `.ui-public.json` file with `{"origin":"https://your-domain.example"}`, and restart the app. Create the owner account through the local address before connecting the HTTPS proxy. The owner manages members under **Accounts**. Reports, queue entries and write-up indexes belong to the corresponding account. Legacy public configurations with credentials are supported. The Docker Compose setup is local only.

## Scan modes

| Mode | Coverage |
| --- | --- |
| **Quick Scan** | Source signatures, short local data flows, credentials, GitHub Actions and Docker Compose configuration, plus dependency advisories. |
| **Deep Scan** | Bundled Semgrep CE rules for JS/TS, Python, PHP, Java, Go, C#, Ruby, GitHub Actions and Dockerfiles, plus dependency advisories. |

### What Quick Scan checks

- **Source and data flow** includes SQL injection, unsafe HTML output, command execution, outbound requests and file paths. Selected JS/TS findings receive a syntax-tree check, including PostgreSQL query objects that pass fixed SQL and bound values separately.
- **Credentials and configuration** includes likely embedded secrets, TLS settings, broad GitHub Actions token permissions and Docker Compose services that disable seccomp or AppArmor confinement. Clear secret references are filtered, explicit placeholders appear as informational, and literal fallbacks remain eligible for review.
- **Dependencies** includes resolved versions from npm, Yarn, pnpm, pinned Python requirements, Pipenv, Poetry and Composer. Both modes match these versions against the bundled advisory snapshot.

Run `node scan.mjs --list-rules` to see the current Quick Scan rule IDs, CWE mappings and severities. Source findings require review in context. Dependency findings report a version match, with deployment and usage left for review. [Rule coverage and supported lockfiles](docs/RULES.md#quick-scan) · [Data and licenses](data/README.md) · [Sources](SOURCES.md)

## CLI and CI

```sh
node scan.mjs --src ./examples/demo-src --out ./reports/demo
node scan.mjs --src ./app --deep --fail-on high
node scan.mjs --src . --diff origin/main --fail-on high
node scan.mjs --src . --baseline ./reports/demo/report.json --fail-on high
node scan.mjs --list-rules
node scan.mjs --knowledge CWE-89
node scan.mjs --help
```

| Option | Use |
| --- | --- |
| `--src PATH` | Scan a local file or directory. |
| `--out DIR` | Write to a specific report directory. Otherwise use a timestamped directory under `.scanner-reports/`. |
| `--deep` | Run bundled Semgrep rules. |
| `--diff REF` | Scan files changed since the merge base of REF and HEAD, including untracked files. Requires Git and sufficient history. |
| `--baseline FILE` | Compare finding fingerprints with an earlier `report.json`. |
| `--no-gitignore`, `--include-tests` | Include ignored files or test code, respectively. |
| `--max-bytes N`, `--max-files N` | Limit individual file size and file count within the supported bounds. |
| `--rules FILE` | Load up to 100 custom literal rules for Quick Scan. |
| `--import-writeup FILE` | Import a text or Markdown write-up up to 1 MiB. Use `--knowledge-dir DIR` to choose where the index is stored or loaded. |

Exit code `0` means the scan completed, `1` means a finding met the threshold passed to `--fail-on`, and `2` means invalid input or an incomplete scan. Use `report.sarif` with a SARIF viewer or a code-scanning workflow. [GitHub Actions example](docs/ci/github-code-scanning.yml)

A suppression must have a reason after `--`. Add it on the affected line or on the preceding line. Suppressed results remain in the report for review.

```js
db.query(sql); // srcaudit-ignore SRC-SQL -- SQL is a fixed internal query
```

A baseline marks a previously reported finding as fixed only when the same mode assessed the file. Findings in skipped or unscanned files count as unassessed. Check coverage before interpreting an empty result.

## Reports, data and limits

Each scan writes HTML, JSON, text and SARIF. Findings show the rule and CWE, location, evidence, impact and remediation. A dependency advisory match identifies an affected version. Review deployment and reachability to assess applicability. Review source excerpts and paths before sharing reports.

| Setting | Default |
| --- | --- |
| Source selection | 2,000 files and 10 MiB per file |
| Total source size | 50 MiB for web uploads and Deep Scan |
| ZIP | 50 MiB compressed and at most 10,000 entries |
| Semgrep scan timeout | 90 seconds |
| `SRCAUDIT_REPORT_RETENTION_DAYS` | 7 days. Set to `0` to disable automatic report cleanup. |
| `SRCAUDIT_ACCOUNT_STORAGE_MIB` | 128 MiB per web workspace, including queued uploads and reports. |

Set Docker options in a local `.env` file before starting Compose. For native use, set the corresponding environment variables before starting the process. Native reports default to `.scanner-reports/`, with web history stored per workspace. Automatic cleanup applies to app-managed report folders and to timestamped CLI reports in the default output directory.

Symlinks, binary files, common dependency and build directories, and tests are skipped by default. CLI scans honor nested `.gitignore` files. ZIP extraction accepts store and deflate entries and rejects unsafe paths. Deep Scan primarily follows data within functions. Oversized inputs and skipped coverage are recorded in the report.

## Verification and contributions

```sh
npm test
npm run test:coverage
npm run benchmark:semgrep
npm run benchmark:check
```

[Benchmark results](docs/testing/accuracy.md) include precision, recall and false-positive rates by labeled dataset and mode. New rules should include a reference, a matched example, a corrected example and expected CWE and location. Report bugs with the scan mode, tool versions and a minimal sanitized example.

MIT licensed. [Security policy](SECURITY.md) · [Data notices](data/NOTICE.md)
