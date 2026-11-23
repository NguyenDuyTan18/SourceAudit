import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { matchedOperationAt, redactedSourceLines, sourceExcerptAt } from './source-excerpt.mjs';
import { reviewPythonFindings } from './python-precision.mjs';
import { isDockerfileName } from './scan-scope.mjs';

const execute = promisify(execFile);
const rulePaths = ['semgrep-js-ts.yml', 'semgrep-multilang.yml', 'semgrep-framework-config.yml'].map((name) =>
  fileURLToPath(new URL('../rules/' + name, import.meta.url)));
const bundled = fileURLToPath(new URL(process.platform === 'win32'
  ? '../.scanner-tools/semgrep/Scripts/semgrep.exe'
  : '../.scanner-tools/semgrep/bin/semgrep', import.meta.url));

const rules = new Map([
  ['srcaudit-js-sql-injection', {
    cwe: 'CWE-89', title: "Request data reaches a SQL query", severity: 'high',
    remediation: "Keep SQL fixed and bind values as parameters. Allowlist dynamic SQL identifiers.",
  }],
  ['srcaudit-js-command-injection', {
    cwe: 'CWE-78', title: "Request data reaches a shell command", severity: 'high',
    remediation: "Select a fixed executable and call it without a shell. Pass arguments separately and validate them.",
  }],
  ['srcaudit-js-ssrf', {
    cwe: 'CWE-918', title: "Request data controls an outbound HTTP URL", severity: 'medium',
    remediation: "Allowlist destinations. Validate the scheme, resolved addresses and each redirect, and restrict outbound traffic.",
  }],
  ['srcaudit-express-path-traversal', {
    cwe: 'CWE-22', title: "Request data controls an Express download path", severity: 'high',
    remediation: "Map input to approved files or resolve relative paths under a fixed root. Review symbolic links and permissions.",
  }],
  ['srcaudit-js-xss', {
    cwe: 'CWE-79', title: "Request data reaches an HTML response", severity: 'high',
    remediation: "Return structured data as JSON and use textContent for plain text. Encode values for their output context when rendering HTML.",
  }],
  ['srcaudit-express-open-redirect', {
    cwe: 'CWE-601', title: "Request data controls the redirect destination", severity: 'medium',
    impact: "Users may be sent from a trusted URL to an unintended destination.",
    remediation: "Map page identifiers to approved destinations. Validate the origin and path when accepting URLs.",
  }],
  ['srcaudit-js-nosql-injection', {
    cwe: 'CWE-943', title: "Request data controls a NoSQL filter or pipeline", severity: 'high',
    impact: "A user-supplied filter may change which records are read or modified.",
    remediation: "Build filters on the server with fixed fields and operators. Validate each value's type.",
  }],
  ['srcaudit-js-prototype-pollution', {
    cwe: 'CWE-1321', title: "Request data reaches an object merge or assignment", severity: 'medium',
    impact: "The effect depends on the merge or assignment, the library version and how the result is used.",
    remediation: "Copy only fields defined by the schema and reject unsafe keys recursively.",
  }],
  ['srcaudit-js-template-injection', {
    cwe: 'CWE-1336', title: "Request data reaches server-side template compilation", severity: 'high',
    impact: "A template engine processing untrusted template source may run unintended expressions.",
    remediation: "Use fixed templates and pass validated user input as template data.",
  }],
  ['srcaudit-js-code-injection', {
    cwe: 'CWE-95', title: "Request data is used as JavaScript code", severity: 'high',
    impact: "An evaluation API may run the input with the current process's permissions.",
    remediation: "Parse data with a schema or select allowed operations from a fixed table.",
  }],
  ['srcaudit-js-unsafe-deserialization', {
    cwe: 'CWE-502', title: "Request data reaches node-serialize.unserialize()", severity: 'high',
    impact: "The deserializer may restore objects with executable behavior. Review the library version and input.",
    remediation: "Use JSON.parse with schema validation. Copy only fields the application needs.",
  }],
  ['srcaudit-js-mass-assignment', {
    cwe: 'CWE-915', title: "Request data determines writable model properties", severity: 'medium',
    impact: "Users may modify fields beyond the intended set if model or authorization checks allow it.",
    remediation: "Allowlist writable properties, validate their types and enforce field-level authorization.",
  }],
]);

const sql = ['CWE-89', "Request data reaches a SQL query", 'high',
  "Keep SQL fixed and bind values. Allowlist dynamic SQL identifiers."];
const command = ['CWE-78', "Request data controls a command or executable", 'high',
  "Select a fixed executable, use a process API without a shell and validate separate arguments."];
const deserialization = ['CWE-502', "Request data reaches object deserialization", 'high',
  "Use schema-validated data formats such as JSON. Avoid reconstructing arbitrary objects from untrusted input."];
const additionalRules = {
  'srcaudit-python-flask-open-redirect': ['CWE-601', "Request data controls a Flask redirect", 'medium',
    "Map approved choices to fixed paths. Validate origin and destination when external redirects are required."],
  'srcaudit-python-flask-html-response': ['CWE-79', "Request data reaches a Flask HTML response", 'medium',
    "Use an autoescaping template and pass values through its context. Encode values for their output context."],
  'srcaudit-python-sax-external-entities': ['CWE-611', "Request XML reaches a parser with external entities enabled", 'high',
    "Disable external entity processing and reject DTDs where possible. Use a parser configured for untrusted XML."],
  'srcaudit-python-request-file-path': ['CWE-22', "Request data controls file access in Python", 'high',
    "Map approved choices to fixed files or constrain resolved paths to an approved root."],
  'srcaudit-python-request-dynamic-code': ['CWE-95', "Request data reaches a Python evaluation API", 'high',
    "Parse data with a schema or choose operations from a fixed list."],
  'srcaudit-python-lxml-xpath-injection': ['CWE-643', "Request data controls an lxml XPath expression", 'high',
    "Keep the XPath expression fixed and pass input through XPath variables."],
  'srcaudit-java-servlet-file-path': ['CWE-22', "Servlet request data controls file access", 'high',
    "Map approved choices to fixed files. If choosing a path is necessary, constrain the resolved path and account for symbolic links."],
  'srcaudit-java-servlet-html-response': ['CWE-79', "Servlet request data reaches an HTML response", 'medium',
    "Use an autoescaping template or encode data for the HTML, attribute or JavaScript context."],
  'srcaudit-js-file-write-path-traversal': ['CWE-22', "Request data controls a Node.js file write path", 'high',
    "Use server-generated names or map approved choices to fixed paths. Verify destination directories and symbolic links."],
  'srcaudit-python-requests-ssrf': ['CWE-918', "Request data controls a Python Requests URL", 'medium',
    "Map service names to fixed URLs or validate schemes, resolved addresses and redirects against the network policy."],
  'srcaudit-php-open-redirect': ['CWE-601', "Request data controls a PHP redirect", 'medium',
    "Map approved page names to internal paths. Validate origin and destination if external URLs are allowed."],
  'srcaudit-java-outbound-ssrf': ['CWE-918', "Request data controls an outbound Java URL", 'medium',
    "Use fixed destinations or validate the scheme, host, resolved addresses and redirects."],
  'srcaudit-python-flask-ssti': ['CWE-1336', "Request data reaches Flask template compilation", 'high',
    "Use fixed templates and pass user values through the template context."],
  'srcaudit-php-curl-ssrf': ['CWE-918', "Request data controls a PHP cURL destination", 'medium',
    "Map approved service names to fixed URLs. Validate the scheme, resolved addresses and redirects."],
  'srcaudit-go-path-traversal': ['CWE-22', "Request data controls a file path in Go", 'high',
    "Map allowed names to fixed paths or constrain access to an approved root."],
  'srcaudit-csharp-command-injection': command,
  'srcaudit-js-untrusted-module': ['CWE-470', "Request data chooses the JavaScript module to load", 'high',
    "Map approved request choices to modules with fixed paths."],
  'srcaudit-python-ldap-injection': ['CWE-90', "Request data controls an LDAP filter", 'high',
    "Keep the LDAP filter structure fixed. Use ldap3.utils.conv.escape_filter_chars for values."],
  'srcaudit-php-unsafe-deserialization': deserialization,
  'srcaudit-java-xpath-injection': ['CWE-643', "Request data reaches an XPath expression", 'high',
    "Use a fixed XPath expression and use XPathVariableResolver to supply values."],
  'srcaudit-go-log-injection': ['CWE-117', "Request data reaches a text log", 'medium',
    "Encode control characters or use a structured logger with a separate data field."],
  'srcaudit-csharp-ssrf': ['CWE-918', "Request data controls an HttpClient URL", 'medium',
    "Use fixed destinations or validate the scheme, host, resolved addresses and redirects."],
  'srcaudit-python-sql-injection': sql,
  'srcaudit-python-command-injection': command,
  'srcaudit-python-unsafe-deserialization': deserialization,
  'srcaudit-php-sql-injection': sql,
  'srcaudit-php-command-injection': command,
  'srcaudit-php-file-inclusion': ['CWE-98', "Request data controls which PHP file is loaded", 'high',
    "Map approved page names to fixed files and keep request input separate from include and require paths."],
  'srcaudit-java-sql-injection': sql,
  'srcaudit-java-command-injection': command,
  'srcaudit-java-unsafe-deserialization': deserialization,
  'srcaudit-go-sql-injection': sql,
  'srcaudit-go-command-injection': command,
  'srcaudit-go-ssrf': ['CWE-918', "Request data controls a Go HTTP client destination", 'medium',
    "Allowlist destinations and verify the scheme, resolved addresses and redirects."],
  'srcaudit-csharp-sql-injection': sql,
  'srcaudit-csharp-path-traversal': ['CWE-22', "Request data controls an ASP.NET file path", 'high',
    "Map approved choices to fixed files or constrain resolved paths to a trusted root."],
  'srcaudit-csharp-open-redirect': ['CWE-601', "Request data controls an ASP.NET redirect", 'medium',
    "Use LocalRedirect for internal destinations or select destinations from a fixed allowlist."],
  'srcaudit-spring-jdbc-template-sql-injection': sql,
  'srcaudit-laravel-raw-sql-injection': sql,
  'srcaudit-rails-http-ssrf': ['CWE-918', "Rails request parameters control an HTTP destination", 'high',
    "Map approved choices to fixed URLs or validate the scheme, host, resolved addresses and redirects."],
};
for (const [id, [cwe, title, severity, remediation]] of Object.entries(additionalRules)) {
  rules.set(id, { cwe, title, severity, remediation });
}

rules.set('srcaudit-github-actions-script-injection', {
  cwe: 'CWE-78', title: "GitHub Actions interpolates event data into a script", severity: 'high',
  evidence: "The run step contains an Actions expression for potentially user-controlled event data.",
  impact: "The expression is expanded before the shell parses the script. Input may change the command that runs with the job's permissions.",
  remediation: "Pass the value through the step's env: mapping and use the shell's quoted environment-variable syntax.",
});
rules.set('srcaudit-github-actions-token-write-all', {
  cwe: 'CWE-250', title: "GitHub Actions grants broad GITHUB_TOKEN write permissions", severity: 'medium',
  evidence: "The workflow or job sets permissions: write-all.",
  impact: "Steps may receive broader write access than their operations require.",
  condition: "Review permissions for the event and repository, including job-level overrides.",
  remediation: "Grant only the permissions used by each job. Start with contents: read where sufficient.",
  reference: 'https://docs.github.com/en/actions/reference/security/secure-use#using-least-privilege',
  status: 'observed',
});
rules.set('srcaudit-dockerfile-root-user', {
  cwe: 'CWE-250', title: "Final Dockerfile stage may run as root", severity: 'medium',
  evidence: "The final stage sets USER to root or 0, or omits USER with a base covered by the rule.",
  impact: "The process may receive more permissions than required if the runtime does not override the user.",
  remediation: "Set USER to a non-root account in the final stage. Give that account only the filesystem access it needs.",
});
rules.set('srcaudit-node-jwt-literal-verification-key', {
  cwe: 'CWE-321', title: "JWT verification uses a hardcoded HMAC key", severity: 'high',
  evidence: "The key argument is a literal and the configured algorithm is HMAC.",
  impact: "A reader who obtains a deployed symmetric key may be able to sign tokens the application accepts.",
  remediation: "Load the key from a secrets manager and restrict accepted algorithms. Rotate a key that was exposed.",
});

rules.set('srcaudit-python-flask-insecure-cookie', {
  cwe: 'CWE-614', title: "Flask response sets a cookie without Secure", severity: 'medium',
  evidence: "A Flask response calls set_cookie() without secure=True.",
  impact: "A browser may send the cookie over HTTP. Check whether it carries session or other sensitive data.",
  remediation: "Set secure=True for sensitive cookies and serve the application over HTTPS.",
  condition: "Review the final Set-Cookie header because a proxy or middleware may add the flag.",
  reference: 'https://flask.palletsprojects.com/en/stable/web-security/#set-cookie-options',
});

rules.set('srcaudit-python-weak-hashlib', {
  cwe: 'CWE-327', title: "Python hashlib uses MD5 or SHA-1", severity: 'low',
  evidence: "A hashlib call selects MD5 or SHA-1 without usedforsecurity=False.",
  impact: "MD5 and SHA-1 lack adequate collision resistance for security-sensitive use.",
  condition: "Determine whether the digest protects integrity or is used as a non-security checksum.",
  remediation: "Use SHA-256 or stronger when collision resistance is needed. Use Argon2id or scrypt for password hashing.",
  reference: 'https://docs.python.org/3/library/hashlib.html',
});
rules.set('srcaudit-python-tempfile-mktemp', {
  cwe: 'CWE-377', title: "Python generates a temporary filename without reserving it", severity: 'low',
  evidence: "The call resolves to tempfile.mktemp(), which returns a name without creating the file.",
  impact: "Another process with directory write access may claim the name before the application opens it.",
  condition: "Verify that the name is opened later and check write access to the temporary directory.",
  remediation: "Use NamedTemporaryFile() or mkstemp() to create and open the file atomically.",
  reference: 'https://docs.python.org/3/library/tempfile.html#tempfile.mktemp',
});
rules.set('srcaudit-python-unverified-tls-context', {
  cwe: 'CWE-295', title: "Python TLS context disables server verification", severity: 'medium',
  evidence: "The call resolves to ssl._create_unverified_context().",
  impact: "HTTPS connections using this context can accept an invalid certificate.",
  condition: "Verify that an outbound client connection uses this context and review its final settings.",
  remediation: "Use ssl.create_default_context() and configure the trusted CA if needed.",
  reference: 'https://peps.python.org/pep-0476/#opting-out',
});

rules.set('srcaudit-python-weak-random', {
  cwe: 'CWE-338', title: "Python uses a non-cryptographic random generator", severity: 'low',
  evidence: "The call resolves to a generator from the random module.",
  impact: "Predictable random values can weaken secrets, tokens and authentication codes.",
  condition: "Trace the result to a secret or security decision. The random module is suitable for simulations and other non-security uses.",
  remediation: "Use the secrets module or another cryptographic random source for security-sensitive values.",
  reference: 'https://docs.python.org/3/library/secrets.html',
});

const languageByExtension = new Map([
  ['.js', 'JavaScript'], ['.mjs', 'JavaScript'], ['.cjs', 'JavaScript'], ['.jsx', 'JavaScript'],
  ['.ts', 'TypeScript'], ['.tsx', 'TypeScript'], ['.py', 'Python'], ['.php', 'PHP'],
  ['.java', 'Java'], ['.go', 'Go'], ['.cs', 'C#'], ['.rb', 'Ruby'],
]);

export const SEMGREP_RULE_COUNT = rules.size;
export function semgrepLanguage(file) {
  if (isDockerfileName(path.basename(file))) return 'Dockerfile';
  if (/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(file)) return 'GitHub Actions';
  return languageByExtension.get(path.extname(file).toLowerCase());
}

export function semgrepExecutable() {
  return process.env.SECURITYSCANNER_SEMGREP_EXE || (existsSync(bundled) ? bundled : 'semgrep');
}

function languageCounts(staged, scanned = new Set()) {
  const languages = {};
  for (const [stagedPath, { language }] of staged) {
    const count = languages[language] ??= { selected: 0, scanned: 0 };
    count.selected++;
    if (scanned.has(stagedPath)) count.scanned++;
  }
  return languages;
}

function normalize(output, workspace, staged) {
  if (!Array.isArray(output?.results) || !Array.isArray(output.errors) || !Array.isArray(output.paths?.scanned)) {
    throw new Error('Invalid Semgrep output');
  }
  const resolve = (file) => typeof file === 'string' ? path.resolve(workspace, file) : undefined;
  const scanned = new Set(output.paths.scanned.map(resolve).filter((file) => staged.has(file)));
  const findings = [];
  const seen = new Set();
  const excerpts = new Map();
  for (const result of output.results) {
    const rule = rules.get(result?.check_id);
    const stagedPath = resolve(result?.path);
    const line = result?.start?.line;
    const column = result?.start?.col;
    if (!rule || !scanned.has(stagedPath) || !Number.isSafeInteger(line) || line < 1 ||
        !Number.isSafeInteger(column) || column < 1) continue;
    const { file, text } = staged.get(stagedPath);
    const endLine = result.end?.line;
    const endColumn = result.end?.col;
    const multiline = Number.isSafeInteger(endLine) && endLine > line &&
      Number.isSafeInteger(endColumn) && endColumn >= 1;
    const id = JSON.stringify([result.check_id, file, line, column]);
    if (seen.has(id)) continue;
    seen.add(id);
    if (!excerpts.has(stagedPath)) excerpts.set(stagedPath, {
      redacted: redactedSourceLines(file, text),
      original: text.length <= 256 * 1024 ? text.split(/\r?\n/) : undefined,
    });
    const lastMarkedLine = multiline ? endLine - (endColumn === 1 ? 1 : 0) : line;
    const { redacted, original } = excerpts.get(stagedPath);
    const sourceExcerpt = sourceExcerptAt(redacted, line, lastMarkedLine);
    const matchedOperation = sourceExcerpt ? undefined : matchedOperationAt(original, line, column);
    const { condition, ...details } = rule;
    const structural = Boolean(rule.evidence);
    findings.push({
      ...details, ruleId: result.check_id, confidence: 'medium', status: rule.status ?? 'needs-review',
      location: { file, line, column, ...(multiline ? { endLine, endColumn } : {}) },
      ...(sourceExcerpt ? { sourceExcerpt } : {}),
      ...(matchedOperation ? { matchedOperation } : {}),
      evidence: rule.evidence ?? 'Semgrep traced request data to a sensitive argument. Open the location to review the original code.',
      impact: rule.impact ?? 'The impact depends on input validation and runtime context.',
      reference: rule.reference ?? 'https://cwe.mitre.org/data/definitions/' + rule.cwe.slice(4) + '.html',
      detection: structural
        ? { method: 'semgrep-pattern', condition: condition ?? 'Review this pattern alongside deployed configuration and runtime behavior.' }
        : { method: 'semgrep-taint', condition: 'Verify the reported data flow, input validation and runtime configuration.' },
    });
  }
  const partial = output.errors.length > 0 || scanned.size < staged.size;
  return {
    status: partial ? 'partial' : 'complete',
    scanned: scanned.size,
    languages: languageCounts(staged, scanned),
    findings,
    message: partial ? 'Semgrep reported analysis errors or skipped selected files.' : undefined,
  };
}

export async function runSemgrep(files, { executable = semgrepExecutable(), run = execute, workspaceDirectory } = {}) {
  const workspace = workspaceDirectory ?? await mkdtemp(path.join(tmpdir(), 'scanner-semgrep-'));
  if (workspaceDirectory) await mkdir(workspace, { mode: 0o700 });
  const staged = new Map();
  try {
    await mkdir(path.join(workspace, 'targets'));
    for (const { file, text, language = semgrepLanguage(file) } of files) {
      if (!language) continue;
      const slot = String(staged.size + 1);
      let stagedName = slot + path.extname(file).toLowerCase();
      // Preserve only the structure needed by the parser and path filters.
      if (language === 'GitHub Actions') stagedName = path.join(slot, '.github', 'workflows', 'workflow.yml');
      if (language === 'Dockerfile') stagedName = path.join(slot, 'Dockerfile');
      const stagedPath = path.join(workspace, 'targets', stagedName);
      if (language === 'GitHub Actions' || language === 'Dockerfile') {
        await mkdir(path.dirname(stagedPath), { recursive: true });
      }
      await writeFile(stagedPath, text, { mode: 0o600, flag: 'wx' });
      staged.set(stagedPath, { file, text, language });
    }
    // Keep the child independent of user Semgrep settings, tokens and project configuration.
    const allowed = new Set(['PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'SYSTEMDRIVE', 'LANG', 'LC_ALL']);
    const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => allowed.has(key.toUpperCase())));
    Object.assign(env, {
      HOME: workspace, USERPROFILE: workspace, APPDATA: workspace, LOCALAPPDATA: workspace,
      TMP: workspace, TEMP: workspace, TMPDIR: workspace,
      SEMGREP_SETTINGS_FILE: path.join(workspace, 'settings.yml'),
      PYTHONUTF8: '1',
    });
    const args = [
      'scan', ...rulePaths.flatMap((file) => ['--config', file]), '--metrics=off', '--disable-version-check',
      '--no-rewrite-rule-ids', '--disable-nosem', '--no-git-ignore',
      '--max-target-bytes=0', '--jobs=1', '--timeout=5', '--timeout-threshold=1',
      '--json', '--quiet', 'targets',
    ];
    const { stdout } = await run(executable, args, {
      cwd: workspace, env, timeout: 90_000, maxBuffer: 4 * 1024 * 1024, windowsHide: true,
    });
    const result = normalize(JSON.parse(stdout), workspace, staged);
    return await reviewPythonFindings(result, staged, { executable, workspace, env, args, run });
  } catch (error) {
    let message = 'Semgrep did not complete. Check the installation and scan limits.';
    if (error.code === 'ENOENT') message = 'Semgrep executable not found. Install Semgrep CE or set SECURITYSCANNER_SEMGREP_EXE.';
    else if (error.killed) message = 'Semgrep exceeded the 90-second analysis time limit.';
    return { status: 'failed', scanned: 0, languages: languageCounts(staged), findings: [], message };
  } finally {
    await rm(workspace, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
  }
}
