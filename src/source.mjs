import { lstat, readdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { createReport, finishReport, SEVERITIES } from './report.mjs';
import { EXTENDED_RULES } from './extended-rules.mjs';
import { SCENARIO_RULES } from './scenario-rules.mjs';
import { analyzeFlow, FLOW_RULES } from './flow.mjs';
import { extractDependencies, dependencyFindings, isDependencyManifest } from './dependencies.mjs';
import { corpusStats } from './corpus.mjs';
import { runSemgrep, semgrepLanguage, SEMGREP_RULE_COUNT } from './semgrep.mjs';
import { isIgnored, parseGitignore } from './gitignore.mjs';
import { applySuppressions, assignFingerprints, collectSuppressions } from './triage.mjs';
import { pathKey } from './git-diff.mjs';
import { filterWithAst } from './ast-filter.mjs';
import { applyFileContext, classifySecret } from './context.mjs';
import { isDockerfileName, isTestPath, MAX_SOURCE_FILE_BYTES, MAX_SOURCE_FILES, MAX_SOURCE_TOTAL_BYTES, MIB } from './scan-scope.mjs';
import { explicitlyInsecureCookie } from './python-quick.mjs';

const SKIP = new Set(['.git', '.svn', 'node_modules', '.venv', 'venv', '__pycache__', 'vendor', 'dist', 'build', 'coverage', '.next', '.scanner-reports', '.scanner-tools', '.scanner-auth']);
const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.php', '.java', '.cs', '.go', '.rb', '.html', '.htm', '.vue', '.svelte', '.astro', '.css', '.scss', '.sass', '.less', '.xml', '.svg', '.sql', '.graphql', '.gql', '.razor', '.cshtml', '.ejs', '.hbs', '.erb', '.jsp', '.kt', '.kts', '.rs', '.ex', '.exs', '.erl', '.dart', '.sh', '.ps1']);
const CONFIG_EXT = new Set(['.json', '.yaml', '.yml', '.toml', '.ini', '.conf', '.config', '.properties', '.pem', '.key', '.env', '.lock', '.mod']);
export const SUPPORTED_SOURCE_EXTENSIONS = [...CODE_EXT, ...CONFIG_EXT];
export function isSupportedSourceFile(name) {
  return CODE_EXT.has(path.extname(name).toLowerCase()) || CONFIG_EXT.has(path.extname(name).toLowerCase()) || path.basename(name).startsWith('.env') || isDockerfileName(path.basename(name)) || /^requirements(?:[.-].*)?\.txt$/i.test(path.basename(name));
}
const ref = (cwe) => `https://cwe.mitre.org/data/definitions/${cwe}.html`;
const rules = [
  { id: 'SRC-SSRF', cwe: 918, severity: 'medium', title: "HTTP client receives a URL from the request", match: /\b(?:fetch|axios\.(?:get|post|request)|requests\.(?:get|post)|urllib\.request\.urlopen)\s*\([^\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|GET|POST))/, impact: "An unrestricted destination may let the server access unintended resources.", fix: "Allowlist destinations. Validate the scheme, resolved addresses and each redirect, and restrict outbound network access." },
  { id: 'SRC-PATH', cwe: 22, severity: 'medium', title: "File API receives a path from the request", match: /\b(?:readFile(?:Sync)?|sendFile|send_file|open|file_get_contents)\s*\([^\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|GET|POST)|\$_(?:GET|POST|REQUEST))/, impact: "An unchecked path may resolve outside the allowed directory.", fix: "Resolve the path and verify it stays under an allowed root. Account for symbolic links and file permissions." },
  { id: 'SRC-SSTI', cwe: 1336, severity: 'high', title: "Server-side template uses request data as source", match: /\b(?:render_template_string|from_string|ejs\.render)\s*\([^\n]*(?:req\.|request\.)/, impact: "The template engine may evaluate expressions supplied by a user.", fix: "Use a fixed template and pass user input as data. Review the template engine and its sandbox configuration." },
  { id: 'SRC-PROTOTYPE', cwe: 1321, severity: 'medium', title: "Request data is used in an object merge or property assignment", match: /\b(?:merge|defaultsDeep|extend)\s*\([^\n]*(?:req\.body|request\.body)|\[\s*(?:req\.(?:query|body|params)[^\]]*)\]\s*=/, impact: "An unsafe merge or assignment may modify object prototypes, depending on the library and how it is used.", fix: "Allowlist fields recursively and reject dangerous keys. Review the merge library and version." },
  { id: 'SRC-XXE', cwe: 611, severity: 'medium', title: "XML parser enables external entities", match: /\bresolve_entities\s*=\s*True\b|\bLIBXML_NOENT\b|\bXmlResolver\s*=\s*new\s+XmlUrlResolver/, impact: "The parser may access files or the network with the application's permissions.", fix: "Disable external entities and DTD processing according to the XML parser's configuration." },
  { id: 'SRC-JWT', cwe: 347, severity: 'high', title: "JWT signature validation is disabled", match: /\bverify_signature["']?\s*[:=]\s*(?:False|false)\b|\bjwt\.decode\s*\([^\n]*\bverify\s*=\s*False/, impact: "Tokens with missing or invalid signatures may be trusted for authentication or authorization.", fix: "Verify the signature and allowlist algorithms. Check the issuer, audience and expiration before trusting claims." },
  { id: 'SRC-EVAL', cwe: 95, severity: 'high', title: "Dynamic code execution requires review", match: /\b(?:eval|exec)\s*\(/, exts: ['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.py', '.php'], impact: "User-controlled data may execute as code with the application's permissions.", fix: "Use a data parser or a fixed set of operations in place of dynamic evaluation." },
  { id: 'SRC-SHELL', cwe: 78, severity: 'high', title: "Shell or system command requires review", match: /\b(?:child_process\s*\.\s*exec|execSync|os\s*\.\s*system|shell_exec|passthru|(?<![.\w])system)\s*\(|\bshell\s*=\s*True\b|\b(?:exec|execFile)\s*\([^\n]*(?:req\.|request\.|\$_(?:GET|POST|REQUEST))/, impact: "Untrusted data embedded in a command can change what runs.", fix: "Use a process API with a separate argument list and no shell. Allowlist programs and validate arguments." },
  { id: 'SRC-SQL', cwe: 89, severity: 'high', title: "SQL string construction requires review", match: /\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n]*(?:\+|\$\{|\s\.\s|\$_(?:GET|POST|REQUEST))|\b(?:execute|query)\s*\(\s*f["']/, impact: "Concatenating untrusted input into SQL may change the query.", fix: "Use parameterized queries or prepared statements. Allowlist dynamic SQL identifiers." },
  { id: 'SRC-XSS', cwe: 79, severity: 'medium', title: "HTML output may expose an XSS risk", match: /\.\s*(?:innerHTML|outerHTML)\s*=|\bdangerouslySetInnerHTML\s*[:=]|\bdocument\.write\s*\(|\bres\.(?:send|write)\s*\([^\n]*(?:req\.|request\.)|\becho\s+\$_(?:GET|POST|REQUEST)/, impact: "Unescaped or unsanitized data may run as script in a browser.", fix: "Use textContent or contextual output encoding. Sanitize HTML when the application must accept markup." },
  { id: 'SRC-DESERIALIZE', cwe: 502, severity: 'high', title: "Deserialization of untrusted data requires review", match: /\b(?:pickle\.loads?|unserialize)\s*\(|\byaml\.load\s*\((?![^\n]*(?:SafeLoader|BaseLoader))/, impact: "The deserializer may construct unexpected objects or execute unintended code.", fix: "Use a schema-validated data format or a safe loader that cannot construct arbitrary objects." },
  { id: 'SRC-TLS-VERIFY', cwe: 295, severity: 'medium', title: "TLS certificate verification is disabled", match: /\brejectUnauthorized\s*:\s*false\b|\bverify\s*=\s*False\b|\bNODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0\b|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)/, impact: "The client may accept a server presenting an invalid certificate.", fix: "Enable certificate and hostname verification. Configure a trusted CA if needed." },
  { id: 'SRC-PY-TLS-CONTEXT', cwe: 295, severity: 'medium', title: "Python TLS context disables server verification", exts: ['.py'], match: /\bssl\._create_unverified_context\s*\(/, impact: "HTTPS connections using this context can accept an invalid certificate.", fix: "Use ssl.create_default_context() and configure the trusted CA if needed.", condition: "Verify the context is used for an outbound client connection and review its final settings.", reference: 'https://peps.python.org/pep-0476/#opting-out' },
  { id: 'SRC-PY-INSECURE-COOKIE', cwe: 614, severity: 'low', title: "Python set_cookie() uses secure=False", exts: ['.py'], match: /\.set_cookie\s*\(/, check: explicitlyInsecureCookie, impact: "A browser may send the cookie over HTTP.", fix: "Set secure=True for sensitive cookies served over HTTPS.", condition: "Review the cookie's purpose and the final Set-Cookie header in the deployed application.", reference: 'https://flask.palletsprojects.com/en/stable/web-security/#set-cookie-options' },
  { id: 'SRC-PY-WEAK-RANDOM', cwe: 338, severity: 'low', title: "Python uses a non-cryptographic random generator", exts: ['.py'], match: /(?<![\w.])random\.(?:getrandbits|randbytes|random|randint|randrange|choice|choices|sample|shuffle|uniform|normalvariate)\s*\(/, impact: "Predictable random values weaken secrets, tokens and authentication codes.", fix: "Use the secrets module or another cryptographic random source for security-sensitive values.", condition: "Trace the result to a secret or security decision. The random module is suitable for simulations and other non-security uses.", reference: 'https://docs.python.org/3/library/secrets.html' },
  { id: 'SRC-DEBUG', cwe: 489, severity: 'low', title: "Debug mode is enabled", match: /\bdebug\s*[:=]\s*(?:true|True|1)\b|\b(?:APP_DEBUG|DEBUG)\s*=\s*(?:true|True|1)\b/, impact: "A production service may expose internal details or verbose errors.", fix: "Disable debug mode in production and verify the deployed configuration." },
  { id: 'SRC-HASH', cwe: 327, severity: 'low', title: "Use of MD5 or SHA-1 requires review", match: /\b(?:md5|sha1)\s*\(|\b(?:createHash|hashlib\.new)\s*\(\s*(["'])(?:[mM][dD]5|[sS][hH][aA]1)\1/, impact: "These digests lack adequate collision resistance for security-sensitive use.", fix: "Use SHA-256 or stronger for collision resistance. Use Argon2id or scrypt for password hashing.", condition: "Determine whether the digest protects integrity or participates in authentication, or is used as a non-security checksum." },
  { id: 'SRC-SECRET', cwe: 798, severity: 'high', title: "Possible embedded credential", secret: true, match: /(?:["']?\b(?:password|passwd|api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["'][^"'\r\n]{8,}["'])|(?:\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{24,}|sk_live_[A-Za-z0-9]{16,})\b)/i, impact: "A real credential in source may allow readers to access protected resources.", fix: "Confirm whether the value is a credential. If confirmed, revoke or rotate it and move it to a secrets manager or runtime configuration." },
  { id: 'SRC-PRIVATE-KEY', cwe: 321, severity: 'high', title: "Possible private key in source", secret: true, match: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/, impact: "A real private key in source may expose a service identity or grant access.", fix: "Confirm whether the value is a private key. If confirmed, replace it and review repository history and access." }
];

rules.push(...EXTENDED_RULES, ...SCENARIO_RULES);
export const SOURCE_RULES = [...rules.map(({ id, title, cwe, severity, condition }) => ({ id, title, cwe: `CWE-${cwe}`, severity, condition })), ...FLOW_RULES];

function evidence(line, secret) {
  if (secret) return '[REDACTED: Possible credential or private key. Review the original line locally.]';
  return line.replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`/g, '"[literal redacted]"')
    .replace(/\b[A-Za-z0-9_+/=-]{24,}\b/g, '[long value redacted]').trim().slice(0, 300);
}

function groupFlowFindings(findings) {
  const key = (file, line, cwe) => JSON.stringify([file, line, cwe]);
  const signatures = new Map();
  for (const finding of findings) {
    if (finding.detection?.method !== 'signature') continue;
    const location = key(finding.location.file, finding.location.line, finding.cwe);
    if (!signatures.has(location)) signatures.set(location, []);
    signatures.get(location).push(finding);
  }
  const attached = new Set();
  const grouped = findings.map((finding) => {
    if (!finding.trace?.length) return finding;
    const related = finding.trace.flatMap((step) => {
      const matches = signatures.get(key(step.file, step.line, finding.cwe)) ?? [];
      // A constructed SQL string is evidence for each distinct call that uses it.
      return step.role === 'sink' ? matches
        : matches.filter((match) => finding.ruleId === 'FLOW-SQL' && match.ruleId === 'SRC-SQL');
    });
    if (!related.length) return finding;
    for (const match of related) attached.add(match);
    const strongest = related.reduce((best, match) =>
      SEVERITIES.indexOf(match.severity) < SEVERITIES.indexOf(best.severity) ? match : best);
    return {
      ...finding,
      severity: SEVERITIES[Math.min(SEVERITIES.indexOf(finding.severity), SEVERITIES.indexOf(strongest.severity))],
      remediation: strongest.remediation,
      relatedRuleIds: [...new Set(related.map(({ ruleId }) => ruleId))],
      detection: {
        method: 'text-flow', condition: strongest.detection.condition,
        asvs: [...new Set(related.flatMap((match) => match.detection.asvs ?? []))],
      },
    };
  });
  return grouped.filter((finding) => !attached.has(finding));
}

export async function scanSource(input, options = {}) {
  const analysis = options.analysis ?? 'quick';
  if (!['quick', 'deep'].includes(analysis)) throw new Error('Invalid source scan mode.');
  const deep = analysis === 'deep';
  const root = path.resolve(input);
  const rootStat = await lstat(root);
  if (rootStat.isSymbolicLink() || (!rootStat.isFile() && !rootStat.isDirectory())) throw new Error('The target must be a normal file/ directory, not a symlink.');
  const base = rootStat.isDirectory() ? root : path.dirname(root);
  const report = createReport('source', root);
  const maxFiles = options.maxFiles ?? MAX_SOURCE_FILES;
  const maxFileBytes = options.maxFileBytes ?? MAX_SOURCE_FILE_BYTES;
  const customRules = options.customRules ?? [];
  const maxFindings = options.maxFindings ?? 5000;
  const excluded = new Set((options.excludePaths ?? []).map((p) => path.resolve(p)));
  const useGitignore = options.gitignore !== false;
  const onlyFiles = options.onlyFiles;
  // Git can return canonical paths while the caller selected a directory through an alias.
  const canonicalBase = onlyFiles ? await realpath(base) : base;
  const linesByFile = new Map();
  const suppressionsByFile = new Map();
  const dependencyFiles = new Set();
  const codeFiles = new Set();
  const contextRemoved = {};
  const snapshot = corpusStats();
  report.stats = { filesScanned: 0, filesSkipped: 0, maxFiles, maxFileBytes, ruleCount: SOURCE_RULES.length + customRules.length, maxFindings, formats: {}, dependencyAnalysis: { manifests: 0, findings: 0, packages: 0, unresolved: 0, unsupportedManifests: 0, unassessedRanges: 0, advisorySnapshot: snapshot.builtAt, advisoryCount: snapshot.advisories, supportedEcosystems: ['npm', 'pip', 'composer'] }, corpus: snapshot };
  const sources = [];
  let deepBytes = 0;
  if (deep) {
    if (customRules.length) throw new Error('Custom JSON rules are available in Quick Scan.');
    report.stats.ruleCount = SEMGREP_RULE_COUNT;
    report.limitations[1] = 'Semgrep CE traces data within functions and matches source and configuration patterns. Review each location in context.';
  }
  if (useGitignore) report.stats.gitignore = { applied: true, ignored: 0 };
  if (onlyFiles) report.stats.diff = { ...(options.diffInfo ?? {}), changedFiles: onlyFiles.size, unchanged: 0 };
  let limitReached = false;

  async function visit(absolute, ignoreStack = []) {
    if (excluded.has(absolute) || limitReached) return;
    const relative = path.relative(base, absolute).split(path.sep).join('/');
    let stat;
    try { stat = await lstat(absolute); }
    catch { report.errors.push(`Can't read metadata: ${relative}`); return; }
    if (stat.isSymbolicLink()) { report.stats.filesSkipped++; return; }
    if (stat.isDirectory()) {
      if (!options.includeTests && relative && isTestPath(relative + '/')) { report.stats.filesSkipped++; return; }
      if (absolute !== root && SKIP.has(path.basename(absolute))) { report.stats.filesSkipped++; return; }
      if (absolute !== root && useGitignore && isIgnored(ignoreStack, relative, true)) { report.stats.gitignore.ignored++; return; }
      let children;
      try { children = await readdir(absolute); }
      catch { report.errors.push(`Could not list directory: ${relative}`); return; }
      let stack = ignoreStack;
      if (useGitignore && children.includes('.gitignore')) {
        try {
          const ignoreFile = path.join(absolute, '.gitignore');
          const ignoreStat = await lstat(ignoreFile);
          if (ignoreStat.isFile() && ignoreStat.size <= maxFileBytes) stack = [...ignoreStack, parseGitignore(await readFile(ignoreFile, 'utf8'), absolute === base ? '' : relative)];
        } catch { report.errors.push(`Can't read .gitignore: ${relative || '.'}`); }
      }
      for (const child of children.sort()) await visit(path.join(absolute, child), stack);
      return;
    }
    if (!stat.isFile()) return;
    const testPath = rootStat.isFile() ? `${path.basename(base)}/${relative}` : relative;
    if (!options.includeTests && isTestPath(testPath)) { report.stats.filesSkipped++; return; }
    if (useGitignore && isIgnored(ignoreStack, relative, false)) { report.stats.gitignore.ignored++; return; }
    if (onlyFiles && !onlyFiles.has(pathKey(absolute)) && !onlyFiles.has(pathKey(path.join(canonicalBase, relative)))) {
      report.stats.diff.unchanged++;
      return;
    }
    const ext = path.extname(absolute).toLowerCase();
    const name = path.basename(absolute);
    const language = deep ? semgrepLanguage(absolute.split(path.sep).join('/')) : undefined;
    const manifest = isDependencyManifest(name);
    const supported = deep ? language || manifest : isSupportedSourceFile(absolute);
    if (!supported) { report.stats.filesSkipped++; return; }
    if (report.stats.filesScanned >= maxFiles) { limitReached = true; report.errors.push(`The ${maxFiles}-file limit was reached. Some source was skipped.`); return; }
    if (stat.size > maxFileBytes) { report.stats.filesSkipped++; report.errors.push(`File exceeds the ${maxFileBytes}-byte limit: ${relative}`); return; }
    let buffer;
    try { buffer = await readFile(absolute); }
    catch { report.errors.push(`Could not read file: ${relative}`); return; }
    if (buffer.includes(0)) { report.stats.filesSkipped++; return; }
    if (buffer.length > maxFileBytes) {
      report.stats.filesSkipped++;
      report.errors.push(`File exceeds the ${maxFileBytes}-byte limit: ${relative}`);
      return;
    }
    if (language && deepBytes + buffer.length > MAX_SOURCE_TOTAL_BYTES) {
      report.errors.push(`Semgrep source exceeds the ${MAX_SOURCE_TOTAL_BYTES / MIB} MiB total limit. Some files were skipped.`);
      limitReached = true;
      return;
    }
    report.stats.filesScanned++;
    report.stats.formats[ext || name] = (report.stats.formats[ext || name] || 0) + 1;
    const text = buffer.toString('utf8');
    const lines = text.split(/\r?\n/);
    linesByFile.set(relative, lines);
    report.stats.linesScanned = (report.stats.linesScanned ?? 0) + lines.length;
    if (text.includes('srcaudit-ignore')) suppressionsByFile.set(relative, collectSuppressions(lines));
    if (manifest) {
      const stats = report.stats.dependencyAnalysis;
      stats.manifests++;
      try {
        const inventory = extractDependencies(name, text);
        stats.packages += inventory.packages.length;
        stats.unresolved += inventory.unresolved;
        stats.unsupportedManifests += inventory.unsupported;
        const dependencies = dependencyFindings(inventory.packages, relative);
        stats.unassessedRanges += dependencies.unassessedRanges;
        report.findings.push(...dependencies.findings);
        if (!inventory.unresolved && !inventory.unsupported && !dependencies.unassessedRanges) dependencyFiles.add(relative);
      } catch { report.errors.push('Could not read dependency manifest or invalid structure: ' + relative); }
    }
    if (deep) {
      if (language) {
        deepBytes += buffer.length;
        sources.push({ file: relative, text, language });
      }
      return;
    }
    codeFiles.add(relative);
    let inBlock = false;
    // Python docstrings / standalone triple-quoted strings are documentation, not code.
    // Only blocks whose first line *starts* with the quotes count, so SQL kept in
    // `query = """...` assignments is still scanned.
    let docQuote = '';
    const python = ext === '.py';
    for (let index = 0; index < lines.length; index++) {
      const raw = lines[index];
      if (raw.length > 8192) {
        report.errors.push(`Line exceeds the 8192-character analysis limit: ${relative}:${index + 1}`);
        continue;
      }
      const line = raw.trim();
      // Line-based comment handling is deliberately conservative; no language parser.
      let docstring = false;
      if (python) {
        if (docQuote) {
          docstring = true;
          if (line.includes(docQuote)) {
            // Closing line counts as documentation only when nothing follows the quotes.
            docstring = line.endsWith(docQuote) && line.indexOf(docQuote) === line.length - 3;
            docQuote = '';
          }
        } else {
          const open = line.match(/^[rRuUbBfF]{0,2}("""|''')/);
          if (open) {
            docstring = true;
            const rest = line.slice(open[0].length);
            if (!rest.includes(open[1])) docQuote = open[1];
            else if (!rest.trimEnd().endsWith(open[1])) docstring = false;
          }
        }
      }
      const comment = inBlock || docstring || /^(?:\/\/|#|<!--|\/\*|\*)/.test(line);
      if (line.startsWith('/*') || line.startsWith('<!--')) inBlock = !line.includes('*/') && !line.includes('-->');
      if (line.includes('*/') || line.includes('-->')) inBlock = false;
      for (const custom of customRules) {
        if (comment || !custom.extensions.includes(ext)) continue;
        if (custom.containsAll?.length && !custom.containsAll.every((part) => raw.includes(part))) continue;
        if (custom.containsAny?.length && !custom.containsAny.some((part) => raw.includes(part))) continue;
        report.findings.push({ ruleId: custom.id, title: custom.title, severity: custom.severity, cwe: custom.cwe, confidence: 'low', status: 'needs-review', location: { file: relative, line: index + 1 }, evidence: evidence(raw, true), impact: custom.impact, remediation: custom.remediation, reference: custom.reference });
      }
      for (const rule of rules) {
        if (rule.id === 'SRC-EVAL' && ext !== '.py' && !/\beval\s*\(/.test(raw)) continue;
        let envSecret = false;
        if (rule.id === 'SRC-SECRET' && (name.startsWith('.env') || ['.ini', '.properties', '.conf', '.config'].includes(ext))) {
          const assignment = raw.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\s#"']+)/);
          envSecret = Boolean(assignment && /PASSWORD|PASSWD|API_KEY|SECRET|ACCESS_TOKEN|AUTH_TOKEN/i.test(assignment[1]) && assignment[2].length >= 8);
        }
        if ((comment && !rule.secret) || (rule.exts && !rule.exts.includes(ext)) || (!envSecret && !rule.match.test(raw))) continue;
        if (rule.check && !rule.check(lines, index)) continue;
        let placeholder = false;
        if (rule.id === 'SRC-SECRET') {
          const kind = classifySecret(raw);
          if (kind === 'reference') { contextRemoved[rule.id] = (contextRemoved[rule.id] ?? 0) + 1; continue; }
          placeholder = kind === 'placeholder';
        }
        if (rule.id === 'SRC-HASH' && ext === '.py' && /\busedforsecurity\s*=\s*False\b/.test(raw)) { contextRemoved[rule.id] = (contextRemoved[rule.id] ?? 0) + 1; continue; }
        report.findings.push({
          ruleId: rule.id, title: rule.title, severity: placeholder ? 'info' : rule.severity,
          confidence: placeholder ? 'low' : rule.id === 'SRC-PRIVATE-KEY' ? 'high' : 'medium', status: 'needs-review', cwe: `CWE-${rule.cwe}`,
          ...(placeholder ? { context: 'placeholder' } : {}),
          location: { file: relative, line: index + 1 }, evidence: evidence(raw, rule.secret),
          impact: rule.impact, remediation: rule.fix, reference: rule.reference || ref(rule.cwe), detection: { method: 'signature', condition: rule.condition || 'You need to verify input, protection, and environment before concluding.', asvs: rule.asvs || [] }
        });
      }
      if (report.findings.length >= maxFindings) {
        report.findings.length = maxFindings;
        report.errors.push(`Scan stopped after ${maxFindings} findings to limit memory usage.`);
        limitReached = true;
        break;
      }
    }
    if (!limitReached && ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.php'].includes(ext)) report.findings.push(...analyzeFlow(lines, relative));
    if (report.findings.length > maxFindings) {
      report.findings.length = maxFindings; limitReached = true;
      report.errors.push(`The ${maxFindings}-finding limit was reached. Some source was skipped.`);
    }
  }
  await visit(root);
  if (deep) {
    const result = sources.length
      ? await (options.semgrepRunner ?? runSemgrep)(sources)
      : { status: 'skipped', scanned: 0, findings: [] };
    if (result.status === 'complete' && result.scanned === sources.length) {
      for (const { file } of sources) codeFiles.add(file);
    }
    const total = report.findings.length + result.findings.length;
    report.findings = report.findings.concat(result.findings).slice(0, maxFindings);
    report.stats.sourceAnalysis = {
      mode: 'deep', engine: 'Semgrep', status: result.status, scanned: result.scanned,
      selected: sources.length, findings: result.findings.length, languages: result.languages ?? {},
      ...(result.pythonPrecision ? { pythonPrecision: result.pythonPrecision } : {}),
    };
    if (result.message) report.errors.push(result.message);
    if (!sources.length && !onlyFiles && !report.stats.dependencyAnalysis.manifests) report.errors.push('No files in languages supported by Deep Scan were selected.');
    if (total > maxFindings) report.errors.push('Showing the first ' + maxFindings + ' findings.');
  } else {
    report.findings = groupFlowFindings(report.findings);
    if (options.astFilter !== false) {
      const sourceByFile = { get: (file) => linesByFile.get(file)?.join('\n') };
      const filtered = filterWithAst(report.findings, sourceByFile);
      report.findings = filtered.findings;
      report.filtered = filtered.removed;
      report.stats.astFilter = filtered.stats;
    }
    if (!report.stats.filesScanned && !onlyFiles) report.errors.push('No supported source files were selected.');
  }
  if (options.contextFilter !== false) {
    const downgraded = applyFileContext(report.findings);
    for (const finding of report.findings) if (finding.context === 'placeholder') downgraded[finding.ruleId] = (downgraded[finding.ruleId] ?? 0) + 1;
    report.stats.contextFilter = { removed: contextRemoved, downgraded };
  }
  assignFingerprints(report.findings, linesByFile);
  applySuppressions(report, suppressionsByFile);
  report.stats.dependencyAnalysis.findings = report.findings.filter(({ advisory }) => advisory).length;
  Object.defineProperty(report, 'scanScope', { value: { codeFiles, dependencyFiles } });
  return finishReport(report);
}
