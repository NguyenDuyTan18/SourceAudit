import { readFile, mkdir, writeFile, readdir, stat, rename, rm } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { SEVERITIES, safeUrl } from './report.mjs';
import { searchCorpus, relatedContext, verificationRequirements } from './corpus.mjs';

const academy = 'https://portswigger.net/web-security/';
const owasp = 'https://cheatsheetseries.owasp.org/cheatsheets/';
function topic(id, name, cwes, keywords, references, reviewSteps, { reviewedAt = '2026-11-05', ruleIds } = {}) {
  return { id, name, cwes, keywords, references, reviewSteps, reviewedAt, ruleIds, detection: 'Review guidance. Verify data flow and safeguards in context.' };
}

export const KNOWLEDGE = [
  topic('sql-injection', 'SQL injection', ['CWE-89'], ['sql injection', 'sql_injection', 'sql-injection', 'sqli', 'parameterized queries', 'query construction'], [owasp + 'SQL_Injection_Prevention_Cheat_Sheet.html'], ["Trace input to the query API.", "Check where parameters are bound and where SQL text is constructed.", "Review dynamic identifiers such as column or table names separately."]),
  topic('xss', 'Cross-site scripting', ['CWE-79'], ['xss', 'cross-site scripting', 'cross_site_scripting', 'html injection', 'html_injection', 'html-injection', 'innerhtml', 'dangerouslysetinnerhtml'], [owasp + 'Cross_Site_Scripting_Prevention_Cheat_Sheet.html'], ["Identify the HTML, attribute or JavaScript context where input is used.", "Check the encoding or sanitizer before the value reaches that context.", "Assess content security policy as an additional control."]),
  topic('command-injection', 'OS command injection', ['CWE-78', 'CWE-95'], ['command injection', 'shell injection', 'shell_exec', 'code injection'], [owasp + 'OS_Command_Injection_Defense_Cheat_Sheet.html'], ["Determine whether the API invokes a shell or accepts a separate argument list.", "Trace input and check validation of both the program and its arguments."]),
  topic('ssrf', 'Server-side request forgery', ['CWE-918'], ['ssrf', 'server-side request forgery', 'server side request forgery'], [academy + 'ssrf', owasp + 'Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'], ["Trace user-controlled URLs to the HTTP client.", "Review the scheme, resolved addresses, redirects and outbound policy."]),
  topic('path-traversal', 'Path traversal / file access', ['CWE-22'], ['path traversal', 'directory traversal', 'sendfile', 'readfile'], [academy + 'file-path-traversal'], ["Verify that the resolved path stays inside an allowed directory.", "Check symbolic links, the root directory and effective file permissions."]),
  topic('deserialization', 'Unsafe deserialization', ['CWE-502'], ['deserialization', 'deserialize', 'pickle', 'unserialize', 'yaml.load'], [owasp + 'Deserialization_Cheat_Sheet.html'], ["Identify the data source and what formats it can supply.", "Review the loader and the object types it can construct.", "Prefer simple data formats with schema validation."]),
  topic('ssti', 'Server-side template injection', ['CWE-1336'], ['ssti', 'template injection', 'render_template_string'], [academy + 'server-side-template-injection'], ["Identify which values supply template source and which are passed as template data.", "Identify the template engine and review its sandbox."]),
  topic('prototype-pollution', 'Prototype pollution', ['CWE-1321'], ['prototype pollution', '__proto__', 'prototype-pollution'], [academy + 'prototype-pollution', 'https://portswigger.net/research/server-side-prototype-pollution'], ["Trace external data into object merges and key assignments.", "Review how unsafe keys are rejected and whether object creation avoids shared prototypes."]),
  topic('xxe', 'XML external entity', ['CWE-611'], ['xxe', 'external entity', 'resolve_entities'], [academy + 'xxe'], ["Check the XML parser configuration for DTD and external entity handling.", "Review the parser version and its effective file and network permissions."]),
  topic('jwt', 'JWT signature validation', ['CWE-347'], ['jwt', 'json web token', 'verify_signature'], [academy + 'jwt'], ["Verify that signature validation is enabled and accepted algorithms are restricted.", "Review issuer, audience and expiration checks."]),
  topic('secrets', 'Embedded credentials / private keys', ['CWE-798', 'CWE-321'], ['hardcoded secret', 'credential', 'private key', 'api key'], [owasp + 'Secrets_Management_Cheat_Sheet.html'], ["Confirm whether the value is a real credential or fixture data.", "If confirmed, revoke or rotate it and review history and access."]),
  topic('access-control', 'Broken access control / IDOR', ['CWE-639', 'CWE-862'], ['idor', 'bola', 'access control', 'authorization'], [academy + 'access-control'], ["Use authorized test identities with different permissions to review access.", "Check server-side authorization for each resource and operation."]),
  topic('weak-digest', "MD5 and SHA-1", ['CWE-328'], ['hashlib', 'md5', 'sha1', 'usedforsecurity', 'weak hash'],
    ['https://docs.python.org/3/library/hashlib.html', owasp + 'Password_Storage_Cheat_Sheet.html', 'https://itsdangerous.palletsprojects.com/en/stable/concepts/#digest-method-security'],
    ["Identify whether the digest is used as a checksum, an authentication primitive or for password storage.", "Review any compatibility constraints and plan a migration for security-sensitive uses.", "Use a password hashing function with suitable cost settings for passwords."],
    { reviewedAt: '2026-11-21', ruleIds: ['SRC-HASH', 'srcaudit-python-weak-hashlib'] }),
  topic('tls-validation', "TLS certificate and hostname verification", ['CWE-295'], ['tls', 'certificate verification', 'sslcontext', 'create_unverified_context'],
    ['https://docs.python.org/3/library/ssl.html#security-considerations', 'https://peps.python.org/pep-0476/'],
    ["Trace the TLS context or client to the deployed connection.", "Verify both the certificate chain and hostname checks.", "For an internal CA, add the trusted CA and keep identity verification enabled."], { reviewedAt: '2026-11-21' }),
  topic('temporary-files', "Safe temporary file creation", ['CWE-377'], ['tempfile', 'mktemp', 'mkstemp', 'namedtemporaryfile', 'temporary file'],
    ['https://docs.python.org/3/library/tempfile.html#tempfile.mktemp'],
    ["Check whether the application opens the returned path later.", "Review directory and file permissions.", "Create the file atomically and close and delete it according to the application's lifecycle."], { reviewedAt: '2026-11-21' })
];

export function searchKnowledge(query = '') {
  const needle = query.toLowerCase().trim();
  return [...KNOWLEDGE.filter((entry) => !needle || [entry.id, entry.name, ...entry.cwes, ...entry.keywords].join(' ').toLowerCase().includes(needle)), ...searchCorpus(needle).results];
}

async function readBounded(file, maxBytes = 1024 * 1024) {
  const info = await stat(file);
  if (!info.isFile() || info.size > maxBytes) throw new Error('Choose a text file no larger than 1 MiB.');
  const text = await readFile(file, 'utf8');
  if (text.includes('\0')) throw new Error('Binary files are unsupported.');
  return text;
}

export class WriteupLimitError extends Error {}

const WRITEUP_FILE = /^writeup-[a-f0-9]{16}\.json$/;

export async function importWriteup(file, directory, { maxEntries = Infinity } = {}) {
  if (!['.md', '.txt'].includes(path.extname(file).toLowerCase())) throw new Error('Write-up must be .md or .txt.');
  const text = await readBounded(file);
  const lower = text.toLowerCase();
  const topics = KNOWLEDGE.filter((entry) => entry.keywords.some((keyword) => lower.includes(keyword))).map((entry) => entry.id);
  const references = [];
  for (const match of text.matchAll(/https:\/\/[^\s<>"')\]]+/g)) {
    if (match[0].length > 2048) continue;
    try {
      // Remove URL query and fragment entirely; preserve no embedded credentials.
      const url = new URL(match[0]);
      if (url.username || url.password) continue;
      url.search = ''; url.hash = '';
      if (!references.includes(url.href)) references.push(url.href);
      if (references.length >= 30) break;
    } catch { /* Ignore malformed references. Never fetch them. */ }
  }
  const digest = createHash('sha256').update(text).digest('hex');
  const entry = { id: digest.slice(0, 16), sha256: digest, importedAt: new Date().toISOString(), topics, references, note: 'The index stores matched topics and reference URLs. It does not store the original text, create rules or verify a vulnerability.' };
  await mkdir(directory, { recursive: true });
  const name = 'writeup-' + entry.id + '.json';
  const output = path.resolve(directory, name);
  if (Number.isFinite(maxEntries)) {
    const existing = (await readdir(directory)).filter((item) => WRITEUP_FILE.test(item));
    if (existing.length >= maxEntries && !existing.includes(name)) throw new WriteupLimitError('The write-up limit has been reached.');
  }
  const temporary = output + '.' + randomUUID() + '.tmp';
  try {
    await writeFile(temporary, JSON.stringify(entry, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
    await rename(temporary, output);
  } finally { await rm(temporary, { force: true }).catch(() => {}); }
  return { ...entry, file: output };
}

export async function loadWriteups(directory, { allowMissing = false } = {}) {
  const entries = [];
  if (!directory) return entries;
  const names = await readdir(directory).catch((error) => {
    if (allowMissing && error.code === 'ENOENT') return [];
    throw error;
  });
  for (const name of names.filter((n) => WRITEUP_FILE.test(n)).slice(0, 200)) {
    const entry = JSON.parse(await readBounded(path.join(directory, name)));
    if (!Array.isArray(entry.topics) || !Array.isArray(entry.references) || entry.topics.some((id) => !KNOWLEDGE.some((k) => k.id === id))) throw new Error('Invalid Write-up index.');
    entries.push({ id: name, topics: entry.topics, references: entry.references.filter((url) => typeof url === 'string' && /^https:\/\//.test(url)).slice(0, 30).map(safeUrl) });
  }
  return entries;
}

export function enrichReport(report, writeups = [], { maxWriteups = Infinity, maxReferences = Infinity } = {}) {
  for (const finding of report.findings) {
    const entry = KNOWLEDGE.find((item) => item.ruleIds?.includes(finding.ruleId) || item.cwes.includes(finding.cwe));
    const context = relatedContext(finding.cwe);
    if (!entry && !context.weakness) continue;
    finding.knowledge = { topic: entry?.id || finding.cwe,
      references: [...new Set([...(entry?.references || []), ...(context.weakness?.references || []), ...context.tests.flatMap((item) => item.references), ...verificationRequirements(finding.detection?.asvs || []).flatMap((item) => item.references), ...context.apiScenarios.flatMap((item) => item.references)])],
      reviewSteps: entry?.reviewSteps || context.weakness?.mitigations?.slice(0, 3) || ['Check the CWE conditions in source and deployed environment.'],
      cweContext: context.weakness ? { name: context.weakness.name, description: context.weakness.description, consequences: context.weakness.consequences, abstraction: context.weakness.abstraction } : undefined,
      owaspTests: context.tests.map(({ id, name, references }) => ({ id, name, references })),
      verificationRequirements: verificationRequirements(finding.detection?.asvs || []).map(({ id, description, references, level }) => ({ id, description, references, level })),
      apiScenarios: context.apiScenarios.map(({ id, name, references }) => ({ id, name, references })),
      advisoryExamples: context.examples.map(({ id, cve, name, references }) => ({ id, cve, name, references: references.slice(0, 1), role: 'context-only-not-a-match' })),
      relatedWriteups: writeups.filter((w) => entry && w.topics.includes(entry.id)).slice(0, maxWriteups)
        .map((w) => ({ id: w.id, references: w.references.slice(0, maxReferences) })) };
  }
  return report;
}

export async function loadCustomRules(file) {
  const data = JSON.parse(await readBounded(file));
  if (!Array.isArray(data) || data.length > 100) throw new Error('The rules file must contain a JSON array of up to 100 rules.');
  const ids = new Set();
  return data.map((rule) => {
    const allowedKeys = ['id', 'title', 'severity', 'cwe', 'extensions', 'containsAll', 'containsAny', 'impact', 'remediation', 'reference'];
    if (Object.keys(rule).some((key) => !allowedKeys.includes(key))) throw new Error('Rule contains an unsupported field. Use literal string patterns.');
    if (!/^CUSTOM-[A-Z0-9-]{1,50}$/.test(rule.id) || ids.has(rule.id)) throw new Error('Each rule ID must be unique and start with CUSTOM-.');
    ids.add(rule.id);
    for (const field of ['title', 'impact', 'remediation', 'reference']) if (typeof rule[field] !== 'string' || !rule[field].trim() || rule[field].length > 1500) throw new Error(`Required rule field is missing or invalid: ${field}.`);
    if (!SEVERITIES.includes(rule.severity) || !/^CWE-\d{1,5}$/.test(rule.cwe)) throw new Error('Severity or CWE is invalid.');
    if (!Array.isArray(rule.extensions) || !rule.extensions.length || rule.extensions.length > 30 || rule.extensions.some((ext) => !/^\.[a-z0-9]{1,10}$/.test(ext))) throw new Error('Invalid Extensions.');
    for (const key of ['containsAll', 'containsAny']) {
      if (rule[key] !== undefined && (!Array.isArray(rule[key]) || rule[key].length > 20 || rule[key].some((value) => typeof value !== 'string' || !value.length || value.length > 200))) throw new Error('Pattern must be a short list of strings.');
    }
    if (!(rule.containsAll?.length || rule.containsAny?.length)) throw new Error('Need at least one literal pattern.');
    const reference = new URL(rule.reference);
    if (reference.protocol !== 'https:' || reference.username || reference.password) throw new Error('Use an HTTPS reference URL without credentials.');
    return { ...rule, reference: safeUrl(reference) };
  });
}
