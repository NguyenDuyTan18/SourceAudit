// Context-aware adjustments that reduce false positives without hiding real issues:
//   - references/templates instead of secret values are dropped,
//   - placeholder-looking secrets and findings in test/example code are downgraded
//     (kept in the report, but they no longer fail `--fail-on high`),
//   - debug flags in development-only config files become informational.
import { SEVERITIES } from './report.mjs';
import { isTestPath } from './scan-scope.mjs';

const lower = (severity) => SEVERITIES[Math.min(SEVERITIES.indexOf(severity) + 1, SEVERITIES.length - 1)];

// Values that point to where a secret lives rather than containing it.
const SECRET_REFERENCE = /^(?:\$\{[^}]+\}|\$\([^)]+\)|\{\{.*\}\}|%\([^)]+\)s|<[^<>]+>|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$|\b(?:process\.env|os\.environ|getenv|import\.meta\.env)\b/;
// Deliberately excludes words like "secret" or "password": "super-secret-123" is a weak
// but possibly real credential and must stay at full severity.
const PLACEHOLDER_WORDS = new Set(['example', 'examples', 'sample', 'dummy', 'fake', 'placeholder', 'your', 'todo', 'fixme', 'redacted', 'test', 'testing', 'development', 'dev', 'demo', 'mock']);
const PLACEHOLDER_PHRASES = ['changeme', 'replaceme', 'yourkey', 'yourapikey', 'yourtoken', 'yoursecret', 'yourpassword', 'insertkeyhere'];

function entropy(value) {
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) { const p = count / value.length; bits -= p * Math.log2(p); }
  return bits;
}

/** Extracts the literal assigned on a credential-looking line, if any. */
export function secretValue(raw) {
  const quoted = raw.match(/[:=]\s*(?:[rbuf]{0,2})(["'`])((?:\\.|(?!\1).){1,500})\1/i);
  if (quoted) return quoted[2];
  const bare = raw.match(/^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*[:=]\s*([^\s#"']+)/);
  return bare?.[1];
}

/**
 * Classifies a credential-looking line:
 *   'reference'   → value is an env/template reference, not a secret (drop),
 *   'placeholder' → value looks like an example or dummy (downgrade),
 *   undefined     → treat as a possible real credential.
 */
export function classifySecret(raw) {
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(raw)) return undefined;
  const value = secretValue(raw);
  if (value === undefined) return undefined;
  const trimmed = value.trim();
  if (SECRET_REFERENCE.test(trimmed)) return 'reference';
  // Known provider token shapes are never treated as placeholders by wording alone.
  if (/\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{24,}|sk_live_[A-Za-z0-9]{16,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/.test(trimmed)) return undefined;
  if (/^(.)\1+$/.test(trimmed) || /^[x*.#_-]+$/i.test(trimmed) || entropy(trimmed) < 2) return 'placeholder';
  const tokens = trimmed.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  if (tokens.some((token) => PLACEHOLDER_WORDS.has(token) || /^x{3,}$/.test(token))) return 'placeholder';
  if (PLACEHOLDER_PHRASES.some((phrase) => tokens.join('').includes(phrase))) return 'placeholder';
  return undefined;
}

const EXAMPLE_SEGMENTS = new Set(['example', 'examples', 'sample', 'samples', 'demo', 'demos', 'fixture', 'fixtures', '__fixtures__', 'mock', 'mocks', '__mocks__', 'stories', 'docs']);

/** 'test' | 'example' | 'generated' | undefined, from a scan-root-relative POSIX path. */
export function fileContext(file) {
  const parts = String(file ?? '').toLowerCase().split('/');
  const name = parts.at(-1) ?? '';
  const dirs = parts.slice(0, -1);
  if (/\.min\.(?:js|css|mjs)$/.test(name) || /\.(?:bundle|chunk)\.[a-z]+$/.test(name)) return 'generated';
  if (isTestPath(String(file ?? ''))) return 'test';
  if (dirs.some((d) => EXAMPLE_SEGMENTS.has(d)) || /\.(?:example|sample)(?:\.|$)/.test(name)) return 'example';
  return undefined;
}

const DEV_CONFIG = /(?:^|[._-])(?:dev|development|local|test|testing)(?:[._-]|$)/i;

const SECRET_RULES = /SECRET|PRIVATE-KEY|JWT-KEY|CREDENTIAL|TOKEN/;

/** Adjusts findings in place according to file context. Returns per-rule counters. */
export function applyFileContext(findings) {
  const downgraded = {};
  const count = (id) => { downgraded[id] = (downgraded[id] ?? 0) + 1; };
  for (const finding of findings) {
    const file = finding.location?.file;
    if (!file) continue;
    const name = file.split('/').at(-1);
    if (finding.ruleId === 'SRC-DEBUG' && DEV_CONFIG.test(name.replace(/^\.env/, 'env'))) {
      finding.context = 'dev-config';
      finding.severity = 'info'; finding.confidence = 'low'; count(finding.ruleId);
      continue;
    }
    const kind = fileContext(file);
    if (!kind || finding.advisory) continue;
    finding.context = kind;
    finding.confidence = 'low';
    // Credentials in tests can still be real; keep their severity, only mark the context.
    if (!SECRET_RULES.test(finding.ruleId)) finding.severity = lower(finding.severity);
    count(finding.ruleId);
  }
  return downgraded;
}
