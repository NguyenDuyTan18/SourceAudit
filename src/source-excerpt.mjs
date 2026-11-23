import path from 'node:path';
import { parse } from '@babel/parser';

const maxSourceBytes = 256 * 1024;
const maxLineLength = 320;
const punctuation = '!#$%&()*+,-./:;<=>?@[\\]^_`{|}~';
const nonCodeKeywords = new Set(['null', 'true', 'false']);
const reviewableCalls = new Set([
  'eval', 'exec', 'execSync', 'execFile', 'spawn', 'system', 'popen', 'run', 'Popen', 'call', 'check_output',
  'shell_exec', 'passthru', 'include', 'include_once', 'require', 'require_once',
  'execute', 'executemany', 'executeQuery', 'executeUpdate', 'query', 'queryForObject', 'queryForList',
  'update', 'select', 'selectOne', 'statement', 'unprepared', 'Query', 'QueryRow', 'Exec', 'SqlCommand',
  'load', 'loads', 'unsafe_load', 'unserialize', 'ObjectInputStream', 'deserialize', 'Deserialize',
  'redirect', 'Redirect', 'sendRedirect', 'header', 'open', 'send_file', 'sendFile', 'Path', 'File',
  'readFile', 'readFileSync', 'ReadAllText', 'ReadAllBytes', 'OpenRead', 'ReadFile', 'Open',
  'get', 'get_response', 'request', 'fetch', 'Get', 'GetAsync', 'PostAsync', 'SendAsync', 'curl_setopt',
  'URL', 'URI', 'openConnection', 'SetRequestUri', 'Command', 'CommandContext', 'Start', 'ProcessStartInfo',
  'Response', 'getWriter', 'write', 'print', 'println', 'Printf', 'Println', 'Raw',
  'XPath', 'ETXPath', 'xpath', 'evaluate', 'compile', 'search', 'search_s', 'search_ext_s', 'parseString',
  'render_template_string', 'set_cookie', 'verify', 'md5', 'sha1', 'new', 'mktemp', '_create_unverified_context',
  'getrandbits', 'randbytes', 'random', 'randint', 'randrange', 'choice', 'choices', 'sample', 'shuffle',
  'uniform', 'normalvariate',
]);

function mask(text) {
  return text.replace(/[^\r\n]+/g, '…');
}

export function redactedSourceLines(file, text) {
  if (Buffer.byteLength(text, 'utf8') > maxSourceBytes) return undefined;
  const extension = path.extname(file).toLowerCase();
  if (!/^\.(?:js|mjs|cjs|jsx|ts|tsx)$/.test(extension)) return undefined;
  const plugins = extension === '.ts' ? ['typescript'] : extension === '.tsx' ? ['typescript', 'jsx'] : ['jsx'];
  try {
    const { tokens } = parse(text, { sourceType: 'unambiguous', tokens: true, plugins });
    let offset = 0;
    const fragments = [];
    for (const token of tokens) {
      if (token.start < offset || token.end < token.start) return undefined;
      const gap = text.slice(offset, token.start);
      fragments.push(/^[ \t\r\n]*$/.test(gap) ? gap : mask(gap));
      const value = text.slice(token.start, token.end);
      const label = token.type.label;
      const identifier = (label === 'name' || label === 'jsxName' || token.type.keyword) &&
        !nonCodeKeywords.has(label) && value.length < 24;
      const symbol = typeof label === 'string' &&
        (label === 'jsxTagStart' || label === 'jsxTagEnd' || /^[^A-Za-z0-9\s]+$/.test(label)) &&
        value.length <= 8 && [...value].every((character) => punctuation.includes(character));
      fragments.push(identifier || symbol ? value : mask(value));
      offset = token.end;
    }
    fragments.push(mask(text.slice(offset)));
    return fragments.join('').split(/\r?\n/);
  } catch {
    return undefined;
  }
}

export function sourceExcerptAt(lines, line, endLine = line) {
  const matched = lines?.[line - 1];
  if (!matched?.trim() || matched.length > maxLineLength) return undefined;
  const first = Math.max(0, line - 2);
  const last = Math.min(endLine, lines.length);
  const lastVisible = Math.min(last, line + 4);
  const preview = lines.slice(first, lastVisible + (lastVisible === last ? 1 : 0)).map((text, index) => {
    const number = first + index + 1;
    const clean = text.replace(/\t/g, '  ').replace(/[\p{Cc}\p{Cf}]/gu, '');
    const excerpt = clean.length > maxLineLength ? clean.slice(0, maxLineLength - 1) + '…' : clean;
    return `${number >= line && number <= last ? '>' : ' '} ${number} | ${excerpt}`;
  });
  if (lastVisible < last) preview.push(`  … | Lines ${lastVisible + 1}–${last} are available in the original file`);
  return preview.join('\n');
}

export function matchedOperationAt(lines, line, column) {
  const original = lines?.[line - 1];
  if (!original || column > Buffer.byteLength(original) + 1) return undefined;
  const left = lines.slice(Math.max(0, line - 4), line - 1).join('\n');
  const text = left ? `${left}\n${original}` : original;
  if (text.length > 8192) return undefined;
  const offset = text.length - original.length + Buffer.from(original).subarray(0, column - 1).toString().length;
  const tokens = /"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|(?:\/\/|#)[^\n]*|\b([A-Za-z_]\w*)\s*\(|[()]/g;
  const calls = [];
  for (const match of text.matchAll(tokens)) {
    if (match.index > offset) break;
    if (match[1]) {
      const name = reviewableCalls.has(match[1]) ? match[1] : undefined;
      if (name && offset < match.index + match[0].length) return `${name}(…)`;
      calls.push(name);
    } else if (match[0] === '(') calls.push(undefined);
    else if (match[0] === ')') calls.pop();
  }
  const active = calls.findLast(Boolean);
  return active ? `${active}(…)` : undefined;
}
