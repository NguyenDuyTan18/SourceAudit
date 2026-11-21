// Minimal .gitignore matcher (https://git-scm.com/docs/gitignore#_pattern_format).
// Paths are POSIX-style and relative to the scan root; `base` is the directory
// holding the .gitignore ('' for the root).

const escapeRegex = (ch) => /[\\^$.*+?()[\]{}|/]/.test(ch) ? '\\' + ch : ch;

function toRegexBody(pattern) {
  let out = '';
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '*') {
      if (pattern[i + 1] === '*') {
        const prevSlash = i === 0 || pattern[i - 1] === '/';
        if (prevSlash && pattern[i + 2] === '/') { out += '(?:.*/)?'; i += 2; continue; }
        if (prevSlash && i + 2 === pattern.length) { out += '.*'; i += 1; continue; }
        // Any other `**` behaves like a single `*`.
        while (pattern[i + 1] === '*') i++;
      }
      out += '[^/]*';
    } else if (ch === '?') out += '[^/]';
    else if (ch === '[') {
      let end = i + 1;
      if (pattern[end] === '!' || pattern[end] === '^') end++;
      if (pattern[end] === ']') end++;
      while (end < pattern.length && pattern[end] !== ']') end++;
      if (end >= pattern.length) { out += '\\['; continue; }
      let body = pattern.slice(i + 1, end);
      const negate = body[0] === '!' || body[0] === '^';
      if (negate) body = body.slice(1);
      out += '[' + (negate ? '^' : '') + body.replace(/\\/g, '\\\\') + ']';
      i = end;
    } else if (ch === '\\' && i + 1 < pattern.length) out += escapeRegex(pattern[++i]);
    else out += escapeRegex(ch);
  }
  return out;
}

export function parseGitignore(text, base = '') {
  const rules = [];
  for (let line of String(text).split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    line = line.replace(/(?<!\\)\s+$/, '');
    if (!line) continue;
    let negate = false;
    if (line.startsWith('!')) { negate = true; line = line.slice(1); }
    else if (line.startsWith('\\!') || line.startsWith('\\#')) line = line.slice(1);
    let dirOnly = false;
    if (line.endsWith('/')) { dirOnly = true; line = line.replace(/\/+$/, ''); }
    if (!line) continue;
    const anchored = line.includes('/');
    if (line.startsWith('/')) line = line.slice(1);
    try {
      rules.push({ negate, dirOnly, regex: new RegExp('^' + (anchored ? '' : '(?:.*/)?') + toRegexBody(line) + '$') });
    } catch { /* Skip patterns that cannot be represented. */ }
  }
  return { base, rules };
}

/** `stack` is ordered from the outermost .gitignore to the innermost. */
export function isIgnored(stack, relativePath, isDirectory) {
  let ignored = false;
  for (const { base, rules } of stack) {
    if (base && relativePath !== base && !relativePath.startsWith(base + '/')) continue;
    const local = base ? relativePath.slice(base.length + 1) : relativePath;
    if (!local) continue;
    for (const rule of rules) {
      if (rule.dirOnly && !isDirectory) continue;
      if (rule.regex.test(local)) ignored = !rule.negate;
    }
  }
  return ignored;
}
