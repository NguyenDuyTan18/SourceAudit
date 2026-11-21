// Keep the punctuation and identifiers of a bounded Python statement while hiding literals and comments.
const withoutLiterals = (text) => text.replace(/"""[\s\S]*?"""|'''[\s\S]*?'''|"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|#[^\r\n]*/g,
  (value) => value.replace(/[^\r\n]/g, ' '));

function callArguments(code, start) {
  let depth = 0;
  let first = start;
  const args = [];
  for (let end = start; end < code.length; end++) {
    const token = code[end];
    if (!depth && (token === ',' || token === ')')) {
      args.push(code.slice(first, end).trim());
      if (token === ')') return args;
      first = end + 1;
    } else if ('([{'.includes(token)) depth++;
    else if (')]}'.includes(token)) depth--;
  }
  return [];
}

export function explicitlyInsecureCookie(lines, index) {
  const end = Math.min(lines.length, index + 12);
  const code = withoutLiterals(lines.slice(index, end).map((line) => line.slice(0, 8192)).join('\n'));
  const firstLine = code.split('\n', 1)[0];
  for (const match of firstLine.matchAll(/(?<![\w.])([A-Za-z_]\w*)\.set_cookie\s*\(/g)) {
    const args = callArguments(code, match.index + match[0].length);
    if (!args.some((argument) => /^secure\s*=\s*False$/.test(argument)) ||
        args.some((argument) => /^(?:partitioned\s*=|\*\*)/.test(argument))) continue;

    const binding = new RegExp(`^\\s*${match[1]}\\s*=\\s*(?!=)(.*)`);
    for (let previous = index - 1; previous >= Math.max(0, index - 32); previous--) {
      const line = withoutLiterals(lines[previous]);
      if (/^\s*(?:(?:async\s+)?def|class)\s+/.test(line)) break;
      const assignment = line.match(binding);
      if (!assignment) continue;
      if (/^flask\.(?:make_response|Response|redirect)\s*\(/.test(assignment[1])) return true;
      if (/^(?:make_response|Response|redirect)\s*\(/.test(assignment[1]) &&
          lines.slice(0, 64).some((part) => /^\s*from\s+flask\s+import\s/.test(part))) return true;
      break;
    }
  }
  return false;
}
