import path from 'node:path';
import { parse } from '@babel/parser';

const maxSourceBytes = 256 * 1024;
const maxLineLength = 320;
const punctuation = '!#$%&()*+,-./:;<=>?@[\\]^_`{|}~';
const nonCodeKeywords = new Set(['null', 'true', 'false']);

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
  if (lastVisible < last) preview.push(`  … | Dòng ${lastVisible + 1}–${last} xem trong file gốc`);
  return preview.join('\n');
}
