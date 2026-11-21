// AST-based false-positive filter for quick-mode findings in JavaScript/TypeScript.
//
// Quick-mode rules match single lines with regular expressions. For the rules below, this
// pass parses the file with @babel/parser, finds the sink call(s) on the reported line and
// removes the finding only when *every* matching sink on that line is provably harmless:
//   - the dangerous argument is a constant (literal, constant concatenation/template,
//     or a `const` bound once in the file to a constant), or
//   - it is wrapped in a well-known encoding/sanitizing call, or
//   - the API is used in a non-injectable form (execFile/spawn without shell,
//     res.sendFile with a `root` option and no spread).
// If the file does not parse, no sink is found on the line, or anything is uncertain,
// the finding is kept. The pass can only remove findings, never add them.
import { parse } from '@babel/parser';

const JS_EXT = /\.(?:[cm]?jsx?|[cm]?tsx?)$/i;
const RULES = new Set(['SRC-SHELL', 'FLOW-SHELL', 'SRC-EVAL', 'FLOW-EVAL', 'SRC-SSRF', 'FLOW-SSRF', 'SRC-PATH', 'FLOW-PATH', 'SRC-SSTI', 'SRC-XSS', 'SRC-SQL', 'FLOW-SQL']);

// Last name of a call that yields data safe for the sink kinds handled here.
const SANITIZERS = {
  any: new Set(['parseInt', 'parseFloat', 'Number', 'Boolean']),
  html: new Set(['escapeHtml', 'escape_html', 'escapeHTML', 'htmlEscape', 'sanitize', 'sanitizeHtml', 'encodeURIComponent', 'encodeForHTML', 'xssFilters', 'inHTMLData']),
  path: new Set(['basename']),
  // Not `format`: util.format does no escaping.
  sql: new Set(['escape', 'escapeId']),
  url: new Set([]),
  shell: new Set(['quote', 'escapeShellArg', 'shellEscape']),
  code: new Set([]),
};

const SKIP_KEYS = new Set(['loc', 'start', 'end', 'extra', 'leadingComments', 'trailingComments', 'innerComments', 'range', 'errors', 'tokens', 'comments']);

function walk(node, visit, parent = null) {
  if (!node || typeof node.type !== 'string') return;
  visit(node, parent);
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const value = node[key];
    if (Array.isArray(value)) { for (const child of value) if (child && typeof child.type === 'string') walk(child, visit, node); }
    else if (value && typeof value.type === 'string') walk(value, visit, node);
  }
}

function plugins(file) {
  if (/\.[cm]?tsx$/i.test(file)) return ['typescript', 'jsx', 'decorators-legacy'];
  if (/\.[cm]?ts$/i.test(file)) return ['typescript', 'decorators-legacy'];
  return ['jsx', 'decorators-legacy'];
}

function parseFile(file, text) {
  return parse(text, {
    sourceType: 'unambiguous', errorRecovery: true, plugins: plugins(file),
    allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, allowImportExportEverywhere: true,
    allowSuperOutsideMethod: true, allowUndeclaredExports: true,
  });
}

const unwrap = (node) => {
  while (node && ['TSAsExpression', 'TSSatisfiesExpression', 'TSNonNullExpression', 'TSTypeAssertion', 'ParenthesizedExpression', 'TypeCastExpression'].includes(node.type)) node = node.expression;
  return node;
};

const calleeName = (callee, aliases) => {
  callee = unwrap(callee);
  if (callee?.type === 'Identifier') return aliases.get(callee.name) ?? callee.name;
  if ((callee?.type === 'MemberExpression' || callee?.type === 'OptionalMemberExpression') && !callee.computed && callee.property.type === 'Identifier') return callee.property.name;
  return undefined;
};
const objectName = (callee) => {
  callee = unwrap(callee);
  if (callee?.type !== 'MemberExpression' && callee?.type !== 'OptionalMemberExpression') return undefined;
  const object = unwrap(callee.object);
  if (object?.type === 'Identifier') return object.name;
  if (object?.type === 'MemberExpression' && !object.computed) return object.property.name;
  return undefined;
};
const property = (object, name) => object?.type === 'ObjectExpression'
  ? object.properties.find((p) => p.type === 'ObjectProperty' && !p.computed && ((p.key.type === 'Identifier' && p.key.name === name) || (p.key.type === 'StringLiteral' && p.key.value === name)))
  : undefined;
const hasSpread = (object) => object?.type === 'ObjectExpression' && object.properties.some((p) => p.type === 'SpreadElement');

/** Facts about the file needed to evaluate expressions: import aliases and single constant bindings. */
function analyzeBindings(ast) {
  const aliases = new Map(); const declarations = new Map();
  const declare = (name, init, kind) => declarations.set(name, [...(declarations.get(name) ?? []), { init, kind }]);
  const declarePattern = (pattern, kind) => {
    if (!pattern) return;
    if (pattern.type === 'Identifier') declare(pattern.name, undefined, kind);
    else if (pattern.type === 'ObjectPattern') for (const p of pattern.properties) declarePattern(p.type === 'RestElement' ? p.argument : p.value, kind);
    else if (pattern.type === 'ArrayPattern') for (const e of pattern.elements) declarePattern(e?.type === 'RestElement' ? e.argument : e, kind);
    else if (pattern.type === 'AssignmentPattern') declarePattern(pattern.left, kind);
    else if (pattern.type === 'RestElement') declarePattern(pattern.argument, kind);
    else if (pattern.type === 'TSParameterProperty') declarePattern(pattern.parameter, kind);
  };
  const assigned = new Set();
  walk(ast, (node) => {
    if (node.type === 'ImportSpecifier' && node.imported) {
      const imported = node.imported.type === 'Identifier' ? node.imported.name : node.imported.value;
      if (imported !== node.local.name) aliases.set(node.local.name, imported);
      declare(node.local.name, undefined, 'import');
    } else if (node.type === 'ImportDefaultSpecifier' || node.type === 'ImportNamespaceSpecifier') declare(node.local.name, undefined, 'import');
    else if (node.type === 'VariableDeclarator') {
      if (node.id.type === 'Identifier') declare(node.id.name, node.init, node.kind ?? undefined);
      else {
        // const { exec: run } = require('child_process')
        if (node.id.type === 'ObjectPattern') for (const p of node.id.properties) {
          if (p.type === 'ObjectProperty' && !p.computed && p.key.type === 'Identifier' && p.value.type === 'Identifier' && p.key.name !== p.value.name) aliases.set(p.value.name, p.key.name);
        }
        declarePattern(node.id, 'pattern');
      }
    } else if (/Function/.test(node.type)) {
      if (node.id?.type === 'Identifier') declare(node.id.name, undefined, 'function');
      for (const param of node.params ?? []) declarePattern(param, 'param');
    } else if (node.type === 'CatchClause') declarePattern(node.param, 'param');
    else if (node.type === 'ClassDeclaration' && node.id) declare(node.id.name, undefined, 'class');
    else if (node.type === 'AssignmentExpression' && node.left.type === 'Identifier') assigned.add(node.left.name);
    else if (node.type === 'UpdateExpression' && node.argument.type === 'Identifier') assigned.add(node.argument.name);
  });
  // `kind` lives on the VariableDeclaration; re-walk to tag const declarators.
  const constNames = new Set();
  walk(ast, (node) => {
    if (node.type === 'VariableDeclaration' && node.kind === 'const') for (const d of node.declarations) if (d.id.type === 'Identifier') constNames.add(d.id.name);
  });
  const constants = new Map();
  for (const [name, list] of declarations) {
    if (list.length === 1 && list[0].init && constNames.has(name) && !assigned.has(name)) constants.set(name, list[0].init);
  }
  return { aliases, constants };
}

function makeEvaluator({ constants }) {
  const isConstant = (node, depth = 0) => {
    node = unwrap(node);
    if (!node || depth > 20) return false;
    switch (node.type) {
      case 'StringLiteral': case 'NumericLiteral': case 'BooleanLiteral': case 'NullLiteral': case 'BigIntLiteral': case 'RegExpLiteral': return true;
      case 'TemplateLiteral': return node.expressions.every((e) => isConstant(e, depth + 1));
      case 'BinaryExpression': case 'LogicalExpression': return isConstant(node.left, depth + 1) && isConstant(node.right, depth + 1);
      case 'UnaryExpression': return node.operator !== 'delete' && isConstant(node.argument, depth + 1);
      case 'ConditionalExpression': return isConstant(node.consequent, depth + 1) && isConstant(node.alternate, depth + 1);
      case 'ArrayExpression': return node.elements.every((e) => e && e.type !== 'SpreadElement' && isConstant(e, depth + 1));
      case 'ObjectExpression': return node.properties.every((p) => p.type === 'ObjectProperty' && !p.computed && isConstant(p.value, depth + 1));
      case 'Identifier': return node.name === 'undefined' || (constants.has(node.name) && isConstant(constants.get(node.name), depth + 1));
      default: return false;
    }
  };
  const isSafe = (node, kind, depth = 0) => {
    node = unwrap(node);
    if (!node || depth > 20) return false;
    if (isConstant(node)) return true;
    if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression') {
      const name = calleeName(node.callee, new Map());
      return Boolean(name && (SANITIZERS.any.has(name) || SANITIZERS[kind]?.has(name)));
    }
    if (node.type === 'TemplateLiteral') return node.expressions.every((e) => isSafe(e, kind, depth + 1));
    if (node.type === 'BinaryExpression') return node.operator === '+' ? isSafe(node.left, kind, depth + 1) && isSafe(node.right, kind, depth + 1) : true;
    if (node.type === 'ConditionalExpression') return isSafe(node.consequent, kind, depth + 1) && isSafe(node.alternate, kind, depth + 1);
    if (node.type === 'Identifier' && constants.has(node.name)) return isSafe(constants.get(node.name), kind, depth + 1);
    return false;
  };
  return { isConstant, isSafe };
}

const SQL_KEYWORD = /\b(?:SELECT|INSERT|UPDATE|DELETE)\b/;
const SHELL_DIRECT = new Set(['exec', 'execSync']);
const SHELL_ARGV = new Set(['execFile', 'execFileSync', 'spawn', 'spawnSync']);
const HTTP = new Set(['fetch', 'got', 'request', 'get', 'post', 'put', 'patch', 'delete', 'head']);
const FILE = new Set(['readFile', 'readFileSync', 'createReadStream', 'open', 'openSync', 'readdir', 'readdirSync']);
const TEMPLATE = new Set(['render', 'compile', 'renderString', 'template']);

/**
 * For one rule and one sink candidate node, returns:
 *   undefined → node is not a sink for this rule; 'safe' → harmless use; 'unsafe' → keep finding.
 */
function classifySink(ruleId, node, ctx) {
  const { isSafe, aliases } = ctx;
  const kind = ruleId.replace(/^(?:SRC|FLOW)-/, '');
  if (node.type === 'AssignmentExpression' && kind === 'XSS') {
    const target = node.left;
    if (target.type === 'MemberExpression' && !target.computed && ['innerHTML', 'outerHTML'].includes(target.property.name)) return isSafe(node.right, 'html') ? 'safe' : 'unsafe';
    return undefined;
  }
  if (node.type === 'JSXAttribute' && kind === 'XSS') {
    if (node.name.name !== 'dangerouslySetInnerHTML') return undefined;
    const value = node.value?.expression;
    const html = property(unwrap(value), '__html');
    return html && isSafe(html.value, 'html') ? 'safe' : 'unsafe';
  }
  if (node.type === 'NewExpression' && kind === 'EVAL') return calleeName(node.callee, aliases) === 'Function' ? (node.arguments.every((a) => isSafe(a, 'code')) ? 'safe' : 'unsafe') : undefined;
  if (node.type !== 'CallExpression' && node.type !== 'OptionalCallExpression') return undefined;
  const name = calleeName(node.callee, aliases);
  const args = node.arguments;
  const safeAll = (list, sanitizer) => list.every((a) => a.type !== 'SpreadElement' && isSafe(a, sanitizer));
  switch (kind) {
    case 'SHELL':
      if (SHELL_DIRECT.has(name)) return args.length && safeAll([args[0]], 'shell') ? 'safe' : 'unsafe';
      if (SHELL_ARGV.has(name)) {
        const options = unwrap(args.find((a, i) => i > 0 && unwrap(a)?.type === 'ObjectExpression'));
        const shell = property(options, 'shell');
        const viaShell = hasSpread(options) || (shell && !(unwrap(shell.value)?.type === 'BooleanLiteral' && unwrap(shell.value).value === false));
        if (!args.length || args[0].type === 'SpreadElement' || !isSafe(args[0], 'shell')) return 'unsafe';
        if (!viaShell) return 'safe';
        return unwrap(args[1])?.type === 'ArrayExpression' && safeAll(unwrap(args[1]).elements.filter(Boolean), 'shell') ? 'safe' : 'unsafe';
      }
      return undefined;
    case 'EVAL':
      if (name === 'eval') return args.length && safeAll([args[0]], 'code') ? 'safe' : 'unsafe';
      if ((name === 'setTimeout' || name === 'setInterval') && args.length && unwrap(args[0])?.type !== 'ArrowFunctionExpression' && unwrap(args[0])?.type !== 'FunctionExpression') return safeAll([args[0]], 'code') ? 'safe' : 'unsafe';
      return undefined;
    case 'SSRF': {
      const http = HTTP.has(name) && (name === 'fetch' || name === 'got' || ['axios', 'got', 'http', 'https', 'superagent', 'request', 'needle', 'ky'].includes(objectName(node.callee)));
      const axiosCall = unwrap(node.callee)?.type === 'Identifier' && ['axios', 'got', 'ky'].includes(unwrap(node.callee).name);
      if (!http && !axiosCall && !(name === 'request' && objectName(node.callee) === 'axios')) return undefined;
      const first = unwrap(args[0]);
      if (!first) return 'unsafe';
      if (first.type === 'ObjectExpression') {
        if (hasSpread(first)) return 'unsafe';
        const url = property(first, 'url'); const base = property(first, 'baseURL');
        return url && isSafe(url.value, 'url') && (!base || isSafe(base.value, 'url')) ? 'safe' : 'unsafe';
      }
      return isSafe(first, 'url') ? 'safe' : 'unsafe';
    }
    case 'PATH':
      if (name === 'sendFile' || name === 'download') {
        const options = unwrap(args[1]);
        if (options?.type === 'ObjectExpression' && property(options, 'root') && !hasSpread(options)) return 'safe';
        return args.length && isSafe(args[0], 'path') ? 'safe' : 'unsafe';
      }
      if (FILE.has(name)) return args.length && isSafe(args[0], 'path') ? 'safe' : 'unsafe';
      return undefined;
    case 'SSTI':
      if (TEMPLATE.has(name) && ['ejs', 'pug', 'jade', 'nunjucks', 'Handlebars', 'handlebars', '_', 'lodash', 'mustache', 'Mustache'].includes(objectName(node.callee))) return args.length && isSafe(args[0], 'code') ? 'safe' : 'unsafe';
      return undefined;
    case 'XSS':
      if ((name === 'send' || name === 'write' || name === 'end') && objectName(node.callee)) return safeAll(args, 'html') ? 'safe' : 'unsafe';
      if ((name === 'write' || name === 'writeln') && objectName(node.callee) === 'document') return safeAll(args, 'html') ? 'safe' : 'unsafe';
      if (name === 'insertAdjacentHTML') return args.length > 1 && isSafe(args[1], 'html') ? 'safe' : 'unsafe';
      return undefined;
    case 'SQL':
      if (['query', 'execute', 'raw', 'exec', '$queryRawUnsafe', '$executeRawUnsafe'].includes(name)) return args.length && isSafe(args[0], 'sql') ? 'safe' : 'unsafe';
      return undefined;
    default: return undefined;
  }
}

function sqlStringBuilders(nodes) {
  // Outermost `+` chains / templates whose literal parts contain an SQL keyword.
  const text = (node) => node.type === 'StringLiteral' ? node.value : node.type === 'TemplateLiteral' ? node.quasis.map((q) => q.value.cooked ?? q.value.raw).join(' ') : '';
  const literals = (node) => {
    node = unwrap(node);
    if (node?.type === 'BinaryExpression' && node.operator === '+') return literals(node.left) + ' ' + literals(node.right);
    return node ? text(node) : '';
  };
  return nodes.filter(({ node, parent }) => {
    const builder = (node.type === 'BinaryExpression' && node.operator === '+') || (node.type === 'TemplateLiteral' && node.expressions.length);
    if (!builder) return false;
    if (parent?.type === 'BinaryExpression' && parent.operator === '+') return false;
    return SQL_KEYWORD.test(literals(node));
  }).map(({ node }) => node);
}

/**
 * Removes provably harmless quick-mode findings in JS/TS files.
 * Returns { findings, removed: [{ ruleId, location, reason }], stats }.
 */
export function filterWithAst(findings, sourceByFile) {
  const stats = { filesParsed: 0, parseErrors: 0, removed: {} };
  const candidates = new Map();
  for (const finding of findings) {
    const file = finding.location?.file;
    if (!RULES.has(finding.ruleId) || !file || !JS_EXT.test(file) || !finding.location.line) continue;
    if (!candidates.has(file)) candidates.set(file, []);
    candidates.get(file).push(finding);
  }
  const drop = new Map();
  for (const [file, list] of candidates) {
    const text = sourceByFile.get(file);
    if (typeof text !== 'string') continue;
    let ast;
    try { ast = parseFile(file, text); stats.filesParsed++; } catch { stats.parseErrors++; continue; }
    if (ast.errors?.length) { stats.parseErrors++; continue; }
    const bindings = analyzeBindings(ast);
    const ctx = { ...makeEvaluator(bindings), aliases: bindings.aliases };
    const byLine = new Map();
    walk(ast.program, (node, parent) => {
      const line = node.loc?.start.line;
      if (!line) return;
      if (!byLine.has(line)) byLine.set(line, []);
      byLine.get(line).push({ node, parent });
    });
    for (const finding of list) {
      const nodes = byLine.get(finding.location.line) ?? [];
      const verdicts = [];
      for (const { node } of nodes) {
        const verdict = classifySink(finding.ruleId, node, ctx);
        if (verdict) verdicts.push(verdict);
      }
      if (finding.ruleId.endsWith('-SQL')) for (const builder of sqlStringBuilders(nodes)) verdicts.push(ctx.isSafe(builder, 'sql') ? 'safe' : 'unsafe');
      if (verdicts.length && verdicts.every((v) => v === 'safe')) drop.set(finding, 'AST: mọi lời gọi nhạy cảm trên dòng chỉ nhận hằng số, dữ liệu đã làm sạch hoặc dùng dạng không thể chèn lệnh.');
    }
  }
  const removed = [];
  const kept = findings.filter((finding) => {
    const reason = drop.get(finding);
    if (!reason) return true;
    stats.removed[finding.ruleId] = (stats.removed[finding.ruleId] ?? 0) + 1;
    removed.push({ ruleId: finding.ruleId, location: finding.location, reason });
    return false;
  });
  return { findings: kept, removed, stats };
}
