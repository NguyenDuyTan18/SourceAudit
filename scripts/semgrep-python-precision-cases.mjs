// Synthetic Python modules for static analysis only. The benchmark never imports them.
const flask = (body, imports = []) => ['from flask import request', ...imports, '', 'def report():', ...body.map((line) => '    ' + line)].join('\n');
const pair = (name, cwe, vulnerable, fixed) => ({ name, ext: 'py', cwe, vulnerable, fixed });

const xpath = (body) => flask(body, ['from lxml import etree']);
const path = (body) => flask(body, ['from pathlib import Path', 'from flask import send_file']);
const xpathQuery = `query = f"/catalog/item[@sku='{value}']"`;
const readPath = [
  'base = Path("/srv/catalog").resolve()',
  'candidate = (base / request.args["document"]).resolve()',
];

export const pythonPrecisionCases = [
  pair('xpath-bound-value', 'CWE-643',
    xpath(['value = request.args["sku"]', xpathQuery, 'return etree.XPath(query)']),
    xpath(['value = request.args["sku"]', 'select = etree.XPath("/catalog/item[@sku=$sku]")', 'return select(document, sku=value)'])),
  pair('xpath-rejects-literal-delimiter', 'CWE-643',
    xpath(['value = request.args["sku"]', `if '"' in value:`, '    return None', xpathQuery, 'return etree.XPath(query)']),
    xpath(['value = request.args["sku"]', `if "'" in value:`, '    return None', xpathQuery, 'return etree.XPath(query)'])),
  pair('xpath-removes-literal-delimiter', 'CWE-643',
    xpath(['value = request.args["sku"]', `clean = value.replace('"', '')`, xpathQuery.replace('{value}', '{clean}'), 'return etree.XPath(query)']),
    xpath(['value = request.args["sku"]', `clean = value.replace("'", "")`, xpathQuery.replace('{value}', '{clean}'), 'return etree.XPath(query)'])),
  pair('xpath-constant-conditional-branch', 'CWE-643',
    xpath(['choice = request.args["sku"]', 'level = int(request.args["level"])', 'value = "standard" if level + 2 > 5 else choice', xpathQuery, 'return etree.XPath(query)']),
    xpath(['choice = request.args["sku"]', 'level = 4', 'value = "standard" if level + 2 > 5 else choice', xpathQuery, 'return etree.XPath(query)'])),
  pair('file-canonical-containment', 'CWE-22',
    path([...readPath, 'if candidate.is_relative_to(base):', '    log(candidate)', 'return send_file(candidate)']),
    path([...readPath, 'if not candidate.is_relative_to(base):', '    raise ValueError("Unknown document")', 'return send_file(candidate)'])),
  pair('file-containment-then-reassignment', 'CWE-22',
    path([...readPath, 'if candidate.is_relative_to(base):', '    candidate = Path(request.args["override"])', '    return send_file(candidate)', 'return None']),
    path([...readPath, 'if candidate.is_relative_to(base):', '    return send_file(candidate)', 'return None'])),
  pair('redirect-origin-check-fails-closed', 'CWE-601',
    flask(['target = request.args["next"]', 'try:', '    parsed = urlsplit(target)', '    if parsed.netloc not in ("docs.example.test",) or parsed.scheme != "https":', '        return "/", 400', 'except ValueError:', '    log("Invalid URL")', 'return redirect(target)'], ['from urllib.parse import urlsplit', 'from flask import redirect']),
    flask(['target = request.args["next"]', 'try:', '    parsed = urlsplit(target)', '    if parsed.netloc not in ("docs.example.test",) or parsed.scheme != "https":', '        return "/", 400', 'except ValueError:', '    return "/", 400', 'return redirect(target)'], ['from urllib.parse import urlsplit', 'from flask import redirect'])),
  pair('file-recheck-preserves-other-input', 'CWE-22',
    flask(['suffix = "summary.txt" if 2 + 3 > 4 else request.args["file"]', `return open(f"{request.args['folder']}/{suffix}")`], ['from project_config import REPORTS_ROOT']),
    flask(['suffix = "summary.txt" if 2 + 3 > 4 else request.args["file"]', 'return open(f"{REPORTS_ROOT}/{suffix}")'], ['from project_config import REPORTS_ROOT'])),
];

export const pythonPrecisionHoldout = [
  pair('holdout-xpath-different-template', 'CWE-643',
    xpath(['value = request.headers["X-Region"]', `if "'" in value:`, '    return None', 'value = request.args["region"]', `search = f"//office[@region='{value}']"`, 'return etree.ETXPath(search)']),
    xpath(['value = request.headers["X-Region"]', `if "'" in value:`, '    return None', `search = f"//office[@region='{value}']"`, 'return etree.ETXPath(search)'])),
  pair('holdout-file-component-guard', 'CWE-22',
    path(['base = Path("/opt/published").resolve()', 'child = base / request.args["asset"]', 'if child.is_relative_to(base):', '    return open(child)', 'return None']),
    path(['base = Path("/opt/published").resolve()', 'child = (base / request.args["asset"]).resolve()', 'if child.is_relative_to(base):', '    return open(child)', 'return None'])),
  pair('holdout-xpath-literal-match', 'CWE-643',
    xpath(['region = request.args["region"]', 'mode = request.args["mode"]', 'match mode:', '    case "direct":', '        value = region', '    case _:', '        value = "default"', xpathQuery, 'return etree.XPath(query)']),
    xpath(['region = request.args["region"]', 'mode = "fallback"', 'match mode:', '    case "direct":', '        value = region', '    case _:', '        value = "default"', xpathQuery, 'return etree.XPath(query)'])),
];
