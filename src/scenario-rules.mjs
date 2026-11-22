const js = ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx'];
const rule = (id, cwe, title, match, exts, remediation, requirement) => ({
  id: 'SC-' + id, cwe, severity: 'medium', title, match, exts,
  condition: 'Review whether untrusted input reaches this API, which protections apply and how the application is deployed.',
  impact: `The pattern matches CWE-${cwe}. Input may trigger an unintended operation when the relevant protections are absent.`,
  fix: remediation, asvs: requirement ? ['ASVS-v5.0.0-' + requirement] : []
});
export const SCENARIO_RULES = [
  rule('JS-INSERT-HTML', 79, "insertAdjacentHTML receives untrusted input", /\.insertAdjacentHTML\s*\([^\n]*(?:req\.|request\.|location\.(?:hash|search))/, js, "Prefer insertAdjacentText or textContent. Sanitize markup when inserting HTML is required.", '1.2.1'),
  rule('JS-FRAGMENT', 79, "createContextualFragment receives URL or request data", /\.createContextualFragment\s*\(\s*(?:location\.(?:hash|search)|req\.|request\.)/, js, "Keep markup fixed or sanitize HTML before creating the fragment.", '1.2.1'),
  rule('JS-SQL-LITERAL', 89, "Sequelize literal() receives request data", /\b(?:Sequelize|sequelize)\.literal\s*\(\s*(?:req\.|request\.)/, js, "Bind values and allowlist any dynamic SQL identifiers.", '1.2.4'),
  rule('PHP-SQL-RAW', 89, "Laravel DB::raw() receives request data", /\bDB::raw\s*\(\s*\$request(?:->|\[)/, ['.php'], "Bind query values and allowlist any dynamic SQL identifiers.", '1.2.4'),
  rule('PY-SQL-RAW', 89, "Django raw SQL uses an interpolated string", /\.raw\s*\(\s*f["']/, ['.py'], "Keep the SQL fixed and bind query values through params.", '1.2.4'),
  rule('PHP-PRINT', 79, "PHP prints request data directly", /\bprint\s+\$_(?:GET|POST|REQUEST)\b/, ['.php'], "Encode output for the HTML, attribute or JavaScript context.", '1.2.1'),
  rule('PY-XPATH', 643, "XPath expression receives request data", /\.xpath\s*\(\s*request\.(?:args|GET|POST|form)/, ['.py'], "Use a fixed XPath expression and bind variables."),
  rule('JS-LDAP', 90, "LDAP search filter receives request data", /\.search\s*\([^\n]*\bfilter\s*:\s*(?:req\.|request\.)/, js, "Keep the filter structure fixed and escape values using the LDAP library."),
  rule('CS-TEMPLATE', 1336, "Razor template is built from request data", /\bRazor\.Parse\s*\(\s*Request\./, ['.cs', '.cshtml'], "Use a fixed template and pass validated request data through the model."),
  rule('JAVA-SSRF', 918, "Java creates a URL from a request parameter", /\bnew\s+URL\s*\(\s*request\.getParameter\s*\(/, ['.java', '.kt'], "Allowlist destinations and validate resolved network addresses and redirects."),
  rule('GO-SSRF', 918, "Go HTTP client receives a request-provided URL", /\bhttp\.(?:Get|Post|Head)\s*\(\s*(?:r|request)\.(?:FormValue|URL\.Query)/, ['.go'], "Allowlist destinations, validate resolved addresses and redirects, and restrict outbound traffic."),
  rule('RUST-TLS', 295, "Rust HTTP client accepts invalid certificates", /\.danger_accept_invalid_certs\s*\(\s*true\s*\)/, ['.rs'], "Enable TLS verification and configure a trusted CA.")
];
