# SrcAudit rule catalog

See [the README](../README.md) for installation and [Sources](../SOURCES.md) for the underlying API documentation and research.

## Deep Scan with Semgrep

SrcAudit stages selected files under temporary names and loads three bundled YAML rule packs. The Semgrep runner disables metrics, reads JSON results and maps them back to the original relative paths. The report records how many files SrcAudit selected and how many Semgrep analyzed. Temporary copies are removed after each run. [Semgrep runner](../src/semgrep.mjs)

| Coverage | Rule pack |
| --- | --- |
| JavaScript and TypeScript SQL, shell, HTML, URL, filesystem, template, object and deserialization checks | [JavaScript and TypeScript](../rules/semgrep-js-ts.yml) |
| Python, PHP, Java, Go and C# checks for selected request data flows into SQL, commands, paths, redirects, parsers and HTTP clients | [Multiple languages](../rules/semgrep-multilang.yml) |
| GitHub Actions permissions and script input, Dockerfile users, Node JWT keys, Spring JDBC, Laravel SQL, Rails HTTP and supplemental Python rules | [Frameworks and configuration](../rules/semgrep-framework-config.yml) |

Taint rules follow values from known inputs to sensitive operations within a function. Structural rules match a particular API call or configuration. Reports distinguish `semgrep-taint` and `semgrep-pattern`. Rule IDs map to CWE, severity, impact and remediation. [Semgrep taint analysis](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview)

### Python precision checks

SrcAudit uses the Python AST to validate selected results involving paths, XPath, evaluated expressions, Flask redirects and HTML, SAX, LDAP and password-independent digest use. It preserves the finding when parsing fails or there is insufficient evidence. [Python AST checks](../src/python-precision.py)

- **Paths.** The checker looks for a resolved path under an approved resolved root and a guard that controls the relevant file access. For a verified constant portion of a path, it can re-run Semgrep on a temporary copy.
- **XPath.** The checker recognizes selected contexts where delimiter handling makes an interpolated value fixed to the intended literal position. Prefer bound XPath variables in application code.
- **Redirects.** The checker recognizes selected cases with a fixed HTTPS hostname allowlist and an early exit for rejected destinations.
- **HTML, LDAP and XML.** The checker can prove selected argument values constant through simple assignments and string operations.
- **Hashes.** The checker considers whether a digest factory is used only through a recognized HMAC call and preserves independent digest findings.

JSON reports expose the filtered counts and reasons at `stats.sourceAnalysis.pythonPrecision`. [Benchmark measurements](testing/accuracy.md#historical-rule-changes)

## Quick Scan

Use `node scan.mjs --list-rules` to print the current quick-scan catalog with stable IDs and CWE mappings. The list is generated from the same registry the scanner uses.

| Family | Scope |
| --- | --- |
| `SRC-*` | General signatures for dynamic execution, SQL, HTML, file paths, outbound requests, XML, TLS, secrets and debug settings. [Source rules](../src/source.mjs) |
| Language and configuration rules | API- and framework-specific patterns, including Ruby, Go, PHP, Java, Python, JavaScript, TypeScript, Rust and C#. [Extended rules](../src/extended-rules.mjs) · [Scenario rules](../src/scenario-rules.mjs) |
| `FLOW-*` | Short, local text-based data flow for selected sensitive calls. [Flow rules](../src/flow.mjs) |
| Custom JSON rules | Optional literal patterns supplied through the CLI. [Example rule file](../examples/custom-rules.json) |
| Dependency advisories | Resolved lockfile versions matched against the bundled advisory snapshot in both modes. [Dependency matching](../src/dependencies.mjs) |

The JS/TS AST filter reviews constants, recognized sanitizers and selected forms of process and file APIs. Context also affects confidence and severity for test or example code and placeholder values. [AST filter](../src/ast-filter.mjs) · [Context checks](../src/context.mjs)

## Add or update a rule

Document the API, input and sensitive argument with an authoritative reference and a CWE. Keep rule IDs and metadata in sync. Include matched and fixed examples, and test the rule ID, location and coverage. Run `npm test` and `npm run benchmark:semgrep` for Deep Scan rules. Run the relevant labeled benchmark before updating the baseline. [Benchmark guide](testing/accuracy.md)
