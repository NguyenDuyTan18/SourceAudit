# Semgrep rule development

Deep Scan runs the bundled Semgrep CE rule packs. This guide covers editing and validating those rules. For the built-in Quick Scan rules, see the [Quick Scan catalog](RULES.md#quick-scan).

## Runtime rule packs

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

## Develop and validate

1. Edit the matching YAML pack and its rule metadata in [the Semgrep runner](../src/semgrep.mjs). Keep rule IDs stable and include a CWE, severity and remediation.
2. Add a synthetic matched example and a fixed counterpart to the relevant fixture set. Assert the intended rule, source filename and location.
3. Validate with the bundled or locally installed Semgrep CE.

```sh
npm run benchmark:semgrep
```

The default validation runs Semgrep only. To see both engines on the same fixture pairs, run `npm run benchmark:semgrep -- --compare-quick`. Scan uploads and imported notes are separate from rule development. [Benchmark guide](testing/accuracy.md)
