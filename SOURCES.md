# SrcAudit sources

The knowledge library describes weaknesses, verification guidance and advisory context. A finding's CWE links to the weakness definition. Consult the original API and advisory documentation when reviewing a finding.

## APIs and rules

| Topic | Primary references |
| --- | --- |
| SQL and shell commands | [OWASP SQL injection prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [OWASP OS command injection defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), [node-postgres parameters](https://node-postgres.com/features/queries), [Spring JDBC](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/jdbc/core/JdbcTemplate.html), [Laravel database](https://laravel.com/docs/12.x/database#running-a-select-query) |
| Browser output, URLs and filesystem | [OWASP XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [PortSwigger path traversal](https://portswigger.net/web-security/file-path-traversal), [Java Files](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/nio/file/Files.html) |
| Framework inputs and settings | [Express routing](https://expressjs.com/en/guide/routing.html), [Flask API](https://flask.palletsprojects.com/en/stable/api/), [Flask security](https://flask.palletsprojects.com/en/stable/web-security/), [Jakarta Servlet request](https://jakarta.ee/specifications/servlet/6.1/apidocs/jakarta.servlet/jakarta/servlet/http/HttpServletRequest.html), [Rails parameters](https://guides.rubyonrails.org/action_controller_overview.html#parameters), [Ruby Net::HTTP](https://docs.ruby-lang.org/en/master/Net/HTTP.html) |
| Object, template and XML handling | [PortSwigger prototype pollution research](https://portswigger.net/research/server-side-prototype-pollution), [PortSwigger template injection](https://portswigger.net/web-security/server-side-template-injection), [Python SAX](https://docs.python.org/3.12/library/xml.sax.html) |
| Tokens and CI configuration | [jsonwebtoken verification](https://github.com/auth0/node-jsonwebtoken#jwtverifytoken-secretorpublickey-options-callback), [GitHub Actions script injection](https://docs.github.com/en/actions/concepts/security/script-injections), [Dockerfile USER](https://docs.docker.com/reference/dockerfile/#user) |
| Dependency comparison | [npm SemVer](https://github.com/npm/node-semver), [PEP 440 implementation](https://github.com/renovatebot/pep440), [Composer versions and constraints](https://getcomposer.org/doc/articles/versions.md) |
| Scanner behavior | [Semgrep taint analysis](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview), [fflate ZIP documentation](https://github.com/101arrowz/fflate#readme), [Node.js test coverage](https://nodejs.org/learn/test-runner/collecting-code-coverage) |

## Offline data

The original snapshot contains [MITRE CWE](https://cwe.mitre.org/data/downloads.html), [OWASP WSTG v4.2](https://github.com/OWASP/wstg/tree/v4.2) and reviewed [GitHub advisories](https://docs.github.com/en/rest/security-advisories/global-advisories). The extensions add [OWASP ASVS v5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0_release), [OWASP API Security 2023](https://github.com/OWASP/API-Security/tree/33cea37b2ffde3e2e62f6b5d79a029a22a846633/editions/2023/en), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and additional reviewed advisories for selected packages.

The manifests record retrieval URLs, revisions, checksums and selection criteria. CISA KEV indicates exploitation observed in the wild. Applicability to a local version or deployment requires review. [Base manifest](data/manifest.json) · [Extension manifest](data/extensions-manifest.json) · [Data notices](data/NOTICE.md)

## Technical references and research

[Technical references](data/references.json) cover NIST SSDF, OpenSSF OSPS and Scorecard, OWASP SAMM and Benchmark, OSV Schema and GitHub SARIF. [Research entries](data/research.json) link to studies of static analyzer precision, coverage and workflow. Refer to the [benchmark results](docs/testing/accuracy.md) for SrcAudit's own measurements.
