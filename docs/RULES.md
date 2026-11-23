# Quick Scan rule catalog

See [the README](../README.md) for installation and [Sources](../SOURCES.md) for the underlying API documentation and research. See [Semgrep rule development](semgrep-rules.md) for the Deep Scan rule packs and their validation.

## Quick Scan

Use `node scan.mjs --list-rules` to print the current quick-scan catalog with stable IDs and CWE mappings. The list is generated from the same registry the scanner uses.

| Family | Scope |
| --- | --- |
| `SRC-*` | General signatures for dynamic execution, SQL, HTML, file paths, outbound requests, XML, TLS, secrets and debug settings. [Source rules](../src/source.mjs) |
| `EXT-*`, `SC-*` | API- and framework-specific patterns, including Ruby, Go, PHP, Java, Python, JavaScript, TypeScript, Rust and C#. [Extended rules](../src/extended-rules.mjs) · [Scenario rules](../src/scenario-rules.mjs) |
| `CFG-*` | Structural YAML checks for GitHub Actions token permissions and Docker Compose confinement. [Configuration rules](../src/config-quick.mjs) |
| `FLOW-*` | Short, local text-based data flow for selected sensitive calls. [Flow rules](../src/flow.mjs) |
| Custom JSON rules | Optional literal patterns supplied through the CLI. [Example rule file](../examples/custom-rules.json) |
| Dependency advisories | Resolved lockfile versions matched against the bundled advisory snapshot in both modes. [Dependency matching](../src/dependencies.mjs) |

### Configuration checks

| Rule | What it checks |
| --- | --- |
| `CFG-ACTIONS-WRITE-ALL` | `permissions: write-all` at workflow or job level in `.github/workflows/*.yml` and `.yaml` files. [GitHub Actions permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions) |
| `CFG-COMPOSE-UNCONFINED` | A service's `security_opt` list sets seccomp or AppArmor to `unconfined` in `compose.yaml`, `docker-compose.yml` and their `.yaml`, `.yml` and override variants. [Compose security options](https://docs.docker.com/reference/compose-file/services/#security_opt) |

These checks read explicit YAML fields and report the relevant line. Compose overlays, includes, variable interpolation and YAML aliases require review of the effective configuration.

### How Quick Scan filters findings

The JS/TS syntax-tree filter checks selected calls for constants and recognized sanitizers. For PostgreSQL-style query objects, it recognizes fixed SQL with a positional placeholder and a separate values array. Dynamic query text, object spreads and computed keys remain eligible for review. [AST filter](../src/ast-filter.mjs) · [node-postgres query configuration](https://node-postgres.com/features/queries#query-config-object)

Secret rules filter clear references such as `${DB_PASSWORD}` and classify explicit placeholders such as `your-password-here` as informational. A reference with a literal fallback, such as `${DB_PASSWORD:-local-value}`, remains eligible for review. Reports redact credential values. [Context checks](../src/context.mjs)

### Dependency file coverage

| Ecosystem | Supported inputs |
| --- | --- |
| npm | `package-lock.json`, `npm-shrinkwrap.json`, Yarn v1/Berry `yarn.lock` and supported `pnpm-lock.yaml` versions |
| PyPI | Exact `==` pins in `requirements*.txt`, `Pipfile.lock` and Poetry lock format 1.x or 2.x in `poetry.lock` |
| Composer | Exact stable versions in `composer.lock` |

Poetry matching reads versions recorded in the lockfile, including optional and development groups. Entries with an explicit alternate source count as unresolved for PyPI matching. Review the dependency counts and the packages actually deployed when interpreting an advisory match. [Dependency matching](../src/dependencies.mjs) · [Poetry lockfile behavior](https://python-poetry.org/docs/basic-usage/#installing-with-poetrylock)

## Add or update a rule

Document the API, input and sensitive argument with an authoritative reference and a CWE. Keep rule IDs and metadata in sync. Include matched and fixed examples, and test the rule ID, location and coverage. Run `npm test` and the relevant Quick Scan benchmark before updating the baseline. [Benchmark guide](testing/accuracy.md)
