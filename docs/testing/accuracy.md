# SrcAudit benchmark results

CI compares measured results with the checked-in [baseline](../../benchmarks/baseline.json). Each external dataset is pinned to a revision in [the benchmark harness](../../scripts/benchmark.mjs). The harness reads the source as text. External benchmark checkouts are stored in an ignored local directory.

## Published measurements

Measured on November 21, 2026 with Semgrep CE 1.184.0 for Deep Scan.

| Labeled dataset | Mode | Precision | Recall | False-positive rate |
| --- | --- | ---: | ---: | ---: |
| OWASP Python v0.1 (1,230 cases) | Quick Scan | 82.13% | 52.88% | 6.68% |
| OWASP Python v0.1 (1,230 cases) | Deep Scan | 91.29% | 62.61% | 3.47% |
| OWASP Java v1.2 (2,740 cases) | Quick Scan | 53.91% | 17.03% | 15.55% |
| OWASP Java v1.2 (2,740 cases) | Deep Scan | 57.14% | 16.96% | 13.58% |

On OWASP Python, Quick Scan found 239 of 452 vulnerable cases and flagged 52 of 778 safe cases. Deep Scan found 283 of 452 vulnerable cases and flagged 27 of 778 safe cases. Expanded Python rules for the default random generator and insecure Flask cookies contributed to the latest gain. Review the use of generated values before treating a random-source finding as a vulnerability.

The Deep Scan also completed on 86 reference JavaScript files and 43 reference Python files with zero warnings. These reference projects lack per-file vulnerability labels. Published percentages apply to their named, labeled dataset.

## Reproduce

```sh
npm run benchmark:semgrep
npm run benchmark:check
node scripts/benchmark.mjs --fetch --mode deep --suite owasp-python,owasp-java --check benchmarks/baseline.json --json results.json
```

| Suite | Data and purpose |
| --- | --- |
| `internal` | Repository fixtures for regression testing. The Quick Scan baseline has 93 pairs with 28 detections and one false positive. |
| `owasp-python` | [OWASP Benchmark Python](https://github.com/OWASP-Benchmark/BenchmarkPython) with published expected results. |
| `owasp-java` | [OWASP Benchmark Java](https://github.com/OWASP-Benchmark/BenchmarkJava) with published expected results. |
| `python-precision`, `python-holdout`, `python-coverage` | Targeted pairs for Python fixes, alternate syntax and framework cases. |
| `clean-js`, `clean-py` | Reference code from Express, Koa, Axios, Flask and Requests. Treat warnings as candidates for manual review. |
| `workflow-reference` | Workflow YAML from the pinned checkout, setup-node and setup-python repositories. The harness reads YAML without executing workflows. |

The full OWASP suites are split into batches for Deep Scan. The harness surfaces incomplete batches as errors. JSON output includes `falsePositiveCases` with the category, CWE and reported rules, and records Python AST precision counts.

### Metrics

- **Precision** is TP / (TP + FP).
- **Recall (TPR)** is TP / (TP + FN).
- **False-positive rate (FPR)** is FP / (FP + TN).
- **Score** is recall minus false-positive rate.
- **Findings per KLOC** counts findings per 1,000 lines. **Actionable findings per KLOC** excludes info-level findings.

A labeled OWASP case counts as detected when a finding in its file matches its CWE category or an accepted alias, such as CWE-327 for the CWE-328 benchmark hash category. The harness tracks findings outside the expected category separately. [Scoring implementation](../../scripts/benchmark-metrics.mjs)

## Historical rule changes

| Milestone | OWASP Python Deep Scan detections | False positives |
| --- | ---: | ---: |
| Before Flask, Python and Servlet expansion | 13/452 | 1/778 |
| After the expansion | 68/452 | 64/778 |
| After Python AST precision checks | 68/452 | 27/778 |
| After Flask HTML and cookies, and SAX rules | 107/452 | 27/778 |
| After expanded LDAP connection recognition | 116/452 | 27/778 |
| After hash, temporary file and TLS checks | 184/452 | 27/778 |
| November 21 verified release | 283/452 | 27/778 |

The first Python AST precision pass lowered FPR from 8.23% to 3.47% and increased precision from 51.52% to 71.58%, with recall at 15.04%. The change verified selected constants, path guards, XPath literal handling and redirect allowlists. The LDAP expansion detected 9 of 16 vulnerable LDAP cases with zero false positives in 13 safe cases in that category. [Python precision checks](../RULES.md#python-precision-checks)

The Quick Scan AST and context filters reduced the earlier internal fixture false positives from nine to one. On the Python reference projects at that stage, warnings fell from 0.687 to 0.25 per KLOC. Benchmark fixtures are designed to exercise particular rules and should be read alongside the independent OWASP suites.

## Update the baseline

Run `npm run benchmark:check` and the relevant Deep Scan suite. Investigate changes against the labeled cases and report any intentional trade-off. Update the baseline with `--update-baseline benchmarks/baseline.json` only after verifying the new results and scope.
