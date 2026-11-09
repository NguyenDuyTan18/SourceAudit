# Verification evidence

## External engines and CTF flags

- `npm run test:coverage` passed 81/81 tests. Fixture tests cover Docker isolation arguments, scoped result parsing, temporary capture cleanup, engine failure reporting, duplicate flags, header and error-response flags, and omission of cookie values from reports.
- An end-to-end API test with OWASP ZAP 2.17.0 and Nuclei 3.11.1 on a synthetic loopback site completed with four ZAP alerts, one Nuclei match, and one CTF flag in the same report. The target received two requests from the built-in scanner. The external tools processed a single saved response.
- Nuclei also passed a standalone Docker smoke test. Docker failed to extract the ZAP image when drive C ran out of space. Both native packages were installed on drive D after their SHA-256 checks passed.

## Write-up driven web probes

- The API integration test first failed because write-up imports did not select web probes. It now verifies that an OWASP HTML injection URL and SQL injection text select two reviewed checks. A third topic and a fenced payload in the same note add no requests of their own.
- A loopback fixture checks raw versus escaped HTML, a new SQL error on a 500 response versus an error present in the baseline, redacted evidence, and write-up references in findings. All test traffic uses GET without cookies.
- `npm run test:coverage` passed 79/79 tests. Runtime line coverage was 98.75%. The updated UI script passed syntax checks. This run exercised the integration through the local API.

## Pentest website from a URL

- RED/GREEN covered profile validation, the URL-to-report API flow, markup inside attributes, and rate-limit responses with oversized bodies. Local fixtures verify same-origin requests, redacted query and cookie values, recorded forms, and separate review findings for CORS and input reflection.
- Separate tests verify the 10-probe and 75-request caps, including redirect hops, and a negative fixture with static HTML and a fixed CORS origin.
- `npm run test:coverage` passed 78/78 tests. Runtime source coverage was 98.69% for lines and 86.87% for branches.
- Browser smoke test against a synthetic loopback site verified URL entry, submission, two scanned pages, three active probes, expandable form inventory, and JSON download. The browser reported zero console errors. The API test also verified HTML and TXT exports. Visual regression and accessibility certification were outside this smoke test.

| Self-review axis | Score | Evidence |
|---|---:|---|
| Accuracy | 4/5 | Positive and negative fixtures distinguish reflection signals from static responses. Detection accuracy across live applications is unmeasured. |
| Completeness | 3/5 | The URL-to-report flow is complete for guest GET checks. Authenticated pages and client-rendered routes need additional coverage. |
| Clarity | 4/5 | Results distinguish attempted and inconclusive probes. The full limits are in exports and the README. |
| Actionability | 5/5 | The browser confirmed the default URL form, inventory, and JSON download. |
| Conciseness | 4/5 | The UI keeps inventory collapsed by default. Repeated response-header findings remain visible by URL. |

Overall 4.0/5. The main coverage gap is authenticated and client-rendered behavior. The browser and fixture results support the guest GET scope described in the README.

## Latest extension, 2026-11-06

- 5004 merged context entries: 984 CWE, 97 WSTG, 345 ASVS v5.0.0 requirements, 33 API Security 2023 risk/scenario entries, 1777 reviewed advisories, 1768 CISA KEV records. New provenance in data/extensions-manifest.json; no download errors in the completed collection.
- 82 source rules: 76 signatures + 6 bounded text-flow rules. Twelve new signatures each have risky/benign regression inputs (HTML sinks, SQL raw APIs, PHP output, XPath, LDAP, Razor, Java/Go URL inputs and Rust TLS). ASVS IDs are attached explicitly to relevant new signatures.
- Final test run: **72/72 pass**, no skipped tests. src coverage: **98.98% lines, 84.06% branches, 89.87% functions**; not a precision/recall measurement or coverage of every external standard.
- RED/GREEN tests confirm ASVS verification context appears in HTML/TXT exports, and that an actual jquery version/advisory match can carry an exact-CVE CISA KEV tag with explicit wording that it is not evidence of local exploitation.
- One pre-existing test cleanup race became visible with the larger corpus: the recovery test started a demo scan then deleted its fixture directory before the scan finished (ENOTEMPTY). The test now waits for that job's completion before teardown; an isolated reproduction and the full suite pass. No production detection logic was reverted to make the test pass.
- OWASP scenario code blocks are removed at import; downloaded records are never interpreted as executable detectors. Package allowlists used during collection are fixed public names, never extracted from user projects.
- Previous limits still apply: heuristic signatures, approximate bounded text flow, offline advisory subset, npm/PyPI comparator scope, no exploit/reachability verification and no claimed universal language support.
- Installed-build browser QA confirmed the 82-rule/5004-record metadata, ASVS/API/KEV filter options and an exact ASVS-v5.0.0-1.2.4 query returning one requirement with its L1 context. No error-level browser logs were observed. Updated synthetic CLI demo completed with 55 findings, 47 advisory matches, one CISA KEV tag and one ASVS-linked finding; these are fixture results, not a live-site assessment.

Date: 2026-11-05. Runtime: Node.js v24.19.0, Windows / PowerShell. No third-party runtime or development dependencies.

## UI/upload revision (latest)

### Recognition revision — current result

- Corpus collected without source errors: 984 CWE v5.0 weaknesses, 97 WSTG v4.2 IDs, 936 reviewed/non-withdrawn GitHub advisories. Source URLs, dates and checksums are in data/manifest.json. License/attribution files are bundled.
- **70 source rules**: 64 signatures (16 original + 48 new), 6 bounded text-flow rules. This is not 70 independent vulnerability classes; 2017 context records are not counted as rules.
- Latest coverage run: **55/55 passing**, no skipped tests; **99.00% lines, 84.96% branches, 92.25% functions** for src. Browser code, updater and launcher are outside these percentages. Coverage does not measure detection accuracy.
- Twenty new signatures have risky/benign regression pairs across JS, Vue/Svelte, Python, PHP, Java, Go, C# and Ruby. Not every new signature has an individual positive/negative fixture; this remains a validation gap.
- Real range checks: lodash 4.17.20 matches CVE-2021-23337; 4.17.21 does not. Werkzeug 3.0.2 matches CVE-2024-34069; 3.0.3 does not. Only synthetic manifests were scanned; no vulnerable package was installed/exploited.
- Flow checks cover aliases, overwritten values, parameterized queries and a RED/GREEN regression where a constant string was mistaken for a tainted identifier of the same name.
- Knowledge API checks cover real CVE lookup, bounded pages, kind filters and invalid filters. CLI research demo completed with 14 findings, 7 version matches and 2 flow candidates.
- Browser QA on the installed D: build verified 70 source rules / 2017 context records, the synthetic 14-finding demo, package/range/fix evidence, and CVE-2021-23337 search returning exactly one advisory. Expanded details showed npm lodash <4.17.21 / fixed 4.17.21 and primary source links. No error-level logs were observed during the demo check. A screenshot is saved beside the release ZIP; no public-site scan or vulnerable-package execution was used.
- Limits: no full AST/interprocedural taint, deployment/reachability verification, universal language semantics, complete CVE feed or measured real-world precision/recall. Automatic affected-range matching is for supported npm/pinned PyPI manifests. Public URL checks remain passive/configuration checks.

Earlier revision evidence is retained below as history.

The later UI revision adds one bundled dependency, `fflate`, for streaming ZIP handling. `npm install fflate --ignore-scripts` completed with zero reported dependency vulnerabilities. The original CLI-only evidence below is retained as history.

- `npm run test:coverage`: **27/27 passing**, no skipped tests. Runtime source: **99.86% lines, 86.02% branches, 93.68% functions**. Browser JavaScript and launchers are outside these percentages.
- Added RED/GREEN evidence for the new UI module, source-upload endpoint and archive extractor. Source-upload API initially returned 404 before implementation; the same test now verifies relative evidence, uploaded target label and format counts.
- Boundary tests cover session token, Host/Origin checks, forged Host through a raw HTTP request, cross-site requests, JSON size/type/parse errors, concurrent-job rejection and recovery after failed work.
- Upload tests cover multiple files, source locations, ZIP deflate extraction, dependency exclusion, invalid ZIP/base64, path traversal, Windows reserved paths, case-insensitive duplicates and expanded-size limits. Temporary uploads only materialize regular files in an owned temporary directory.
- UI browser QA used the in-app browser because the separate Playwright extension was absent. A real file chooser selected the synthetic `examples/demo-src/app.js`, then the UI scanned it and showed **9 findings**, `.js (1)` in the format inventory, relative file:line and redacted evidence. This differs from the 10-finding CLI sample that also enables a custom redirect rule.
- Browser checks verified severity filtering, selecting SQL evidence/remediation and searching the knowledge library for prototype pollution. No error-level browser logs were observed at that point.
- At 375px and 1440px viewport widths, the DOM page width stayed within the viewport; the mobile navigation intentionally scrolls horizontally. No prior visual baseline exists, so visual-regression comparison is **inconclusive**, not a claimed pass.
- No claim of full language semantics, universal stack coverage, accessibility certification, CVE coverage or production readiness is made. Source format inventory is not detection coverage.

## Scope and user journeys

1. Given a source folder or file, generate findings with file:line, redacted evidence, estimated severity, CWE and remediation without executing project code.
2. Given an authorized HTTP(S) URL, inspect a bounded set of responses and distinguish failed checks from findings.
3. Extend recognition with literal custom rules and link imported write-up topics to review guidance.
4. Produce terminal, JSON, TXT and self-contained HTML reports; use nonzero status for incomplete scans or configured severity thresholds.

## TDD record

- Initial RED: `node --test` failed because the newly referenced scanner modules did not exist.
- Research/custom-rule RED: `node --test test/knowledge.test.mjs` executed and failed because `CUSTOM-TEST` and `SRC-SSRF` were not detected. Both passed after implementation.
- Resource-limit RED: the oversized-response test initially failed for `/big`, revealing that the response could emit `end` before a request-destroy error reached the promise. The fix rejects at the byte-limit boundary. The same test now passes.
- Environment-secret RED: the unquoted `.env` credential test found zero results instead of two. Config assignment recognition was added; raw values remain redacted.
- Classification RED: `node --test --test-name-pattern="shell exec"` failed because JavaScript shell exec was also reported as eval. The implementation now reserves Python exec handling for Python, and the regression passes.
- Long-line RED: a 9000-character source line was initially scanned as complete. It is now skipped with an explicit partial result; matching input lines is bounded at 8192 characters.

No Git repository was present in the deliverable folder; no commits, pushes, remote writes or public-site scans were made.

## Final checks

`npm run test:coverage` — **18/18 passing**, no skipped tests.

| Runtime module | Lines | Branches | Functions |
|---|---:|---:|---:|
| knowledge.mjs | 100.00% | 73.21% | 100.00% |
| report.mjs | 100.00% | 81.25% | 81.82% |
| source.mjs | 100.00% | 89.13% | 87.50% |
| url.mjs | 99.41% | 85.92% | 100.00% |
| Overall | 99.79% | 84.16% | 93.15% |

Coverage is for `src/*.mjs`; the CLI is validated separately by child-process E2E tests, not included in these coverage percentages. Coverage does not establish detection precision or absence of security bugs.

`node --check` — scanner entry point, all runtime modules and test files passed syntax checks. `--list-rules` and knowledge search were exercised. No separate TypeScript build/typecheck or lint dependency is configured.

## Guarantees covered

| Behavior | Evidence |
|---|---|
| Source rules include locations, review status and fixes | Synthetic JS, Python, PHP/config fixtures |
| Known embedded credentials are not copied to reports | Assertions on JSON serialization of fixtures |
| Comments/dependency folders/binary/oversized files and configured limits | Unit/integration tests |
| DNS/IP policy, credentials in URL, unsupported schemes/ports | Input-boundary tests |
| Validated DNS result pinned to connection | Mock transport with a resolver that would return a private address on a second lookup; resolver called once |
| Contextual header checks, cookie values hidden, CORS wildcard informational | Response analysis tests |
| Same-origin crawl and query redaction | Local HTTP server integration |
| Redirect/timeout/size/content-encoding/HTTP failures stay incomplete | Local HTTP server error paths |
| Reports escape untrusted markup and contain no executable external content | HTML escaping/CSP output assertions |
| Write-up import avoids retaining body credentials and attaches relevant topics | Import/index/enrichment tests |
| Custom rules do not execute code or accept regex | Schema validation and source matching tests |
| CLI writes output and returns expected exit status | Spawned process E2E tests |

## Known verification limits

No real public website, third-party source repository, live TLS server, proxy, non-Windows OS or Node version other than v24.19.0 was tested. DNS pinning is validated with a mocked HTTP transport; local real HTTP integration uses loopback. HTML assertions verify output encoding and structure, not a screenshot-based browser review. Filesystem permission/race errors, sophisticated multiline obfuscation and all language grammars are not exhaustively tested. Regex source matching has no data-flow analysis and has no benchmarked precision/recall. No automated exploit verification or CVE database is included.

## Self-review

| Axis | Score | Evidence / improvement |
|---|---:|---|
| Accuracy | 4/5 | Findings separate observed configuration from review-needed patterns; real-world precision remains unmeasured. Next improvement: a labeled detection corpus. |
| Completeness | 4/5 | Both requested input modes, detailed outputs, custom rules and write-up context exist. Full semantic analysis needs an additional engine. |
| Clarity | 4/5 | Vietnamese output, examples and explicit limits; individual rules can still require specialist interpretation. |
| Actionability | 4/5 | Runs without package installation and supplies file:line/review steps. Runtime confirmation remains a separate manual task. |
| Conciseness | 4/5 | Terminal output prioritizes evidence and fixes; large finding sets repeat remediation, better consumed through JSON. |

Average 4.0/5. Highest-impact follow-ups: benchmark false positives/negatives, add parser/taint integration, then deduplicate repeated findings in large reports. These are follow-ups, not claimed current features.
