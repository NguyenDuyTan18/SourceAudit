# Local home-page navigation — 2026-11-08

Journey derived from the reported local-access error: opening the home page from an external link must load the application, then allow its own authenticated API requests.

## Evidence

- RED: `node --test --test-name-pattern='external link' test/ui.test.mjs` failed with `403 !== 200` using HTTP navigation headers.
- GREEN: `node --test test/ui.test.mjs` passed 13/13 tests.
- Coverage: `npm run test:coverage` passed 88/88 tests, zero skips; overall lines 97.07%, branches 84.64%, functions 93.98%. UI server lines 97.44%.
- Syntax: `node --check src/ui-server.mjs` and `node --check test/ui.test.mjs` passed. No separate build, typecheck or lint script exists.
- Live: restarted the verified UI process at `http://127.0.0.1:8787`; external-link navigation headers now return HTTP 200. Browser reload displayed the input form and loaded corpus counts.

| Guarantee | Evidence |
|---|---|
| External top-level GET navigation may open `/` | New HTTP integration test, live HTTP request |
| Cross-site API, health, scripts, styles, iframe, CORS and POST requests remain blocked | New integration test |
| Foreign Origin and forged Host remain blocked | Integration assertions |
| API calls from the loaded local session work | Bootstrap assertions and browser corpus counts |

Only top-level document navigation to the home page gets the exception. The local host and session restrictions remain in place. No public tunnel was enabled. No Git repository is present, so no checkpoint commits were created. Coverage does not prove absence of security defects; browser link headers were reproduced through HTTP integration, and direct reload was checked visually.

## Self-evaluation

| Axis | Score | Evidence / improvement |
|---|---:|---|
| Accuracy | 4 | Reproducer fails before and passes after; browser reload works. Actual external browser-link headers were simulated; a browser-origin link test could add evidence. |
| Completeness | 4 | Both navigation and rejection cases covered; verification is on the current Windows/Node environment only. |
| Clarity | 4 | Error cause and working URL supplied in Vietnamese; the existing generic access error could identify its specific cause. |
| Actionability | 5 | Updated service is running at the original port and the application tab is open. |
| Conciseness | 4 | Production change is limited to request validation; the regression fixture could be shared if more navigation cases are added. |

Average 4.2/5. Improvement priorities: exercise a real external-page link in browser automation, then make rejected-request diagnostics more specific. Self-check: the user can verify the delivered local fix immediately through the open application; public ngrok support remains a separate request.
