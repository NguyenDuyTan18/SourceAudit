# Ngrok access — 2026-11-08

Journey derived from the reported public HTTP 403: open the configured ngrok domain, sign in, and use the existing UI/API without granting anonymous access to scans, reports or source files.

## Changes and evidence

- Added an optional `.ui-public.json` configuration with one HTTPS origin and generated credentials. The file is excluded from Git. Invalid/incomplete settings prevent startup. Default operation without this file remains local.
- Public Host and an exact configured X-Forwarded-Host are supported. Unrecognized hosts, conflicting Origin, cross-site API requests and invalid session tokens are rejected.
- A native HTML sign-in form creates an origin-bound session lasting eight hours. HTTPS sessions use Secure, HttpOnly, SameSite=Strict cookies; restart revokes sessions. Sessions are bounded to 100. Basic authentication remains available to command-line clients. All application assets and APIs require authentication.
- The launcher authenticates its health check without logging credentials. Ngrok was restarted with the existing account configuration, the requested public domain and `--inspect=false`; no authtoken was read or changed.

| Behavior | RED | GREEN |
|---|---|---|
| Configured public origin requires authentication and accepts authenticated requests | `node --test --test-name-pattern='public access\|public-access' test/ui.test.mjs`: 2 failures, public host returned 403 and invalid config did not throw | Same target passed both tests |
| Browser-compatible form sign-in | Public-access test expected login HTML HTTP 200 and received 401 | Form, cookie, session-token and wrong-credential assertions passed |
| Native form retains its Origin for CSRF validation | Browser POST logged `Origin: null`; new header assertion expected `same-origin`, received `no-referrer` | Login page sets `Referrer-Policy: same-origin`; authenticated browser navigation succeeded |

The login form rejects missing CSRF, missing/foreign Origin, unsupported content type and bodies over 4096 bytes. Anonymous API/report requests receive 401. Wrong session token, forged Host, foreign origin, cross-origin cookie reuse and cross-site API requests are covered by integration assertions.

`npm run test:coverage`: **90/90 passed**, zero skips. Overall lines **97.18%**, branches **85.07%**, functions **93.75%**; UI server lines **98.05%**. `node --check` passed for `ui.mjs`, `src/ui-server.mjs` and `test/ui.test.mjs`. No separate build/typecheck/lint script exists. No Git repository was present, so no checkpoint commits were created.

Live HTTP checks through ngrok confirmed anonymous 401, authenticated home/bootstrap/script 200 and foreign Origin 403. Browser verification initially exposed unsupported Basic-auth navigation, then the null-Origin form issue. After the final fix, the in-app browser successfully submitted the sign-in form, followed its redirect, and displayed the complete scanner UI with 82 rules and 5004 knowledge items. Temporary selected-header diagnostics were removed. No external pentest target was scanned for this verification.

The referrer policy behavior is documented by [MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy#effect_on_the_origin_header). Runtime validation covers the current Windows/Node/browser environment; expiry and session-cap eviction were not time-travel/load tested. Ngrok remains dependent on the running agent, network and account limits. Credentials are kept in the local ignored configuration and are not included in this report.

## Self-evaluation

| Axis | Score | Evidence / improvement |
|---|---:|---|
| Accuracy | 4 | Confirmed public HTTP responses and completed browser sign-in. Expiry/cap behavior is code-reviewed rather than clock/load tested. |
| Completeness | 4 | Actual ngrok UI and API work, with rejection tests and launcher support. Current validation covers one browser environment. |
| Clarity | 4 | Vietnamese login and direct credentials supplied. Password recovery still uses local configuration. |
| Actionability | 5 | Service and tunnel are running; the public browser tab is signed in and retained. |
| Conciseness | 4 | Login is plain HTML without dependencies. Existing local-session and new authentication checks make the server handler longer; future access changes could warrant extraction. |

Average **4.2/5**. Highest-impact follow-ups: clock-based expiry/cap tests and a second-browser check. Self-check: the user can immediately verify the working public application in the retained tab. No remaining blocker for the requested access fix.
