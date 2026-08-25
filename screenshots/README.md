# Screenshots — selected evidence

Selected captures from the assessment on an authorized, local OWASP Juice Shop instance. The full,
per-finding walkthrough (mechanism, steps, impact, remediation) is in the
[main README](../README.md#findings) and the [writeups](../writeups/).

| File | Shows |
|------|-------|
| `01-scoreboard-solved-challenges.jpg` | OWASP Juice Shop challenges solved — Login Admin, Password Strength (SQLi / weak creds), View Basket (IDOR), and more |
| `02-profile-page-csp-fields.jpg` | Profile page — the Username and Image URL fields used in the CSP bypass |
| `03-burp-repeater-injection-testing.jpg` | Burp Suite Repeater — editing and resending a request during injection testing |
| `04-burp-http-history.jpg` | Burp Proxy HTTP history — locating the target requests (`/rest/saveLoginIp`, `/api/*`) |
| `05-last-login-ip-page.jpg` | Last Login IP page — the render target of the HTTP header (`True-Client-IP`) test |
| `06-header-xss-channel-verified.jpg` | Header XSS — a benign `True-Client-IP: 1.2.3.4` is reflected into `lastLoginIp` (the header is processed) |
| `07-header-xss-sanitizer-detected.jpg` | Header XSS — a simple payload returns empty, revealing the server-side sanitizer to bypass |
| `08-header-xss-filter-mapping.jpg` | Header XSS — systematically mapping the allowlist filter (an `<img>` payload is stripped) before bypassing it |

> A curated subset. Most findings (DOM-based XSS, SQL Injection, IDOR, and the stored-XSS chains) are
> documented step-by-step, with exact payloads and expected results, in the [writeups](../writeups/)
> and the README findings table.
