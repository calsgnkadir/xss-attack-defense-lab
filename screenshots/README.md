# Screenshots — selected evidence

Selected captures from the assessment on an authorized, local OWASP Juice Shop instance. The full,
per-finding walkthrough (payloads, steps, impact, remediation) is in the
[report](../report/OWASP-JuiceShop-Security-Assessment.pdf).

| File | Shows |
|------|-------|
| `01-scoreboard-solved-challenges.jpg` | OWASP Juice Shop challenges solved — Login Admin, Password Strength (SQLi / weak creds), View Basket (IDOR), and more |
| `02-profile-page-csp-fields.jpg` | Profile page — the Username and Image URL fields used in the CSP bypass |
| `03-burp-repeater-injection-testing.jpg` | Burp Suite Repeater — editing and resending a request during header / API injection testing |
| `04-burp-http-history.jpg` | Burp Proxy HTTP history — locating the target requests (`/rest/saveLoginIp`, `/api/*`) |
| `05-last-login-ip-page.jpg` | Last Login IP page — the render target of the HTTP header (`True-Client-IP`) test |

> These are a curated subset. Most findings (DOM-based XSS, SQL Injection, IDOR, and the stored-XSS
> chains) are documented step-by-step, with exact payloads and expected results, in the full report.
