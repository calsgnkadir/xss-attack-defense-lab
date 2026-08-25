# Writeups

Short, mechanism-first technical writeups on the vulnerability classes practised
in this repository. The goal is to **explain how each bug works** — not to list
payloads — using the hands-on findings and local labs here as concrete examples.

| # | Title | Class | Based on |
|---|-------|-------|----------|
| 01 | [Why filtering isn't protection: the nested-tag sanitizer bypass](01-filtering-is-not-protection.md) | Sanitizer bypass / mutation | Findings 2 & 8 |
| 02 | [Mutation XSS (mXSS): when the browser rewrites your "clean" HTML](02-mutation-xss.md) | Mutation XSS | [`labs/mxss-lab.html`](../labs/mxss-lab.html) |
| 03 | [Assessing DOM XSS in a hardened React SPA (a field methodology)](03-dom-xss-assessment-react-spa.md) | DOM XSS / source→sink audit | Live bug-bounty target (anonymised) |
| 04 | [SQL Injection: when your input becomes part of the query](04-sql-injection.md) | SQL Injection | Finding #6 + PortSwigger Academy labs |
| 05 | [Forging JWTs: `alg:none` and RS256→HS256 key confusion](05-jwt-forgery.md) | JWT / broken authentication | OWASP Juice Shop JWT challenges |
| 06 | [DOM Clobbering: breaking a control with only HTML](06-dom-clobbering.md) | DOM Clobbering | [`labs/clobber-lab.html`](../labs/clobber-lab.html) (Finding #10) |
| 07 | [Prototype Pollution: poisoning every object at once](07-prototype-pollution.md) | Prototype Pollution → XSS | [`labs/protopollution-lab.html`](../labs/protopollution-lab.html) (Finding #11) |
| 08 | [jQuery footguns: `$()`, `.html()`, and `$.extend` pollution](08-jquery-footguns.md) | jQuery DOM XSS / pollution | [`labs/jquery-lab.html`](../labs/jquery-lab.html) (Finding #12) |

> Lab-based writeups use authorized, local, intentionally-vulnerable targets
> only. Field writeups (e.g. 03) come from authorized testing under a public
> bug-bounty program's scope and rules, with the target anonymised and no
> undisclosed vulnerability revealed.
