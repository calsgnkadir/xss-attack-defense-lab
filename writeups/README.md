# Writeups

Short, mechanism-first technical writeups on the vulnerability classes practised
in this repository. The goal is to **explain how each bug works** — not to list
payloads — using the hands-on findings here as concrete examples. Every writeup
is tied to a real, confirmed finding (OWASP Juice Shop) or a real-target field
assessment.

| # | Title | Class | Based on |
|---|-------|-------|----------|
| 01 | [Why filtering isn't protection: the nested-tag sanitizer bypass](01-filtering-is-not-protection.md) | Sanitizer bypass / mutation | Findings 2 & 8 (Juice Shop) |
| 02 | [Assessing DOM XSS in a hardened React SPA (a field methodology)](02-dom-xss-assessment-react-spa.md) | DOM XSS / source→sink audit | Live bug-bounty target (anonymised) |
| 03 | [SQL Injection: when your input becomes part of the query](03-sql-injection.md) | SQL Injection | Finding #6 (Juice Shop) + PortSwigger Academy |
| 04 | [Forging JWTs: `alg:none` and RS256→HS256 key confusion](04-jwt-forgery.md) | JWT / broken authentication | Juice Shop — Unsigned JWT (solved); Forged Signed JWT (attempted, not solved) |
| 05 | [IDOR / BOLA: the server checks who you are, not what's yours](05-idor-bola.md) | Access control / IDOR / BOLA | Finding #7 (Juice Shop `/rest/basket/{id}`) |
| 06 | [Building an XSS bot: encoding a methodology as code](06-building-an-xss-bot.md) | Tooling / automation | `dxa` + `dxadyn`; live-verified on Bludit 3.16.2 (CVE-2026-4420 shape) |
| 07 | [Teaching the bot to log in, find its own targets, and shut up](07-teaching-the-bot-to-log-in.md) | Tooling / real-target maturity | v3.1-v3.4: session import, auto-crawl, JSON/header submit, PHP static, escape-aware squelch, HTML report |
| 08 | [What the bot doesn't shout about is what makes it useful](08-what-does-not-shout-matters.md) | Tooling / precision > recall | v3.5-v3.7 + Java: sink-context, dedup, PUT/PATCH/DELETE, Content-Type gate, Java/Servlet/Spring static |
| 09 | [Three HIGH to one: a precision journey on real code](09-three-high-to-one-a-precision-journey.md) | Tooling / engineered heuristic | v3.8 + v3.9 case study on hotel-platform (own project): cross-method sanitizer + multi-line join + sink-family dedup walk static HIGH count from 3 → 2 → 1 |

> Every writeup here is backed by hands-on work on an **authorized** target:
> OWASP Juice Shop (local Docker) or, for the field writeup (02), authorized
> testing under a public bug-bounty program's scope and rules — target anonymised,
> no undisclosed vulnerability revealed.
