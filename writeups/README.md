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

> Every writeup here is backed by hands-on work on an **authorized** target:
> OWASP Juice Shop (local Docker) or, for the field writeup (02), authorized
> testing under a public bug-bounty program's scope and rules — target anonymised,
> no undisclosed vulnerability revealed.
