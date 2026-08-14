# Writeups

Short, mechanism-first technical writeups on the vulnerability classes practised
in this repository. The goal is to **explain how each bug works** — not to list
payloads — using the hands-on findings and local labs here as concrete examples.

| # | Title | Class | Based on |
|---|-------|-------|----------|
| 01 | [Why filtering isn't protection: the nested-tag sanitizer bypass](01-filtering-is-not-protection.md) | Sanitizer bypass / mutation | Findings 2 & 8 |
| 02 | [Mutation XSS (mXSS): when the browser rewrites your "clean" HTML](02-mutation-xss.md) | Mutation XSS | [`labs/mxss-lab.html`](../labs/mxss-lab.html) |

**Planned:**

- DOM Clobbering: access control bypass with zero script — based on [`labs/clobber-lab.html`](../labs/clobber-lab.html)
- Prototype Pollution → XSS: from `__proto__` in a query string to an `innerHTML` sink — based on [`labs/protopollution-lab.html`](../labs/protopollution-lab.html)

> All examples come from authorized, local, intentionally-vulnerable targets only.
