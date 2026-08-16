# Writeups

Short, mechanism-first technical writeups on the vulnerability classes practised
in this repository. The goal is to **explain how each bug works** — not to list
payloads — using the hands-on findings and local labs here as concrete examples.

| # | Title | Class | Based on |
|---|-------|-------|----------|
| 01 | [Why filtering isn't protection: the nested-tag sanitizer bypass](01-filtering-is-not-protection.md) | Sanitizer bypass / mutation | Findings 2 & 8 |
| 02 | [Mutation XSS (mXSS): when the browser rewrites your "clean" HTML](02-mutation-xss.md) | Mutation XSS | [`labs/mxss-lab.html`](../labs/mxss-lab.html) |
| 03 | [Assessing DOM XSS in a hardened React SPA (a field methodology)](03-dom-xss-assessment-react-spa.md) | DOM XSS / source→sink audit | Live bug-bounty target (anonymised) |

**Planned:**

- DOM Clobbering: access control bypass with zero script — based on [`labs/clobber-lab.html`](../labs/clobber-lab.html)
- Prototype Pollution → XSS: from `__proto__` in a query string to an `innerHTML` sink — based on [`labs/protopollution-lab.html`](../labs/protopollution-lab.html)

> Lab-based writeups use authorized, local, intentionally-vulnerable targets
> only. Field writeups (e.g. 03) come from authorized testing under a public
> bug-bounty program's scope and rules, with the target anonymised and no
> undisclosed vulnerability revealed.
