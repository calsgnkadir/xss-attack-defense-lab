# Defenses & Secure Coding

Finding a vulnerability is only half the job — knowing how to **fix** it is the other half. For every
class exercised in this assessment, this is how it should be defended, and *why*. These mitigations
map directly to the findings in the [report](../report/OWASP-JuiceShop-Security-Assessment.pdf).

## The one rule behind most XSS

**Filtering (blocklist) is not protection; encoding and allowlisting are.** A blocklist tries to guess
every dangerous input and always misses one — e.g. a filter that strips `<script>` still lets
`<img src=x onerror=…>` execute, and a single-pass filter can be defeated when *removing* one tag
re-forms another (the nested-tag mutation in Findings 2 and 8). The reliable controls are:

- **Context-aware output encoding.** When you only need text, render it as text (`textContent`,
  template auto-escaping). The browser escapes `< > & "` and nothing can execute. This is the default
  and the safest option.
- **Allowlist sanitisation for rich HTML.** If users genuinely need some HTML, parse it and keep only
  a known-safe set of tags/attributes, dropping everything else — applied idempotently so a single
  pass cannot re-form a tag. Use a battle-tested library (**DOMPurify**), never a hand-rolled regex.
- **Content Security Policy (CSP).** A second layer: even if injection succeeds, a strict CSP
  (`script-src 'self'` + per-response nonce, no `unsafe-inline`) stops the script from running.
- **`HttpOnly` + `Secure` + `SameSite` cookies.** So a successful XSS still cannot read the session
  token — which is what turns "an alert box" into "account takeover".

## Per-class defenses

| Class (finding) | Root cause | Fix |
|-----------------|-----------|-----|
| **DOM-based XSS** (search sink) | Framework auto-escaping was turned off (`bypassSecurityTrustHtml`) | Don't opt out of escaping; if raw HTML is unavoidable, sanitise with DOMPurify first. Add CSP + `HttpOnly` token. |
| **Stored XSS — sanitizer bypass** (feedback) | Single-pass blocklist; deletion re-forms a valid tag | Allowlist parser, applied recursively until stable; output-encode at render. |
| **Stored XSS — HTTP header** (`True-Client-IP`) | Same allowlist filter, bypassed by nested-tag mutation | Make sanitisation idempotent/recursive; never trust CDN headers (`True-Client-IP`, `X-Forwarded-For`) as input. |
| **Stored XSS — registration API → admin panel** | Client-side validation only; admin panel renders raw | Validate on the **server** for every field; output-encode in the admin UI too. |
| **CSP bypass** (profile Image URL) | User input reflected into the CSP header | Never reflect user input into a security header; use a static, strict CSP with nonces. |
| **SQL Injection** (product search) | User input concatenated into SQL | Parameterized queries / ORM bindings only; least-privilege DB user. |
| **IDOR / BOLA** (basket) | Ownership never checked | Enforce per-object authorization on every request (`resource.ownerId === session.userId`). |
| **Zip Slip → Stored XSS** (subtitle) | Archive entry names not validated; content rendered raw | Reject/normalise `../` in entry names, extract only inside the target dir; sanitise rendered content (incl. subtitles). |
| **mXSS (Mutation XSS)** | Browser re-parse mutates a "clean" string into a live one | Allowlist on the *parsed* DOM; parse-serialise idempotently; DOMPurify. |
| **DOM Clobbering** | Code reads a global that an injected `id`/`name` can shadow | Read via `getElementById`, not the global namespace; `Object.create(null)` for lookup maps. |
| **Prototype Pollution → XSS** | Guard-less deep merge / query parser writes to `__proto__` | Guard `__proto__`/`constructor`; `Object.freeze(Object.prototype)`; keep libraries current. |
| **jQuery-specific XSS** | `$(userInput)` builds HTML; `.html()` is an `innerHTML` sink; old `$.extend` pollution | Prefer `.text()`; never pass user input to `$()`; upgrade to jQuery ≥ 3.5. |

## Cross-cutting principles

- **Defense in depth.** No single control is enough. Server validation *and* client encoding *and* CSP
  *and* `HttpOnly` cookies — so one failure doesn't become a breach.
- **Secure by default.** Auto-escaping frameworks are safe until you opt out; the safest change is
  often *not disabling* a protection you already have.
- **Validate and encode at the right layer.** Validate on the server (client checks are only UX);
  encode at the point of output, for the correct context (HTML / attribute / URL / JS).
