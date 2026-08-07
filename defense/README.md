# Defense — sanitiser attack vs. defense

The rest of this repository shows how input filters were **bypassed** (see the report's Findings 2 and
8: a single-pass filter is defeated when removing one tag re-forms another, and a `<script>`-only
blocklist misses the `<img onerror>` event-handler vector). This folder shows the **defensive** side:
why a naive blocklist falls and what actually holds.

## Run it

Open [`demo.html`](demo.html) directly in a browser (`file://`, offline). Feed a payload to two
sanitisers and watch them render side by side. The default payload only *reports* execution — no
`alert()` popups.

## What it demonstrates

| | `vulnerable-sanitizer.js` | `secure-sanitizer.js` |
|---|---|---|
| Approach | **Blocklist**, single pass — strips `<script>` and `javascript:` only | **Allowlist** — parses to an inert DOM, keeps only known-safe tags/attributes, drops the rest |
| Payload `<img src=x onerror=...>` | passes through untouched → **executes** | `<img>` is not on the allowlist → **dropped**, no `onerror` |
| Why | it never considers event-handler attributes | nothing dangerous survives, because only *safe* things are allowed |

The lesson is the one the assessment kept proving: **blocklist / single-pass filtering is not
protection.** Real defenses are:

- **Output encoding** — if you only need text, never build HTML (`textContent`, `safeText()`). The
  browser escapes everything; nothing can execute.
- **Allowlist sanitisation** — allow known-safe tags/attributes, drop everything else, applied
  idempotently. In production use a battle-tested library (**DOMPurify**) rather than hand-rolling.
- **Content Security Policy** — a second layer that stops injected scripts from running even if the
  sanitiser is bypassed.
- **`HttpOnly` cookies** — so a successful XSS still cannot read the session token.

## Files

- `demo.html` — side-by-side interactive demo (open in a browser)
- `vulnerable-sanitizer.js` — the weak blocklist filter (exists to be broken)
- `secure-sanitizer.js` — `safeText()` (output encoding) and `allowlistSanitize()` (allowlist parser)

> Educational. Local, offline, self-contained.
