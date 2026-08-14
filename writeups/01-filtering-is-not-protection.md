# Why filtering isn't protection: the nested-tag sanitizer bypass

> **TL;DR** — A single-pass filter that *deletes* dangerous substrings can be
> defeated by making the deletion itself assemble a new dangerous tag. Removing
> `<script>…</script>` from the right input leaves a working `<iframe>` behind.
> The act of sanitising is what builds the payload.

This is one of the first bugs that changed how I think about input handling. I
hit it while working the *Server-side XSS Protection* path on OWASP Juice Shop
(local, authorized) — it appears twice in this repository's findings: the
feedback comment (Finding 2) and the `True-Client-IP` header → Last Login IP page
(Finding 8), both behind the *same* server-side filter.

## The defense that feels reasonable

A very common instinct is: *"XSS is `<script>`, so strip `<script>`."* So the
server runs something like:

```js
// single pass, remove <script>…</script>
clean = dirty.replace(/<script.*?>.*?<\/script>/gi, '');
```

It looks safe. `<script>alert(1)</script>` in, empty string out. Ship it.

## Why it fails: deletion can *create* a tag

The filter reasons about the string it was **given**. It does not reason about
the string it **leaves behind**. Feed it this:

```
<<script>Foo</script>iframe src="javascript:alert(`xss`)">
```

Walk it as the filter does. It scans for `<script>…</script>` and finds exactly
one complete block — `<script>Foo</script>` — and removes it. `Foo` is just
inert filler to make the block well-formed. What is left?

```
<iframe src="javascript:alert(`xss`)">
```

Before sanitising, that leading `<` and the trailing `iframe src=…>` were **not**
a tag — the `<script>` block sat between them and broke them apart. After
sanitising, the two fragments fuse into a valid, live `<iframe>`. The filter did
not miss the payload; **the filter assembled it.**

This is a *mutation*: the input string is not equal to the string the browser
finally parses. Any defense that inspects the input, not the parsed result, is
playing the wrong game.

## Why it then executes

Two small facts do the rest:

1. **`javascript:` URLs run.** `<iframe src="javascript:…">` executes its script
   when the iframe loads — no `<script>` tag needed.
2. **`<script>` inserted via `innerHTML` is inert, but event handlers and URL
   schemes are not.** That is why bypasses reach for `onerror`, `onload`, or
   `javascript:` rather than a raw `<script>` — a different, still-live code path.

When the sanitised value is dropped into the page (in Juice Shop, into the
feedback list and the Last Login IP element), the browser parses the *mutated*
string, builds the iframe, loads it, and runs the URL. The payload fired.

## The pattern, generalised

The nested-tag trick is one shape of a bigger rule: **a blocklist that deletes
can be re-formed.** Classic siblings:

- `<scr<script>ipt>alert(1)</scr<script>ipt>` → strip both `<script>` tokens →
  `<script>alert(1)</script>` reassembles.
- Filters that lower-case, trim, or entity-decode *after* their check, so the
  value the check saw is not the value that renders.

Every one of these is the same failure: **one pass, no re-check, input ≠ output.**

## The fix that actually holds

Stop trying to enumerate "bad." Two controls do the real work:

1. **Context-aware output encoding — the default.** If the value only needs to be
   *text*, render it as text (`textContent`, template auto-escaping). The browser
   escapes `< > & "` and nothing can parse into a tag. Most "sanitisation" is
   solving a problem you created by choosing an HTML sink for text.

2. **Allowlist parsing for genuine rich HTML.** If users truly need some HTML,
   parse it into a DOM, keep only a known-safe set of tags/attributes, drop the
   rest, and **apply it until the output is stable** (idempotent / recursive) so a
   single pass can't leave a re-formed tag. Use a maintained library —
   **DOMPurify**, `sanitize-html` — never a hand-rolled regex.

Then layer defense in depth so one slip isn't a breach:

- **CSP** (`script-src 'self'` + per-response nonce, no `unsafe-inline`) — even a
  successful injection has nothing to run.
- **`HttpOnly` + `Secure` + `SameSite` cookies** — a successful XSS still can't
  read the session token, which is what turns "an alert box" into account
  takeover.

## Takeaway

**Filtering guesses at every dangerous input and always misses one — sometimes
the one it makes itself.** Encoding and allowlist parsing decide what output is
*allowed to be*, which is a question with a finite, correct answer. If you find
yourself writing `.replace(/<script>/…)`, you are defending the wrong layer.

---

*Tested only on authorized, local, intentionally-vulnerable targets (OWASP Juice
Shop via Docker). See the repository [README](../README.md) for the full finding
and remediation table.*
