# Methodology — Source → Sink XSS Hunting

A repeatable process for finding and reasoning about injection bugs, used throughout this project.
The emphasis is on *understanding* each step, not pasting a known payload.

---

## The loop

### 1. Source inventory
List every place attacker bytes enter the client:

- URL: route params, `?query`, `#fragment`
- Reflected API data: product names, reviews/feedback, usernames, basket item names, uploaded file
  names, order comments
- Stored-then-rendered: anything you can save that another view later renders
- Browser state: `localStorage`, `sessionStorage`, non-`HttpOnly` cookies read by JS
- Cross-origin: `postMessage` listeners, `window.name`

*Method:* open DevTools → Network, click through every feature once, note every writable field and
every API response drawn on screen. Undiscovered bugs live in fields nobody thinks to test — a file
name, a comment body, a deep-link parameter.

### 2. Sink discovery
Save the bundled `main.js` (DevTools → Sources → Save as) and grep for dangerous sinks:

```
bypassSecurityTrust | innerHTML | outerHTML | insertAdjacentHTML |
document.write | eval( | Function( | [innerHTML] | srcdoc | setAttribute
```

Every match is a candidate sink. `bypassSecurityTrust*` and `[innerHTML]` matches are gold — each is
a spot where a developer deliberately turned off the framework's auto-escaping.

### 3. Backward-trace each sink to a source
For each sink, ask: *what variable feeds this, and can I reach it from my source list?*

```
SINK (main.js)          local var        component input        route param / API field
el[innerHTML] = x   ←   x = this.foo  ←  @Input foo         ←   ?id= / review.message
                                                                       ▲
                                                          can I control this? → yes = candidate bug
```

A sink fed by a hardcoded constant is a false positive — discard it. A sink reachable from an
attacker source without encoding is a finding. **Tools list line numbers; only the trace tells you
if it is real.**

### 4. Inert probe
Send a harmless marker first — e.g. `<b>apple` — and read the **DOM** (DevTools → Elements), not the
rendered page:

- A real `<b>apple</b>` element in the tree → **raw HTML sink**, bug confirmed
- Literal `&lt;b&gt;apple` text → escaped, safe on this path (look for a *second* reflection context)

Isolating one variable ("does markup render?") before touching script keeps the test clean.

### 5. Escalate — one rung
A bare `<script>` inserted via an `innerHTML` path does **not** run (HTML5 rule). Escalate with a
different execution path:

- Event-handler attribute on a self-firing element: `<img src=x onerror=…>` (the broken `src`
  triggers `error` with zero clicks)
- A `javascript:` URL scheme evaluated on load: `<iframe src="javascript:…">`
- Filter bypass when a sanitizer is present: nested tags whose removal re-forms a dangerous tag
  (mutation), or a browser mutation such as `<image>` → `<img>`

### 6. Verify cleanly
Prove execution with `console.log(document.domain)` before any `alert()`:

- No modal blocks DevTools
- The printed origin (`localhost`) proves *where* the code ran — real execution, not just HTML
  injection

### 7. Check authorization
If the action hit an update/admin endpoint, ask whether the privilege used was actually required. A
"working" write with a normal user often uncovers a separate, serious access-control (IDOR/BOLA) bug.

---

## Which layer — Network or Browser?

| Vulnerability | Where the work happens | How to analyse |
|---------------|------------------------|----------------|
| DOM-based XSS, mXSS, clobbering, prototype pollution | Entirely in the browser | DevTools **Console / Elements** (Network tab is empty) |
| Prototype pollution delivery | Payload rides in the URL | Network shows the request; Console verifies pollution (`({}).x`) |
| Reflected / Stored XSS | Input goes to the server and back | **Network / Burp** — payload (request) vs. reflection (response) |
| Header XSS | Header the browser won't send on its own | **Burp** (Match-and-replace / manual header) |

**One-liner:** if the bug reaches the server, work from the Network/Burp side; if it stays in the
browser, work from Console/Elements. Some XSS is invisible in Network because it is purely
client-side.

---

## Automation vs. reasoning
Automated tools (Burp **DOM Invader**, Semgrep rulesets) generate *candidates*. The backward-trace is
done by hand to confirm them. That split — **the tool finds, the human verifies** — is how you find
real bugs without pasting exploits you cannot explain.
