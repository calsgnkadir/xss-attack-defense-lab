# Assessing DOM XSS in a hardened React SPA (a field methodology)

> **TL;DR** — Server-side output encoding (what React gives you by default)
> stops *reflected* XSS but says **nothing** about DOM XSS, because a DOM XSS
> lives entirely in the browser: the app's own JavaScript takes a client-side
> **source** (URL fragment, `postMessage`, `referrer`) and hands it to a
> **sink** (`innerHTML`, `document.write`, `eval`). This writeup is the method I
> used to assess a real, hardened e-commerce SPA on a public bug-bounty program —
> a **source → sink** audit done two ways (static + dynamic) — and why a clean,
> negative result is still a real, reportable piece of work.

> **Target anonymised on purpose.** The site is a live e-commerce React/Next.js
> app on a public bug-bounty program. No vulnerability was found and none is
> disclosed here; I keep the name out as basic disclosure hygiene. The value of
> this writeup is the *method*, which is identical on any target.

## Why reflected-XSS reasoning does not carry over

The day before this assessment I confirmed the site's search reflection was safe:
every marker character came back HTML-encoded (`<` → `&lt;`, `"` → `&quot;`) in
the server-rendered HTML. That is React doing its job — values interpolated into
JSX are escaped **on the server**.

DOM XSS is a different bug in a different place:

```
reflected XSS:  attacker input --> SERVER builds HTML --> browser renders   (React encodes here)
DOM XSS:        attacker input --> browser JS builds/HTML --> DOM sink       (React never sees this)
```

The decisive source for DOM XSS is the **URL fragment** (`location.hash`, the
`#...` part). The fragment is *never sent to the server*, so no server-side
sanitiser — however good — can even see it. If client JS reads it and writes it
into an HTML sink, you have DOM XSS regardless of how well the server encodes.
That is why "reflected is safe" tells you nothing here, and why this pass was
worth doing.

## The method: source → sink, the same idea as the repo's linter

This is the exact model behind this repository's
[`dom-xss-analyzer`](../tools/dom-xss-analyzer/) and
[`methodology.md`](../methodology.md): locate the **sources**, locate the
**sinks**, and prove whether any source *reaches* a sink. The tool does it on
source you own; here I do it by hand on a live, minified bundle. Same reasoning,
two settings.

**The sinks I looked for** (the value becomes markup/JS):

| Sink | Why it's dangerous |
|------|--------------------|
| `.innerHTML` / `.outerHTML` | assigned string is parsed as HTML |
| `insertAdjacentHTML` | same, positional |
| `document.write` | writes raw HTML into the document |
| `eval` / `Function()` | string executed as code |
| React `dangerouslySetInnerHTML` | opt-out of React's escaping |

**The sources I looked for** (attacker-controllable, client-side):

| Source | Notes |
|--------|-------|
| `location.hash` | the prize — never reaches the server |
| `location.search` | often handled server-side, still worth tracing |
| `document.referrer` | attacker sets it via a linking page |
| `window.name` | survives cross-navigation, classic vector |
| `postMessage` (`addEventListener("message", …)`) | cross-frame data, frequently unchecked |

## Pass 1 — static: search the bundles

In DevTools → **Sources**, a project-wide search (`Ctrl+Shift+F`) over the
loaded JavaScript for each sink and source above. The bundle is minified, but the
tokens that matter don't rename: `location.hash`, `innerHTML`, and the browser
APIs stay literal even after minification, so text search still finds them.

What the results actually showed:

- **`insertAdjacentHTML`** and **`window.name`** — *zero* matches. Two vectors
  eliminated immediately.
- **`innerHTML`** — many matches, but all inside the **React runtime**, analytics
  SDKs, or wrapped in **Trusted Types** (`typeof trustedTypes`, `createHTML(…)`).
  None was `element.innerHTML = <a source>`.
- **`dangerouslySetInnerHTML`** — React-internal plus a few app components
  (coupon text, promo "nudge" text) fed by **server-provided strings**, not by
  any URL/message input.
- **`document.write`** — a single hit, writing into an **iframe sandbox's**
  `contentDocument`, not fed by user input.
- **`location.hash` / `document.referrer`** — present, but **where** matters:
  almost all were third-party analytics (Bing, LINE, Clarity, GTM, Criteo) that
  read them for *tracking* — `encodeURIComponent(referrer)`, `return
  location.hash`, `-1 !== location.hash`. The site's own reads *returned or
  compared* the value; none flowed into an HTML sink.

The single most important observation: **sources exist, sinks exist, but no
source is wired to a sink.** DOM XSS needs the two to meet on one data path.
Here they never touch.

Two structural defenses reinforced that:

- **Trusted Types.** The `trustedTypes` / `createHTML` markers around the
  `innerHTML` sites indicate the app is Trusted-Types-aware. When a page enforces
  `require-trusted-types-for 'script'` via CSP, the browser **forbids assigning a
  plain string to `innerHTML`** at all — a string must first pass a registered
  policy. That converts "did the dev remember to sanitise?" into a
  browser-enforced invariant.
- **An active CSP**, confirmed independently when a `frame-src` directive blocked
  a framed request during testing.

## Pass 2 — dynamic: instrument the one live source

Static reading of minified code can miss a flow that only exists at runtime. The
one source with real listeners in the app's own code was `postMessage`, so I
confirmed it live. A **read-only** one-liner in the console registers a logging
listener — no page code is modified, nothing is sent anywhere:

```js
window.addEventListener('message', e => console.log('[msg]', e.origin, e.data), true);
```

(`addEventListener` returns `undefined` — that's the listener installing
correctly, not an error.) Then interact with the page — scroll, let carousels and
banners load, let widgets initialise — and watch the console.

Result: **not a single `[msg]` fired.** The top document received no
`postMessage` at all during interaction. The listeners the static search found
were infrastructure — a `MessageChannel`/`MessagePort` pair and a `setImmediate`
polyfill (which posts a private token to itself and checks `source`) — not an
attacker-reachable `e.data → sink` path. The dynamic pass confirmed what the
static pass implied: this source is dead for the top frame.

## The verdict, and why a negative result counts

For this page the assessment closed **clean**, and it closed *twice*:

| Method | Result |
|--------|--------|
| Static source→sink search | no source reaches any HTML sink |
| Live `postMessage` instrumentation | no cross-frame messages received |
| Structural defenses | Trusted-Types-aware sinks + active CSP |

That is not "I threw payloads and nothing popped." It is a **mapped attack
surface with a reasoned, cross-checked conclusion** — the same output the repo's
linter produces, done by hand on a live target. In real bug-bounty work most
pages end exactly here; the skill on display is *ruling a surface out with
evidence* so time goes to the pages that haven't been.

It is also honest about scope: this covers **one page's bundle**. DOM XSS more
often hides on heavier, more dynamic views (product detail, account, search
filters) that ship different JavaScript, or in third-party widgets — the natural
next targets, assessed the same way.

## What made this target hard (the defensive lesson)

This repo is an *attack **and** defense* lab, so the mirror image matters. The
site was clean for reasons any application can copy:

1. **Framework-default escaping** everywhere, with `dangerouslySetInnerHTML`
   reserved for server-trusted strings only — not user input.
2. **Trusted Types**, turning "remember to sanitise before `innerHTML`" from a
   discipline into a browser-enforced rule.
3. **A real CSP** as defense in depth, so a single slip is not automatically a
   breach.
4. **No `insertAdjacentHTML`, no `window.name` handling, no `document.write`** of
   user data — a small, deliberate sink surface.

## Takeaway

Reflected-safe is not DOM-safe: they are different bugs in different places.
Assess DOM XSS the way the linter in this repo *thinks* — enumerate sources,
enumerate sinks, and prove whether any path connects them — then confirm the one
live source at runtime. A clean, evidence-backed "no path" is a legitimate result,
and producing it is the same muscle you use to find the case where a path *does*
exist.

---

*Performed under a public bug-bounty program's scope and rules. Target
anonymised; no vulnerability found or disclosed. The methodology is the
transferable part, and it mirrors this repository's
[`dom-xss-analyzer`](../tools/dom-xss-analyzer/) and [`methodology.md`](../methodology.md).*
