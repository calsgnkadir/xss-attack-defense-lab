# DOM Clobbering: breaking a control with only HTML

> **TL;DR** — Sometimes you can't inject `<script>` (CSP, a sanitizer that strips
> handlers) but you *can* inject plain, boring HTML — an `<a>`, an `<img>`, a
> `<form>` with an `id` or `name`. The browser turns named elements into
> **properties on `document`/`window`**, so an injected `<a id="isAdmin">` creates
> a global `isAdmin` out of thin air. If app code trusts that global for a decision,
> your markup — with **zero JavaScript** — overwrites ("clobbers") it. This is XSS's
> quiet cousin: no script, and it still subverts logic.

Every injection writeup in this repo has a sink where a value is interpreted as
code. Clobbering is the exception that proves the rule: you don't inject code at
all. You inject a **name**, and rely on the browser's own behaviour of exposing
named elements as global variables to collide with something the application
trusts.

## The one idea: named HTML becomes JavaScript globals

The browser auto-exposes elements with an `id` (and `name`, on some elements) as
properties:

```html
<a id="config"></a>
```
```js
window.config        // → the <a> element
document.config      // → the same element
```

You didn't declare `config` — the DOM did. So if application code reads a global
to make a decision:

```js
if (window.isAdmin) { showAdminPanel() }        // expects a real flag
```

and an attacker can inject **one tag** with that id into the page:

```html
<a id="isAdmin"></a>
```

then `window.isAdmin` is now an anchor element — **truthy** — and the admin check
passes. No script ran; a sanitizer that allows `<a>` (and only strips script and
`on*` handlers) lets this straight through, and a strict CSP is irrelevant because
nothing executes. That is the whole class: **markup that impersonates a variable.**

## Escalating: building nested objects

A single flag is the simple case. Attackers also *shape* clobbered values:

- **Two elements, nested lookup.** `<form id="x"><input id="y"></form>` makes
  `x.y` resolve to the input element — clobbering `config.token`-style nested reads.
- **`name` + collections.** Multiple elements sharing a `name` become an
  `HTMLCollection`, which can be indexed to reach a specific node.
- **`.value` / `href` gadgets.** `document.getElementById('x')` on a clobbered
  element, then reading `.value` or `.href`, can feed a *string* the attacker
  controls into a later sink — turning a script-less clobber into a real XSS when
  chained to an `innerHTML`/`location` sink downstream.

The local lab in this repo — [`labs/clobber-lab.html`](../labs/clobber-lab.html)
— isolates the basic form: a page that grants access on a global flag, defeated by
injecting an element with that `id`. It's **Finding #10** of the assessment.

## Why it slips past defenses

- **Sanitizers focus on execution.** They strip `<script>` and `on*` handlers but
  routinely allow `<a>`, `<img>`, `<form>`, `<input>` with `id`/`name` — exactly
  the ingredients of a clobber.
- **CSP doesn't apply.** No inline or remote script runs, so `script-src` never
  gets a say.
- **The code looks safe.** `if (window.isAdmin)` reads like a normal flag check —
  the bug is that the flag lives in a namespace the DOM can write to.

## The fix

1. **Don't read security-relevant state from the global/DOM namespace.** Keep flags
   and config in module/closure scope, not on `window`. A variable the DOM cannot
   name is a variable the DOM cannot clobber.
2. **Resolve elements explicitly.** Use `document.getElementById('x')` — which
   returns *only* real elements — never `document.x` / `window.x`, which return
   whatever got clobbered.
3. **Type-check, don't truth-check.** `if (isAdmin === true)` rejects an anchor
   element; `if (isAdmin)` accepts it. Guard on the exact expected type.
4. **Strip `id` and `name` from user HTML.** A current **DOMPurify** removes
   clobbering vectors by default (`SANITIZE_DOM`); a hand-rolled allowlist must
   explicitly drop these attributes.
5. **`Object.create(null)`** for lookup maps, so there's no inherited surface to
   shadow.

## Takeaway

XSS doesn't always need script. If an application trusts a value that the DOM can
name — a global flag, a config object read off `window` — then plain, "safe" HTML
is enough to overwrite it. **Don't let the page's markup and its variables share a
namespace**, and read elements by `getElementById`, not by the name the attacker
gets to choose.

---

*Demonstrated on an authorized, local target only:
[`labs/clobber-lab.html`](../labs/clobber-lab.html) (Finding #10) — open it in a
browser and inject the `id` to watch the global flip. Same repo theme — a value
interpreted in a context the developer didn't expect — at the JavaScript-global
layer.*
