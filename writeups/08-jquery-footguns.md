# jQuery footguns: `$()`, `.html()`, and `$.extend` pollution

> **TL;DR** — jQuery turns three ordinary-looking lines into vulnerabilities:
> passing user input to **`$()`** (which parses an HTML-looking string into live
> elements), using **`.html()`** as a raw sink, and **`$.extend(true, …)`** on old
> versions (prototype pollution, CVE-2019-11358). Legacy jQuery — 3.3.1 in this
> lab — is still bundled everywhere, so "harmless" DOM code silently becomes an
> `innerHTML`/execution sink. The bugs aren't exotic; they're the library's
> conveniences used the obvious way.

This one ties the repo together: it's DOM XSS
([methodology](../methodology.md)) *and* prototype pollution
([Writeup 07](07-prototype-pollution.md)) delivered through a single, extremely
common library. **Finding #12**, isolated in
[`labs/jquery-lab.html`](../labs/jquery-lab.html) on jQuery 3.3.1.

## Footgun 1 — `$(userInput)` builds HTML, not just selectors

`$()` is overloaded: give it `#id` and it *selects*; give it a string that looks
like HTML and it **creates elements**. jQuery decides by looking for a `<` in the
string — so attacker input flips it from selector to HTML factory:

```js
$(location.hash.slice(1))          // developer meant "select #something"
$('#' + userInput)                 // or this
```

Feed it `<img src=x onerror=alert(1)>` and jQuery *constructs* that element; the
broken `src` fires `onerror` and the script runs. A classic real-world trigger is
`$(location.hash)` — the fragment never hits the server, so no server filter sees
it (the DOM-XSS shape from the methodology doc).

## Footgun 2 — `.html()` is an `innerHTML` sink

`.html(x)` sets `innerHTML` under the hood. Any user value passed to it is parsed
as HTML:

```js
$('#out').html(userInput);         // raw HTML → same risk as element.innerHTML = userInput
```

The safe sibling is **`.text()`**, which sets `textContent` and escapes markup —
the jQuery equivalent of "render as text, not HTML."

## Footgun 3 — `$.extend(true, …)` prototype pollution (CVE-2019-11358)

Before jQuery 3.4, the deep-merge `$.extend(true, target, source)` copied
attacker keys — including `__proto__` — straight onto `Object.prototype`:

```js
$.extend(true, {}, JSON.parse('{"__proto__":{"polluted":"yes"}}'));
({}).polluted        // → "yes"   — every object now carries it
```

That's the exact mechanism of [Writeup 07](07-prototype-pollution.md), shipped as
a library bug: any page bundling old jQuery and deep-merging user-controlled JSON
(a common pattern for config/options) inherits a pollution primitive, which a
gadget can escalate to XSS.

## Why legacy jQuery keeps this alive

- **It's everywhere.** Huge numbers of production sites still ship jQuery 1.x–3.3.
  The vulnerable behaviours are the *documented* behaviours, not bugs to be
  spotted in review.
- **The calls read as harmless.** `$('#' + id)`, `.html(data)`,
  `$.extend(true, …)` look like everyday jQuery — the risk is invisible without
  knowing the parsing/merge semantics.

## The fix

1. **Never pass user input to `$()`.** If you must select, confirm the value is a
   plain id and use `document.getElementById(id)` — which can only select, never
   construct.
2. **Use `.text()` for user data**, `.html()` only for content you built and
   trust (and sanitise with DOMPurify if it must be rich HTML).
3. **Upgrade to jQuery ≥ 3.5**, which fixes both the `$()` HTML-execution edge
   cases and the `$.extend` prototype pollution. Guard `__proto__` in any merge you
   own regardless.
4. **Prefer an auto-escaping framework.** Modern React/Angular/Vue escape by
   default; the safest long-term fix is often not to hand-render HTML through
   jQuery at all.

## Takeaway

jQuery's ergonomics are the vulnerability: `$()` will happily turn a string into
live HTML, `.html()` is `innerHTML` with a friendlier name, and old `$.extend`
pollutes the base object. Treat every user value going into `$()` or `.html()` as
a sink, upgrade past 3.4, and reach for `.text()` and `getElementById` by default.

---

*Demonstrated on an authorized, local target only:
[`labs/jquery-lab.html`](../labs/jquery-lab.html) (Finding #12) on jQuery 3.3.1 —
`$()` selector-to-HTML, the `.html()` sink, and `$.extend(true, …)` pollution.
Pulls together the repo's DOM-XSS and prototype-pollution threads inside one
real-world library.*
