# Mutation XSS (mXSS): when the browser rewrites your "clean" HTML

> **TL;DR** — The HTML string you hand to `innerHTML` is **not** the HTML the
> browser ends up with. The parser silently *repairs and normalises* markup, so a
> string a sanitizer just approved can become a live payload the instant the
> browser re-parses it. The sanitizer checked one string; the browser built a
> different one.

The bug in [Writeup 01](01-filtering-is-not-protection.md) came from a filter
*deleting* text. mXSS is subtler: nobody deletes anything. The **browser itself**
transforms safe-looking input into dangerous output. I built a tiny lab in this
repo to watch it happen: [`labs/mxss-lab.html`](../labs/mxss-lab.html).

## The one idea: input string ≠ rendered DOM

HTML parsing is *lenient by design*. Browsers accept broken, mis-cased,
mis-nested, half-quoted markup and quietly "fix" it into a valid DOM. That means
a round trip is lossy:

```
your string  --parse-->  DOM  --serialize-->  a DIFFERENT string
```

My lab does exactly this round trip and compares the two ends:

```js
sink.innerHTML = s;          // your string -> DOM (the browser parses & repairs)
const after = sink.innerHTML; // DOM -> string (what the browser actually built)
if (s !== after) { /* MUTATION: parser saw something different than you wrote */ }
```

When `s !== after`, the browser changed your markup. **That gap is the entire
vulnerability class** — because a sanitizer runs on `s`, but the page renders
`after`.

## A worked example

Suppose the sanitizer blocks `<img ...>` (a reasonable-looking rule). Send it:

```html
<image src=x onerror=alert(1)>
```

The sanitizer scans for `<img` and sees only `<image` — no match, looks clean,
approved. But `<image>` is a legacy alias: the HTML parser **normalises it to
`<img>`**. After the browser parses it, the DOM contains:

```html
<img src="x" onerror="alert(1)">
```

`src=x` fails to load, `onerror` fires, script runs. The sanitizer never saw an
`<img>` tag — **the browser created it** during parsing. Drop that payload into
the lab and the "before" and "after" panels will disagree: proof of mutation.

Other everyday mutations that break string-based filters:

- attributes get re-quoted (`onerror=alert(1)` → `onerror="alert(1)"`),
- HTML entities get decoded/re-encoded,
- missing end tags are inserted and mis-nested tags are reordered,
- tag/attribute names are lower-cased.

Any of these can turn a string a blocklist judged safe into different, live markup.

## The dangerous version: namespace confusion

The deep mXSS bugs (including several historical DOMPurify bypasses) use
**foreign-content** elements — `<svg>` and `<math>`. Inside them the parser
follows different rules; when sanitized content built in one context is later
inserted into another (a plain `innerHTML`), the **re-parse crosses a namespace
boundary and mutates**. Markup that was inert as SVG/MathML becomes live HTML.

The common thread with the simple `<image>` case is identical: **the string was
sanitized in one parsing context and rendered in another, and the two disagree.**

## Why this defeats string sanitizers specifically

A regex/string sanitizer is, by definition, reasoning about characters. But XSS
is decided by the **parsed DOM**, and the browser's parser is the only authority
on what those characters become. Checking the input string is checking a draft
the browser is free to rewrite. You can't out-regex a parser you don't run.

## The fix

1. **Sanitize on the parsed DOM, not the string, and make it idempotent.** Parse
   the input into a DOM, keep only an allowlist of nodes/attributes, then
   *serialize and re-parse until the output stops changing*. If a single pass
   could still mutate, run it to a fixed point. This is exactly what a mature
   library does — use **DOMPurify** (kept current), never a hand-rolled filter.
2. **Match the sanitisation context to the render context.** Sanitize for the
   exact place the value will live; don't sanitize as HTML then inject into SVG.
3. **Prefer not to parse HTML at all.** If the value is text, use `textContent` /
   template auto-escaping — no parser, no mutation, no bug.
4. **Defense in depth:** a strict CSP and `HttpOnly` cookies, so a slip isn't a
   breach.

## Takeaway

**Don't trust the string; trust the DOM the browser actually builds.** The moment
your validation and the browser's parser look at two different things, you have an
mXSS. The round-trip test in the lab (`inputHTML !== element.innerHTML`) is the
fastest way to *see* that gap — and it's the same check researchers use to find
these bugs in real sanitizers.

---

*Demonstrated only on an authorized, local lab
([`labs/mxss-lab.html`](../labs/mxss-lab.html)) — open it in a browser and try the
payloads above.*
