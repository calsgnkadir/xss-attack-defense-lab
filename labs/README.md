# Local Labs

Self-authored, self-contained HTML labs that isolate advanced ("next-gen") XSS classes which OWASP
Juice Shop does not expose (it lacks the required gadget, or its framework is not vulnerable to that
class). Each lab is a single file — open it directly in a browser (`file://`), no server needed.

> Educational use only. Each lab intentionally contains vulnerable code to demonstrate one mechanism.

| File | Class | What it demonstrates |
|------|-------|----------------------|
| `mxss-lab.html` | **Mutation XSS** | An `innerHTML` round-trip mutates `<image>` into `<img>`. A filter that blocks `<img>` misses `<image>`, which the browser then "repairs" into a live, executing `<img onerror>`. Input string ≠ serialized output = the mutation. |
| `clobber-lab.html` | **DOM Clobbering** | Injecting only HTML (`<a id="isAdmin">`, no script) creates a `window.isAdmin` global via named access, bypassing an `if (window.isAdmin)` check, then feeds a clobbered value into a sink. Primitive **+** gadget. |
| `protopollution-lab.html` | **Prototype Pollution → XSS** | A guard-less query parser writes `__proto__[widgetHtml]=…` onto `Object.prototype`; a downstream gadget (`config.widgetHtml || default`) then reaches an `innerHTML` sink. A brand-new `{}` inherits the polluted value. |
| `jquery-lab.html` | **jQuery-specific XSS** | On jQuery 3.3.1: (A) `$(userInput)` turning a `<`-string into a live element, (B) `.html()` as an `innerHTML` sink, (C) `$.extend(true, {}, json)` prototype pollution (CVE-2019-11358). |

## How to run
1. Open any `*.html` file directly in your browser.
2. Open DevTools (F12) → Console.
3. Follow the on-page instructions; proofs print to the Console (`console.log`), not modal alerts.

## Why these are local labs (not Juice Shop)
- **Clobbering** needs a gadget (code that reads the clobbered global) — Juice Shop has none.
- **Prototype pollution** — Juice Shop's Angular build is not vulnerable to it.
- **jQuery** — Juice Shop is Angular, it does not ship jQuery.
- **mXSS** is pure browser behaviour and needs no specific target.

Building the minimal vulnerable case for each is itself the exercise: it forces you to isolate the
exact primitive + gadget + sink that makes the class work.
