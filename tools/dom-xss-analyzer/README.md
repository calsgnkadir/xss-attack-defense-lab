# dxa — source→sink XSS analyzer (full-stack)

[![CI](https://github.com/calsgnkadir/xss-attack-defense-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/calsgnkadir/xss-attack-defense-lab/actions/workflows/ci.yml)

A small, dependency-free static linter that flags XSS sources, sinks, and the
likely **source → sink flows** between them — on **both sides** of a web app:

- **client side** — JavaScript / TypeScript (DOM XSS)
- **server side** — C# / ASP.NET & Razor (server-rendered XSS)

It is the `source → sink` methodology from this repository
([`../../methodology.md`](../../methodology.md)) expressed as runnable code.

![dxa HTML report](report-preview.png)

*The `--html` report: severity/confidence badges, the source→sink flow, and the
offending line for every finding — both JavaScript (DOM XSS) and C#/.NET.*

## What it does

1. **Finds sinks.**
   - *JavaScript:* `innerHTML`/`outerHTML`, `insertAdjacentHTML`,
     `document.write`, `eval`, the `Function()` constructor, string `setTimeout`,
     jQuery `.html()`/`.append()`, `$()` on a variable, `location`/`window.open`
     navigation, `setAttribute` on dangerous attributes, Angular
     `bypassSecurityTrust*`, React `dangerouslySetInnerHTML`.
   - *C# / .NET:* `@Html.Raw()`, `Response.Write()`, `new HtmlString()` /
     `MvcHtmlString`, Blazor `MarkupString`, control `.InnerHtml`.
2. **Finds sources.**
   - *JavaScript:* `location.hash`/`.search`/`.href`, `document.URL`,
     `document.referrer`, `window.name`, `document.cookie`, web storage, URL
     params, `history.state`, `postMessage` data (in files with a `message`
     listener).
   - *C# / .NET:* `Request.Query`/`Form`/`Params`/`Cookies`/`Headers`/`Body`,
     route values.
3. **Taint pass (JS).** A bounded fix-point marks variables assigned from a
   source (or from another tainted variable) as tainted. A sink that consumes a
   tainted value, or a source directly, is raised to **HIGH confidence**; a sink
   on a dynamic-but-untraced value is **medium**; a sink on a pure literal is
   **low**. (C# is sink-detection with source-on-line confidence; no cross-line
   taint — kept deliberately simple and honest.)

## Usage

```bash
python dxa.py <file-or-directory> [--json] [--html FILE] [--min-confidence low|medium|high]
```

Exit code is non-zero when findings are reported, so it can gate CI.

```bash
# scan a single file
python dxa.py examples/vulnerable.js

# scan a project, only the likely-real flows
python dxa.py ../../ --min-confidence high

# machine-readable output
python dxa.py src/ --json

# self-contained HTML report (severity/confidence, source->sink flow, code)
python dxa.py src/ --html report.html
```

### Example

```
$ python dxa.py examples/vulnerable.js
examples/vulnerable.js:6  [HIGH/high confidence]  sink: innerHTML  <- tainted var: q
    value assigned to (inner|outer)HTML is parsed as HTML
    | document.getElementById('out').innerHTML = q;
...
8 finding(s) - 4 at HIGH confidence (a source or tainted value reaches the sink).
```

`examples/vulnerable.js` (flagged) and `examples/safe.js` (the escaped/guarded
equivalents, quiet at `--min-confidence high`) double as a self-test.

## Tests

A `pytest` suite (`test_dxa.py`) locks down the detector's behaviour — taint
propagation, source read-vs-write, the C#/Razor rules, and that guarded/literal
cases are *not* raised to high confidence. It runs in CI on every push (see the
badge above).

```bash
pip install pytest
pytest -q      # from this directory
```

## Honest limitations

This is a **heuristic** — regular expressions plus a light taint pass, *not* a
sound analysis. It does **not** build an AST or a precise data-flow graph, so:

- **False positives:** matches inside comments and strings; a value flagged as
  reaching a sink may actually be validated (e.g. an allowlist the linter can't
  see). `examples/safe.js` shows a guarded `location.href` that is reported at
  medium and correctly disappears at `--min-confidence high`.
- **False negatives:** taint through function calls, aliasing, object
  properties, and template/JSX expressions is not tracked.

Use it to **prioritise** where to look, then confirm each finding by hand with
the browser DevTools workflow described in the repository. It is a triage aid and
a demonstration of the methodology — not a replacement for review.

## Why it exists

The repository documents *how* to reason about DOM XSS. This tool encodes the
first, mechanical half of that reasoning (locate the sources and sinks, connect
them) so the human can spend time on the half that matters: judging exploitability.

## Companion: `dxadyn` — dynamic reflection verifier

`dxa` is **static**: it reads code and says *"this looks like a source → sink
flow."* [`dxadyn.py`](dxadyn.py) is the **dynamic** other half: it drives a
*running* target, injects a unique canary (`dxa<rand>"<dXsS>`) into every GET
parameter and form field it discovers, and checks whether the markup comes back
**unencoded** — turning a static guess into an evidence-backed *"reflected raw
here"* candidate.

```
static  (dxa)     grep code for innerHTML/eval/… + source → sink taint
dynamic (dxadyn)  send canary → read response → did the markup survive raw?
```

```bash
python dxadyn.py http://localhost:8090/            # probe one page's inputs
python dxadyn.py http://localhost:8090/ --depth 1  # also follow same-host links one hop
```

It classifies each reflection as **unencoded** (raw tag survived → HTML injection
likely, HIGH), **attr-only** (a bare `"` survived → attribute breakout), or
**encoded** (reflected but escaped → safe, not reported). Stdlib only, same
zero-dependency ethos as `dxa`. It reports *candidates* — a raw reflection is a
strong signal, not proof of execution; confirm each in the browser, exactly as
with `dxa`'s HIGH findings.

> ⚠️ **Authorized / local targets only** — your own instance or an in-scope
> bug-bounty/VDP asset. `test_dxadyn.py` proves the detector on a throwaway local
> reflector (it flags the raw echo, ignores the HTML-escaped one).

### v2 - authenticated + stored mode

`dxadyn --stored` adds the two things v1 was missing: **login** and a **two-step
flow** (inject somewhere, verify on a different page). Together they cover the
class that matters most for real bug-hunting: an authenticated user (Author /
Editor) stores a payload in one place and it renders raw on a page that anyone -
or an admin - visits later.

```bash
python dxadyn.py --stored \
    --login http://localhost:8090/admin/login --user admin --pass labpass123 \
    --target http://localhost:8090/admin/new-content --target-field tags \
    --extra "title=probe,slug=dxaprobe,content=b,type=published" \
    --check 'http://localhost:8090/tag/{CID}-dxss'
```

`--login` grabs the CSRF token and posts credentials; success = a redirect off
the login page **or** a new session cookie. `--target` is the form to submit,
`--target-field` is the input to inject into, `--extra` fills the other required
fields. Each `--check` URL is then fetched and searched for the canary; `{CID}`
in a check URL is replaced with the canary id (handy when the target slugifies
the input into a URL, e.g. Bludit's `/tag/<slug>`).

**Ground-truth validation** - `test_dxadyn.py` runs an end-to-end auth+stored
flow against a throwaway local fixture, and the tool has been confirmed live on
Bludit 3.16.2 (CVE-2026-4420-shaped: tags-field stored XSS → renders raw in
`/tag/<slug>` page title, `</title>`-breakout executes in the body).

> ⚠️ **Authorized only.** These flows write into the target. Use on your own
> local instance or an in-scope bug-bounty/VDP asset. Confirm each flagged
> reflection in the browser (does the payload actually execute in the context it
> lands in? `<title>` reflection needs a `</title>` breakout; body reflection
> needs the right event handler).
