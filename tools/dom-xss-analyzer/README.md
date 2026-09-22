# dxa — source→sink XSS analyzer (full-stack)

[![CI](https://github.com/calsgnkadir/xss-attack-defense-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/calsgnkadir/xss-attack-defense-lab/actions/workflows/ci.yml)

A small, dependency-free static linter that flags XSS sources, sinks, and the
likely **source → sink flows** between them — across a full-stack surface:

- **client side** — JavaScript / TypeScript (DOM XSS)
- **server side** — C# / ASP.NET & Razor (server-rendered XSS)
- **server side** — PHP (`echo` / `print` / `<?= ?>` / Blade `{!! !!}` / Twig `|raw`)

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
   - *PHP:* `echo`/`print` of a `$var`, short-echo `<?= $var ?>`, Blade
     `{!! $x !!}` (raw), Twig `|raw`, `printf`/`vprintf`, `file_put_contents`.
2. **Finds sources.**
   - *JavaScript:* `location.hash`/`.search`/`.href`, `document.URL`,
     `document.referrer`, `window.name`, `document.cookie`, web storage, URL
     params, `history.state`, `postMessage` data (in files with a `message`
     listener).
   - *C# / .NET:* `Request.Query`/`Form`/`Params`/`Cookies`/`Headers`/`Body`,
     route values.
   - *PHP:* superglobals `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER`
     (incl. `HTTP_*` headers)/`$_FILES`, `php://input`, Laravel
     `Request::input(...)` / `request()->query(...)`, Symfony `$request->query`.
3. **Taint pass (JS + PHP).** A bounded fix-point marks variables assigned from
   a source (or from another tainted variable) as tainted. A sink that consumes
   a tainted value, or a source directly, is raised to **HIGH confidence**; a
   sink on a dynamic-but-untraced value is **medium**; a sink on a pure literal
   is **low**. (C# is sink-detection with source-on-line confidence; no cross-line
   taint — kept deliberately simple and honest.)
4. **FP squelch.** If an escape-family call (`htmlspecialchars`, `DOMPurify.sanitize`,
   `HttpUtility.HtmlEncode`, ...) is on the same line as the sink, HIGH is
   downgraded to MEDIUM — the value is more likely sanitised than not, and the
   operator's attention should go to the un-escaped lines.

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

### v3.1 - session import (`--cookie`, `--header`)

Real modern targets increasingly ship **SPA admins that log in via a JS-driven
JSON call** (Grav's `admin2`, most React/Vue/Svelte admin panels). Scripting
that login is fragile - and often needs MFA / OAuth / captcha. `dxadyn` sidesteps
that entirely: **log in through your browser once, copy the session cookie from
DevTools, paste it in.** Every subsequent request rides that session.

```bash
# authenticated reflected probe on an admin surface, using a real browser session
python dxadyn.py http://target/admin/settings \
    --cookie "PHPSESSID=abc123; csrf=xyz"

# same, for a bearer-token API + custom CSRF header
python dxadyn.py http://target/dashboard \
    --header 'Authorization: Bearer eyJ...' \
    --header 'X-CSRF-Token: tok42'

# --cookie combined with --stored to probe an authenticated stored-XSS flow
python dxadyn.py --stored --cookie "PHPSESSID=abc123" \
    --target http://target/admin/new-content --target-field tags \
    --extra "title=t,type=published" \
    --check 'http://target/tag/{CID}-dxss'
```

`--header` is repeatable. Both flags attach to **every** request `dxadyn` makes
(the initial page fetch, the injection submit, the check URLs). Unit tests
(`test_apply_cookie_rides_every_request`, `test_apply_header_parses_name_value_and_rejects_junk`)
run a local echo server and assert the header actually arrives on the wire.

### v3.2 - `--auto-check` (submit, then crawl to find where the payload landed)

v2's stored mode needed `--check URL[,URL]` - the operator had to *know* which
page would carry the payload. v3.2 removes that: after the submit, `dxadyn`
crawls one hop out from the target's origin (plus the submit's landing page and
any `--auto-check-from` seeds you pass), fetches each candidate, and verdicts
every page whose body actually contains the canary id. Autonomous - no more
guessing where the tag/comment/post shows up.

```bash
# fully autonomous - the tool finds the reflected page itself
python dxadyn.py --stored --auto-check \
    --login http://localhost:8090/admin/login --user admin --pass labpass123 \
    --target http://localhost:8090/admin/new-content --target-field tags \
    --extra "title=probe,slug=x,content=b,type=published"

# hint with a URL template when the reflection page is "orphaned"
# (linked from nowhere - Bludit's /tag/<slug> is a classic example).
# {CID} in a seed URL is replaced with the canary id.
python dxadyn.py --stored --auto-check \
    --auto-check-from 'http://localhost:8090/tag/{CID}-dxss' \
    --login ... --target ... --target-field tags --extra ...
```

Findings from auto-check are flagged with `[auto]` in the output so you can tell
them apart from a hand-picked `--check` hit.

**Live-verified on Bludit 3.16.2** — CVE-2026-4420-shaped tag-field stored XSS
was detected end-to-end (login → submit `admin/new-content` → crawl 32 pages →
verdict `/tag/<slug>` page unencoded). Reproduction is one command (above).

**Honest limitation.** Auto-check does one hop from its seeds. If the vulnerable
page has no inbound link anywhere in that reach (Bludit's default theme doesn't
render `/tag/<slug>` links at all), you need to hint the URL shape with
`--auto-check-from '.../{CID}...'`. That is not "the tool failing" - it is the
tool being honest that it cannot conjure orphan URLs it has never seen.

### v3.3 - `dxa2dyn` bridge + `--probe-headers`

Two additions turn the pair into an integrated bot:

**`dxa2dyn.py` - static -> dynamic bridge.** Runs `dxa` on a codebase, pulls
likely HTTP parameter names out of its HIGH-confidence findings (Express
`req.query.q`, Django-ish `request.form['x']`, .NET `Request.QueryString["y"]`,
`URLSearchParams.get('z')` ...), then drives `dxadyn` against a running URL,
adding those hinted parameters as targeted GET probes on top of the parameters
`dxadyn` discovers by crawling. One command, both lenses.

```bash
python dxa2dyn.py ./app/routes http://localhost:3000/ \
    --cookie "sid=..." --header 'X-CSRF: tok'
```

**`--probe-headers "H1,H2,..."`** — reflected-mode add-on that sends the target
URL once per named header, each carrying a canary, and verdicts the response.
Catches the class of header-injection reflection (`X-Forwarded-For`,
`True-Client-IP`, `Referer`, `User-Agent` written into a page). This is
Finding #8's shape from this repo's Juice Shop assessment, but caught by an
automated probe.

```bash
python dxadyn.py http://target/dashboard --cookie "sid=..." \
    --probe-headers "True-Client-IP,X-Forwarded-For,Referer,User-Agent"
```

**Honest scope of v3.3:**
- `dxa2dyn`'s static side is JS/TS + C#/.NET only (that's `dxa`'s scope).
  Bludit's PHP source, for example, yields zero JS/C# hits - the bridge then
  falls back to `dxadyn`'s own crawl discovery. PHP support belongs in a future
  `dxa` extension.
- `--probe-headers` catches **reflected** header XSS (single response). The
  stored two-step variant is v3.4 (`--stored --header-target`).
- Both features have unit tests (`test_dxa2dyn.py`, `test_probe_headers_*`) that
  run a local echo/reflector server and assert raw vs escaped is told apart.

### v3.4 - `--json-body` and `--stored --header-target`

Stored mode's `--target-field` shape covered classic HTML forms. v3.4 adds the
two other shapes real modern targets use:

**`--json-body 'JSON_TEMPLATE'` — SPA / REST admin path.** Post a JSON body
directly to `--target` with `{CANARY}` where the payload should land. This is
the escape hatch for admins like Grav's `admin2` that log in over a JS-driven
JSON API instead of an HTML form. Combine with `--cookie` (from a browser
session) to get through the SPA login itself.

```bash
python dxadyn.py --stored \
    --cookie "session=..." \
    --target http://target/api/v1/pages --json-body '{"tags":"{CANARY}"}' \
    --auto-check --auto-check-from 'http://target/tag/{CID}-dxss'
```

`{CANARY}` is JSON-string-safe substituted (the canary's `"` is properly
escaped so the template stays valid JSON).

**`--header-target HEADER_NAME` — stored header-injection.** Sends one request
to `--target` with the canary in the named HTTP header, then verdicts the
check URL(s). This is the class where an app writes an incoming header
(`X-Forwarded-For`, `True-Client-IP`, `Referer`, `User-Agent`) into a page
that renders **later**, on a different route or for a different user. This
repo's own Juice Shop Finding #8 (`True-Client-IP` → Last Login IP) is the
canonical shape, and Bludit has the same pattern:

```bash
python dxadyn.py --stored \
    --cookie "BLUDIT-KEY=..." \
    --target http://localhost:8090/admin/dashboard --header-target True-Client-IP \
    --method get --csrf-field "" \
    --check http://localhost:8090/admin/users/admin
```

Both new shapes plug into `--auto-check` too — the crawler doesn't care how the
canary got submitted, only where it surfaces.

**Honest scope of v3.4:** the JSON body path is a literal template — no schema
introspection, no OpenAPI. If the target expects a nested body you author it,
same as any other API-testing tool. That is deliberate: schema-driven fuzzing
is a different (larger) project.
