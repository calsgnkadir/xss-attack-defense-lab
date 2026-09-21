# Building an XSS bot: encoding a methodology as code

> **TL;DR** — The rest of this repo's writeups explain *how* an XSS bug works.
> This one turns that reasoning into a program: a static half (`dxa`) that reads
> code and flags source→sink flows, and a dynamic half (`dxadyn`) that drives a
> running target — injects a unique canary, follows the app's own links, and
> reports where the payload survived **unencoded**. End-to-end it needs no
> hand-picked URL: log in, submit, let it crawl. Same source→sink method as the
> hand-work in this repo — just automated, deterministic, and re-runnable in CI.
> Live-verified: it detects a CVE-2026-4420-shape stored XSS in Bludit's `tags`
> field autonomously.

Every earlier writeup here does the same three moves by hand: name the sources,
name the sinks, prove one reaches the other. Those moves *are* an algorithm; a
tool is just that algorithm without a human in the loop for the mechanical part.
The interesting question stops being "did the payload land?" and becomes "does
this reflection actually execute in the context it lands in?" — which is where
judgment still belongs.

## The gap the bot fills

Two things the by-hand writeups (01, 02, 05) hit repeatedly:

- **Static reading is a guess.** `grep`-ing a codebase for `innerHTML` says
  *"this is a sink"* — it does not say the value that reaches it is
  attacker-controlled or that the response actually renders it raw.
- **Dynamic testing is manual toil.** Log in, open the form, paste a canary,
  save, click around looking for where it shows up, view source, decide whether
  the browser will execute it. Every field. Every page. Every target.

The bot doesn't remove the judgment — it removes the toil, so the human time
goes to the judgment.

## Two halves of the same method

### `dxa` — source→sink as a linter (static)

A ~315-line regex + light taint pass over JS/TS and C#/.NET code.
Sink catalogue (`innerHTML`, `document.write`, `eval`, React
`dangerouslySetInnerHTML`, Angular `bypassSecurityTrust*`, jQuery `.html()`,
C#'s `@Html.Raw`, …), source catalogue (`location.hash`, `document.referrer`,
`URLSearchParams`, `Request.Query`, …), and a bounded fix-point that marks a
variable tainted if it was assigned from a source or another tainted variable.
A sink that consumes a tainted value is **HIGH**; a sink on a dynamic-but-untraced
value is **MEDIUM**; a sink on a constant is **LOW**. Exit code is non-zero when
findings are reported, so it can gate CI.

Honest about what it isn't: a regex heuristic, not a sound program analysis. It
prioritises where to look; a human still confirms.

### `dxadyn` — the dynamic verifier

Also stdlib-only. Injects a **unique canary** into every input it discovers and
inspects how it comes back:

```
canary = dxa<8hex>"<dXsS>
```

The `<dXsS>` marker is what has to survive **raw** for a reflection to count as
HTML injection — a `<` and `>` around content that isn't a real HTML tag will
either be encoded (safe) or preserved (unsafe). The `"` in front is a bonus
signal: if only the quote survives, you might still have an attribute-breakout
class bug. Every occurrence of the canary id is inspected: markup follows
directly → `unencoded` (HIGH); only a raw quote follows → `attr-only` (MEDIUM);
neither → `encoded` (safe, silent); id absent → this page isn't reflecting here.
The check looks at what follows the id **immediately** — otherwise the id landing
inside a link like `<a href="/tag/<cid>-…">` false-fires on the attribute's own
closing `"`.

Four modes let it reach real targets:

- **reflected** (default) — crawl a URL, probe every form field / GET param,
  verdict the same response.
- **`--stored`** — POST/GET one form on `--target`, then verdict each of one or
  more `--check` URLs.
- **`--login`** or **`--cookie` / `--header`** — classic HTML form login *or*
  paste a browser session cookie / bearer header. The cookie path is the escape
  hatch for SPA / OAuth / MFA logins that a scripted form-post cannot script.
- **`--auto-check`** — the one that turns stored mode from a manual sequence
  into a bot: submit, then crawl one hop from the origin (plus the submit's
  landing page and any `--auto-check-from` seeds) and verdict every page whose
  body actually contains the canary. No more guessing where the reflection will
  surface.

`{CID}` inside a `--check` or `--auto-check-from` URL is replaced with the
canary id — a hint for reflection pages that are otherwise unlinked (see the
honest limitation below).

## The walkthrough: catching Bludit's `tags` stored XSS

Target: **Bludit 3.16.2** in a local Docker container on `localhost:8090`,
admin credentials created via `bin/plugin login newuser`. The class we're
after is CVE-2026-4420: an authenticated user (Author, Editor, Admin) writes
a payload into a page's `tags` field; it renders unescaped on `/tag/<slug>`.

**By hand — six steps.** Log in. Open `admin/new-content`. Put
`dxaCANARY"><img src=x onerror=alert(1)>` in `tags`. Publish. Guess where it
shows up. Load `/tag/<slug>` (only if the theme links to it — which the
`alternative` theme doesn't). View source. Realise the reflection landed in
`<title>` — where `<img onerror>` doesn't execute — and re-inject with a
`</title>` breakout so it lands in `<body>` and the browser runs it. That last
step is what turns "the value reflected raw" into "this actually runs."

**With the bot — one command:**

```
python dxadyn.py --stored --auto-check \
    --auto-check-from 'http://localhost:8090/tag/{CID}-dxss' \
    --login http://localhost:8090/admin/login --user admin --pass labpass123 \
    --target http://localhost:8090/admin/new-content --target-field tags \
    --extra "title=probe,slug=probe1,content=b,type=published"
```

Output (redacted for length):

```
[dxadyn] login … -> OK
[dxadyn] STORED-AUTO probe … (seeds=3, max=60) - authorized/local only
[dxadyn] canary id = dxaa4479970
[dxadyn] submit landed at: http://localhost:8090/admin/content
[dxadyn] crawled 32/32 pages
http://localhost:8090/tag/dxaa4479970-dxss  [HIGH] [auto]
    stored via …/admin/new-content field 'tags'  -> UNENCODED (HTML injection)
    (submit HTTP 200, check HTTP 200)
```

`[auto]` distinguishes an auto-discovered hit from a hand-picked `--check`.
The exit code is `1` — a CI job on this target would fail. The judgment step
that remains is the same one the six-step by-hand version ends on: **does this
context actually execute?** For this class the tag lands in `<title>`; that is
an HTML injection but not, on its own, script execution. `</title>` breakout in
a follow-up injection puts an `<img onerror>` in `<body>` and the browser fires
it — the "unencoded" report is the invitation to check exactly that.

## What "caught" honestly means

The bot proves **HTML injection** — a value reached the response as markup, not
as text. That is one step short of proving **script execution**, which depends
on the surrounding context (a text-only place like `<title>` or a plain
attribute won't run an `<img onerror>` without a follow-on breakout; a body
insertion often will). The bot flags reflections; a human still puts one in the
browser to confirm. This is the same discipline the repo has always had: the
tool tells you where to spend your time, not what to believe.

The Bludit finding is worth calling out for what it *is* and *isn't*:

- **It is:** a real, reproducible, authenticated stored XSS on Bludit 3.16.2,
  caught end-to-end by the bot with no hand-picked check URL.
- **It isn't:** a novel CVE. Bludit is heavily audited and the tags/categories
  input class has several existing CVEs. The value here is **tool validation on
  a real target** — the same shape you'd want in a portfolio piece.

## Honest limitations

- **Auto-check is one hop.** If the reflection page is *orphaned* — nothing on
  the site links to it, like Bludit's `/tag/<slug>` under the default theme —
  the crawler cannot conjure the URL. Hint it via `--auto-check-from` with a
  `{CID}` template. That is not the tool failing; it is the tool being honest.
- **HTML-form login only** (unless you paste a cookie). Svelte/React admins
  that post JSON to `/api/v1` (Grav's `admin2` is a live example) cannot be
  scripted with `--login`; the answer is `--cookie` from DevTools or a future
  JSON-body mode.
- **No headless browser.** Reflections that execute purely in the client
  (DOM-XSS via `location.hash` → `innerHTML`) are not visible in the raw HTTP
  response the tool inspects — that is what [Writeup 02](02-dom-xss-assessment-react-spa.md)'s
  method covers by hand, and what a future headless verifier would automate.
- **Regex, not AST.** Static side has the usual heuristic drawbacks
  ([`dxa`'s own README](../tools/dom-xss-analyzer/README.md#honest-limitations)
  lists them). Use HIGH-confidence flags to prioritise, not as gospel.

## Takeaway

The methodology in this repo isn't magic; it's an algorithm — enumerate sources,
enumerate sinks, prove one reaches the other, then judge whether the browser
runs it. Automating the mechanical two-thirds turns finding *this shape* of bug
from "an afternoon per target" into "one command," and frees a human to spend
their attention on the part that still requires taste: does the reflected value
actually execute in the context it landed in? Everything else, the bot can do
deterministically, offline, and in CI — no AI needed, no LLM to hallucinate,
and every step reproducible in a unit test.

---

*Hands-on, on an authorized local target only: Bludit 3.16.2 in Docker on
`localhost:8090`, admin credentials seeded via the login-plugin CLI. Tool
sources: [`tools/dom-xss-analyzer/dxa.py`](../tools/dom-xss-analyzer/dxa.py) +
[`dxadyn.py`](../tools/dom-xss-analyzer/dxadyn.py) — 27 pytest cases, CI-gated,
zero third-party dependencies. Reference: CVE-2026-4420 (Bludit ≥ 3.17.2 confirmed,
3.16.2 shown here to carry the same shape).*
