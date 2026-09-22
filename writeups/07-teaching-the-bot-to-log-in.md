# Teaching the bot to log in, find its own targets, and shut up

> **TL;DR** — [Writeup 06](06-building-an-xss-bot.md) shipped the first
> version of the XSS bot: static (`dxa`) + dynamic (`dxadyn`) source→sink
> together in one command. It caught the obvious classes but left three real
> problems: **modern admins log in over JSON, not HTML forms**; **stored
> reflections don't always live where you tell them to**; and **static analysis
> on well-written code turns into an avalanche of false HIGH-confidence noise**.
> This writeup is the fix pass — session import for SPA logins (`--cookie` /
> `--header`), autonomous post-submit crawling (`--auto-check`), two more
> submission shapes (`--json-body`, `--header-target`), a third static language
> (PHP), an escape-aware false-positive squelch, and a visual HTML report.
> None of it is a new class; all of it is what "makes it a tool you'd actually
> hand to someone else."

The interesting rule this pass illustrates: the difference between "toy" and
"tool" is almost never a new attack technique — it's what happens on the second,
tenth, and thousandth run against a real target that doesn't cooperate.

## Problem 1 — the admin doesn't have an HTML form to scrape

`dxadyn --login` (writeup 06) fetches the login page, grabs the CSRF token from
a hidden `<input>`, POSTs credentials, follows the redirect. That's exactly the
1998 shape and it's exactly what most admins **used to** look like. Modern
admins (Grav's `admin2`, most React/Vue/Svelte-shell dashboards) render a
mostly-empty HTML shell and log in over a JSON call to `/api/v1/…`. No form,
no CSRF `<input>` — no purchase for scripted login.

Two flags close this without adding a real browser dependency:

```
--cookie "sid=abc; csrf=xyz"                     # attach one Cookie header to everything
--header 'Authorization: Bearer eyJ...'          # repeatable; bearer / X-CSRF / anything
```

The mechanism is a one-line change in `fetch()`: every request merges a shared
`EXTRA_HEADERS` dict on top of `User-Agent`. The user logs in **through their
own browser** (which handles the SPA, OAuth, MFA, whatever), copies the
session cookie out of DevTools, pastes it once, and every subsequent request
`dxadyn` makes rides that session. This is the **escape hatch every scanner
eventually adds** because the alternative — scripting five vendors' JS login
flows — is a full-time job.

A regression test opens a real HTTP echo server and asserts the header arrives
on the wire; no more silent "it looked like it worked."

## Problem 2 — the payload lands somewhere you didn't guess

The v2 stored mode required `--check http://target/tag/...` — the operator had
to *know* which page would carry the payload. Bludit's `/tag/<slug>` is a
classic example: the URL is derived from the tag value, and the theme doesn't
even link to it, so you either look at the source of the CMS or you guess.

`--auto-check` removes that. After the submit, `dxadyn` fetches a small set of
seeds (the submit's landing page, the target's origin `/`, and any
`--auto-check-from` URLs the operator passes), extracts every same-host `<a
href>` one hop out, and **verdicts every page whose body actually contains the
canary id**. No more guessing where the tag/comment/post surfaces. On Bludit's
CVE-2026-4420-shape tag stored XSS the full pipeline is:

```
login → submit admin/new-content (tags = canary) → crawl 33 pages → verdict
                                                → /tag/<slug> UNENCODED [auto]
```

Bludit's `alternative` theme is a good stress test because it *never* links to
`/tag/<slug>`. Auto-check would find nothing on its own. The `--auto-check-from
http://target/tag/{CID}-dxss` template covers this case honestly: the operator
tells the bot the URL *shape*, the bot fills in the canary id and probes it.
That's not "the tool failing to be autonomous"; it's the tool being honest that
it can't conjure orphan URLs it has never seen. A verdict tightening ("markup
must follow the canary immediately, not somewhere near it") kills the false
positive where the canary lands inside a slug URL and the attribute's closing
`"` looks like an attribute breakout.

## Problem 3 — one submission shape isn't enough

`--target-field` posts an HTML form. The other two shapes real targets use are
**JSON body** (SPA admins) and **an HTTP header value** (headers that later
render into a page). v3.4 adds both, wired into the same `probe_stored` and
`probe_stored_auto` — the auto-crawler doesn't care how the canary was submitted,
only where it surfaces.

```
--json-body '{"tags":"{CANARY}","title":"probe"}'   # SPA / REST admin path
--header-target True-Client-IP                      # stored header injection
```

`{CANARY}` inside a JSON template is JSON-string-safe substituted (the canary's
`"` gets escaped so the template stays valid JSON); the header path uses the
same `EXTRA_HEADERS` hook as `--cookie`. The header shape is Finding #8's class
in this repo's Juice Shop assessment — the two-step `True-Client-IP` →
`lastLoginIp` render — with the manual steps automated.

## PHP joins JS/C# on the static side

`dxa` used to only read JS/TS and C#/.NET. Anything PHP-heavy (Bludit,
WordPress plugins, small self-hosted CMSes) got zero coverage and the bridge
(`dxa2dyn`) produced zero hints. v3.4 (co-committed) added PHP sinks
(`echo`/`print` of `$vars`, `<?= $var ?>`, Blade `{!! !!}`, Twig `|raw`, printf
family), PHP sources (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER`/
`$_FILES`, `php://input`, Laravel `Request::input(...)` / `request()->…`,
Symfony `$request->…`), and — the interesting piece — **PHP taint** running on
the same bounded fix-point that JS uses, with a per-language `ASSIGN` regex.
A word-boundary bug had to be fixed en route (Python's `\b` doesn't treat `$`
as a word boundary; `(?<!\w)` lookbehind works for both PHP and JS identifiers).

`dxa` on Bludit's `bl-kernel/` (~110 PHP files) reports **260 findings, 0
HIGH.** That is the *right* number — Bludit disciplines its output through
`Text::htmlEncode()`, so the source→sink border never opens in a single line.
On a plugin from a hobby developer with a `echo $_GET['q']` in it, the same
tool would fire HIGH and be right. The number a bot returns on well-written
code is as important as the number on bad code; if the well-written case is
noisy, no one uses the tool.

## Shutting up: the false-positive squelch

The first version of the escape-aware HIGH → MEDIUM downgrade did *"if there
is an escape call on this line, silence the finding."* That was too aggressive
against minified single-line blobs (jQuery's line 2 is 90 KB; `encodeURIComponent`
appears in it *somewhere*, so every real finding on that line got silenced).
The fix: **proximity.** The escape call must be within ~200 characters of the
sink's match position, and lines longer than 500 characters (minified) skip the
squelch entirely — they need eyes-on review anyway.

Regression numbers on the seeded example corpus + Bludit:

- `safe.php`  HIGH = 0 (escape sits next to the sink — silenced correctly)
- `vulnerable.php`  HIGH = 5 (no escape near the sink — unchanged)
- Bludit `bl-kernel/`  HIGH = 4 (jQuery's real `innerHTML` from `location.hash`
  is no longer silenced by a distant `encodeURIComponent`; recovered)

This is what "engineered" means, one drop at a time: catch a false pattern, add
a specific counter-heuristic, keep the corpus of what should and should not fire
in tests so the next change doesn't undo it.

## Visual output: `--html`

`dxa` had a self-contained HTML report from the beginning; `dxadyn` only wrote
text. `--html FILE` closes that. The two tools now share visual language — dark
GitHub-ish theme, severity/confidence badges, origin column
(`reflected` / `stored` / `stored-auto` / `dxa-guided`) — so the pair look like
one product. The Bludit run above renders as one `[HIGH]` `[unencoded]` row with
the canary URL, submit + check HTTP codes, and a warning strip that says exactly
what it says in the text output: *"reflection is not proof of execution — confirm
each HIGH in the browser (the surrounding HTML context decides whether the
payload actually runs)."* A screenshot of this report is what goes into a
portfolio.

## What "professional" honestly means (and doesn't)

After this pass:

| Class | Covered | How |
|-------|---------|-----|
| Reflected XSS | ✅ | `dxadyn <url>` |
| Reflected header XSS | ✅ | `--probe-headers` |
| Stored XSS (form → same or other page) | ✅ | `--stored --check` or `--stored --auto-check` |
| Stored XSS (JSON API path) | ✅ | `--json-body` |
| Stored header injection (two-step) | ✅ | `--header-target` |
| SPA / bearer-token targets | ✅ | `--cookie` / `--header` |
| Static: JS / C# / PHP source → sink | ✅ | `dxa` |
| Static-guided dynamic probing | ✅ | `dxa2dyn` |
| DOM XSS via `location.hash` / `postMessage` | ❌ | needs a headless browser (Playwright) |
| Blind XSS (fires elsewhere / later) | ❌ | needs an out-of-band callback server |
| Payload mutation / WAF bypass | ❌ | one canary shape only |
| Sink-context awareness (`<title>` vs `<body>`) | ⚠️ | flags reflection, not executability |
| Concurrency, rate-limit, robots.txt | ❌ | sequential; polite-crawl not implemented |

The honest position, given that list: this is **not** a Burp Scanner or DalFox
competitor. It is a **reference-quality methodology tool** — the source→sink
discipline that runs through the rest of this repo, written down as code,
tested against real vulnerable targets, and shipped with the honest edges of
what a regex-plus-canary approach can and cannot see. The blind spots above
aren't excuses; they are the *reasons* an interview conversation about this
tool has a second half. *"Why not headless?"* opens the door to a real
discussion about coverage vs deployment cost that a candidate who has thought
about the trade-off can defend.

## Takeaway

Between writeup 06 and this one, the bot went from *"catches the classic shape
against the exact URL you tell it to look at"* to *"logs in against a modern
admin, submits a payload however the target expects it, and finds where the
payload landed on its own — then writes a page you can share."* Same
underlying methodology as every other writeup here (enumerate sources, enumerate
sinks, prove the reach, judge execution) — automated far enough that the human
time goes to the last step.

---

*Hands-on, on an authorized local target only: OWASP Bludit 3.16.2 in Docker
(`localhost:8090`, admin credentials seeded via the login-plugin CLI), plus
seeded `examples/` corpus (safe.php / vulnerable.php / vulnerable.js /
vulnerable.cs / vulnerable.cshtml). Tool sources:
[`tools/dom-xss-analyzer/dxa.py`](../tools/dom-xss-analyzer/dxa.py),
[`dxadyn.py`](../tools/dom-xss-analyzer/dxadyn.py), and the bridge
[`dxa2dyn.py`](../tools/dom-xss-analyzer/dxa2dyn.py) — 44 pytest cases, CI-gated,
zero third-party dependencies. Reference: CVE-2026-4420 shape (Bludit tags
stored XSS, autonomous end-to-end detection).*
