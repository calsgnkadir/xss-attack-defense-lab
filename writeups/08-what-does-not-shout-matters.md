# What the bot *doesn't* shout about is what makes it useful

> **TL;DR** — [Writeup 06](06-building-an-xss-bot.md) shipped the bot; [Writeup
> 07](07-teaching-the-bot-to-log-in.md) taught it to log in and shut up about
> escaped code. This pass finished the second half: **teach it that "reflected
> raw" is not one thing**. A canary that lands in `<title>` doesn't execute; a
> canary echoed inside `application/json` isn't parsed as HTML at all; the same
> underlying stored bug reflected across 58 admin preview pages isn't 58 bugs.
> None of this makes the bot find more — it makes the bot's HIGH label mean
> something. The other half of the pass added a fourth static language (Java /
> Servlet / Spring / JSP / Thymeleaf), which turned a 211-file Spring backend
> into 3 real "eyes-on this line" candidates instead of nothing.

The interesting rule this pass illustrates: **a security tool's value is
proportional to how much of its output the human can trust as signal**. The
easy way to make a tool look impressive is to raise its recall (flag more).
The useful way is to raise its precision (flag *the right* things) and be
honest about the rest. That is what v3.5-v3.7 do.

## The gap writeup 07 left open

At the end of writeup 07 the bot could log in against SPAs, submit through
JSON / forms / headers, crawl its own check URLs after the submit, and quiet
same-line escapes on the static side. But its output still read the same for
every raw reflection:

```
[HIGH] UNENCODED (HTML injection)   -- for every single hit
```

Three separate real-world problems all wore that label:

- The Bludit tag XSS from writeup 06 lands **inside `<title>`**. It IS a raw
  reflection, but `<title>` renders as text; a browser doesn't run
  `<img onerror>` there without a `</title>` breakout. So "HIGH executable"
  overstates it.
- WonderCMS's stored payload surfaces on **58 different admin preview pages**
  because the same template renders the current page's content on every
  admin route. All 58 rows are one bug; the label buries the real signal.
- A REST endpoint that echoes the canary in a `{"name":"dxa..\"<dXsS>"}`
  response body flags as `[HIGH] UNENCODED` too — but the response is
  `application/json`, so the browser parses it as JSON and nothing executes.
  Same label, different reality.

Each of these is a specific, addressable false-positive class. Fixing them
doesn't need better crawling or a headless browser; it needs the bot to look
at *where the payload landed* and *how the response is served* before deciding
what to yell.

## Sink context: `<title>` is not `<body>`

`find_context(cid, body)` walks backward from the first canary occurrence and
classifies the enclosing HTML region:

- **`body`** — free markup context; a raw `<img onerror>` executes as-is.
- **`title`** — inside an unclosed `<title>...</title>`; needs `</title>`
  breakout for real execution.
- **`script`** — inside `<script>...</script>`; needs a JavaScript string
  breakout (`';...//`), a different attack shape.
- **`attr:<name>`** — inside an HTML attribute value; needs `"` or `'` breakout.
- **`url-attr:<name>`** — the attribute is `href`/`src`/`action`/... — a
  `javascript:` URL executes here without markup.

Each finding then computes a **severity** on top of the raw verdict:

```
executable    - HIGH + body/unknown context: <img onerror> works
breakout-req  - HIGH + title/script/attr: needs a follow-on payload
attr-breakout - verdict is 'attr-only' (a bare " survived)
```

The Bludit CVE-2026-4420-shape tag payload used to render as `[HIGH]
UNENCODED`; it now renders as `[BREAKOUT-REQ] context=title` — accurate: it
IS reflected raw, but you need `</title>` to execute. Same information, no
overstatement. The bot's output is now closer to what an experienced tester
would say by hand.

## Dedup: one bug is one row

WonderCMS's stored content preview turns up on every admin plugin/theme page,
so a single payload injection surfaces on ~58 URLs. The v2 output was ~58
rows, one per URL — one bug, 58 lines of noise. `dedupe_findings(findings)`
groups by `(canary_id, reflection, context)` and keeps the first URL as
primary; the rest go into a `duplicates: [...]` list on it. Output becomes:

```
http://target/tag/dxa... [EXECUTABLE] context=body
    (+57 more URLs, same bug)
```

Not a new detection, a legibility fix. On real targets — anywhere the same
value threads through a shared template — this collapses the "wall of red"
to something a human can act on.

## PUT / PATCH / DELETE: reaching real REST APIs

v3.4's `--method get|post` was too narrow. REST endpoints that store data
use `PUT` (`/api/candidate/profile`), `PATCH`, or `DELETE`. `fetch()` grew a
`method=` kwarg (Python's `Request(method=...)`) and every submission path
(`_submit_form`, `_submit_json`, `_submit_header`) plumbed it through. The
CLI's `--method` choices expanded from two to five. That's it — 30 lines,
but without them dxadyn simply couldn't touch half the modern API surface.

## The Content-Type gate — the live-fire lesson

The first time I pointed the v3.6 build at my own hotel-platform (React SPA
+ Spring Boot + MySQL, JWT-authenticated REST), the bot came back with:

```
[EXECUTABLE] context=body   POST /api/candidate/profile
    -> UNENCODED (HTML injection)
```

The excitement lasted about ninety seconds. The response was:

```
HTTP/1.1 200
Content-Type: application/json
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-store
...
{"fullName":"dxa..\"<dXsS>", ...}
```

The canary survived raw in the body bytes, but the browser is *never* going
to parse that as HTML. `application/json` + `nosniff` means "this is JSON, do
not sniff it as anything else." The finding was real HTML injection only in
the sense that the value crossed the trust boundary; there is no browser path
by which it executes without a client-side sink downstream (a React
component that `dangerouslySetInnerHTML`'s it).

So the bot needed to see the Content-Type before scoring. `fetch()` widened
to return `(status, final_url, body, content_type)`; all 17 call sites in
the codebase updated. `_apply_ct_gate(reflection, context, content_type)`
runs on every finding and downgrades non-HTML responses:

- HTML-like (`text/html`, xhtml, svg, `text/*` except json/plain/csv,
  empty/unknown) → keep the existing severity.
- JSON family (`application/json`, `application/ld+json`, `application/
  hal+json`, `application/problem+json`, `text/json`) and `text/plain` /
  `text/csv` → context becomes `json-body`, severity becomes `json-only`.

`json-only` is a *new* severity, deliberately not `executable` and
deliberately not `-`. The value **did** reflect raw across a boundary; that
is worth recording. But it's a "look one layer up in the front-end"
finding, not a "the browser will run this now" finding. The bot's line about
the hotel-platform PUT now reads:

```
[JSON-ONLY] context=json-body   PUT /api/candidate/profile
    -> UNENCODED (HTML injection)
```

Same underlying facts, honest label. The finding is still surfaced — it just
doesn't crowd out actual body-context executions when both exist on the same
target.

## Java: the fourth language

None of the above helps if the tool can't read the code that produced the
response in the first place. The hotel-platform backend is 211 Java files,
Spring Boot 3, Servlet-level filters — a wall to `dxa` until this pass.

`dxa` now scans `.java` / `.jsp` / `.jspx` / `.tag`. Sinks: Servlet
`response.getWriter().print/println/write`, `PrintWriter.print`,
`ServletOutputStream.write`, JSP `<%= %>` scriptlets, `<c:out escapeXml=
"false">`, Thymeleaf `th:utext` and `[(${...})]`, jsoup `Element.html(x)`,
and `response.setHeader`. Sources: `request.getParameter`, `getHeader`,
`getCookies`, `getReader`, `getInputStream`, path-info, plus the Spring
annotations `@RequestParam`, `@RequestHeader`, `@PathVariable`,
`@CookieValue`, `@RequestBody`, `@ModelAttribute`. Taint runs the same
bounded fix-point as JS/PHP, driven by a Java-specific `ASSIGN` regex that
handles `Type name = expr;` (types may be generic). FP squelch: OWASP
`Encode.forHtml*`, Apache Commons `StringEscapeUtils.escapeHtml{3,4}`, Spring
`HtmlUtils.htmlEscape`, ESAPI `encodeForHTML` — within 200 chars of the sink,
downgrade HIGH to MEDIUM.

Pointed at hotel-platform's `hotelapp/src/main/java`: **3 HIGH, 6 MEDIUM,
211 files scanned in a second.** The three HIGH: two on
`IdempotencyFilter.java:88` (the same line matched two sink patterns —
`servlet-writer` and `response-write`, that's a dedup opportunity for
another pass) writing a cached JSON body back on cache hit; one on
`CorrelationIdFilter.java:50` writing the inbound `X-Correlation-Id` value
back onto the response header. Both are defensively guarded at runtime:
`IdempotencyFilter` writes cached prior-successful-JSON with an
`application/json` Content-Type; `CorrelationIdFilter` calls `sanitize(inbound)`
and enforces a 64-character length limit before echoing. The bot flagged
the reach, not the exploit — which is exactly the right level for a regex
heuristic. A cross-method-taint upgrade (see honest limitations) would
follow the `sanitize()` call one level and quiet the CorrelationId flag; it
is deliberately not done yet because the value of *"here is a source that
reaches a sink through your own code, please review"* is high on its own.

## Where the bot honestly stands after this pass

Updated capability matrix:

| Class | Covered | How |
|-------|---------|-----|
| Reflected XSS | ✅ | `dxadyn <url>` |
| Reflected header XSS | ✅ | `--probe-headers` |
| Stored XSS (form) | ✅ | `--stored --target-field` |
| Stored XSS (JSON API) | ✅ | `--stored --json-body` |
| Stored header injection (2-step) | ✅ | `--stored --header-target` |
| Autonomous check URL discovery | ✅ | `--auto-check` (with orphan-page hints via `--auto-check-from`) |
| SPA / bearer-token / OAuth targets | ✅ | `--cookie` / `--header` |
| REST methods (PUT/PATCH/DELETE) | ✅ | `--method` (v3.6) |
| Sink-context awareness | ✅ | `find_context()` + severity ladder (v3.5) |
| Response Content-Type awareness | ✅ | `_apply_ct_gate()` (v3.7) |
| Same-bug dedup across pages | ✅ | `dedupe_findings()` (v3.5) |
| Static: JS / TS / C# / PHP / Java | ✅ | `dxa` (Java added this pass) |
| Static-guided dynamic probing | ✅ | `dxa2dyn` |
| Cross-method taint (Java `sanitize()`, etc.) | ❌ | regex-not-AST limitation |
| DOM XSS via `location.hash` → sink | ❌ | needs a headless browser |
| Blind XSS (fires elsewhere / later) | ❌ | needs an out-of-band callback server |
| Payload mutation / WAF bypass | ❌ | one canary shape only |

The gaps at the bottom are real. This pass didn't close them; it made the
findings the bot *does* return more honest — which is the harder half of a
security tool's job. **Precision before recall** is a defensible engineering
choice for a hand-written triage aid; recall-first is the design for
commercial scanners with response teams to filter their output.

## Takeaway

Every fix in this pass — sink context, dedup, Content-Type gate, Java —
targeted a specific class of false or over-labelled finding I had seen the
bot produce against a *real* target (Bludit, WonderCMS, hotel-platform).
None of them made the bot find something it wasn't finding before. All of
them made the label attached to what it finds match what the human would
say after looking. That is the maturity step between "runs" and "you would
actually hand it to someone."

Same source→sink discipline as the rest of the repo — with the honest edges
of what a regex-plus-canary approach can and can't tell you drawn in ink.

---

*Hands-on, on authorized local targets only: seeded `examples/` corpus
(safe.java / vulnerable.java joined the JS + C# + PHP set); OWASP Bludit
3.16.2 (auto-check on the tag stored XSS, now labelled context=title
breakout-req); WonderCMS latest (58-page dedup collapse to 1 primary);
hotel-platform (Spring Boot 3 + React SPA + MySQL, 211 Java files scanned +
JWT-authenticated PUT probe demonstrating the JSON Content-Type gate).
Tool sources: [`tools/dom-xss-analyzer/dxa.py`](../tools/dom-xss-analyzer/dxa.py),
[`dxadyn.py`](../tools/dom-xss-analyzer/dxadyn.py), and
[`dxa2dyn.py`](../tools/dom-xss-analyzer/dxa2dyn.py) — 66 pytest cases,
CI-gated, zero third-party dependencies.*
