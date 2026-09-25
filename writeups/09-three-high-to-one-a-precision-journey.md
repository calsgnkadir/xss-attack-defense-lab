# Three HIGH to one: a precision journey on real code

> **TL;DR** — After [Writeup 08](08-what-does-not-shout-matters.md) added Java
> to `dxa`, the first live-fire run against my own hotel-platform Spring Boot
> backend (211 Java files) returned **3 HIGH findings**. Reading them by hand,
> two were false positives that the regex heuristic just couldn't see through:
> one was a value passed through a *local* `sanitize()` helper on a different
> line from the sink, the other was a single line matching two overlapping
> sink patterns and getting reported twice. This writeup is the anatomy of
> the two follow-up fixes — **v3.8 cross-method sanitizer awareness with
> multi-line statement join**, and **v3.9 sink-family dedup** — that walked
> the HIGH count down 3 → 2 → 1 without weakening what the bot flags on real
> problems. The remaining 1 HIGH is a *real* reach worth reviewing.

Writeup 08 was about the *categories* of noise the bot learned to quiet
(sink-context, dedup across pages, JSON responses). This one is narrower and
more useful as a case study: **one target, three specific false-positive
patterns, three code changes, three tests that reproduce the exact real-file
shape, and the honest final number.** It's what the "engineered" in
"engineered heuristic" actually looks like — a drop, a reading, a fix, a
regression test, a re-scan. Not a big idea, just the day's work.

## The baseline: three HIGH on hotel-platform

`dxa` after the Java support pass. Command:

```
python dxa.py hotelapp/src/main/java --json --min-confidence high
```

Result:

```
HIGH: 3
  CorrelationIdFilter.java:50  sink=response-header   taint=['cid']
      | response.setHeader(HEADER, cid);
  IdempotencyFilter.java:88    sink=servlet-writer    taint=['cached']
      | response.getWriter().write(cached.body());
  IdempotencyFilter.java:88    sink=response-write    taint=['cached']
      | response.getWriter().write(cached.body());
```

Three rows. Reading them by hand:

- **CorrelationIdFilter.java:50** — the flagged sink is
  `response.setHeader(HEADER, cid)`. `cid` shows up in the tainted-vars set,
  so `dxa` thinks a user-controlled header rides straight back out. Looking
  at the file, though:

  ```java
  String inbound = request.getHeader(HEADER);
  String cid = (inbound != null && !inbound.isBlank() && inbound.length() <= 64)
          ? sanitize(inbound)
          : shortUuid();
  // ...
  response.setHeader(HEADER, cid);
  ```

  `cid` **is** built from `inbound`, but always through a local `sanitize()`
  helper (or replaced entirely by `shortUuid()`). The value that reaches
  `setHeader` is sanitised. The bot didn't see `sanitize()` for two reasons:
  its escape gate only matches OWASP-standard names, and the whole
  expression spans three physical lines so even if the gate knew `sanitize`,
  it wouldn't have been on the same line as the assignment.

- **IdempotencyFilter.java:88** — the same line reported *twice*, once as
  `servlet-writer` and once as `response-write`. Two different sink patterns
  in the catalogue happen to overlap: `servlet-writer` matches any
  `getWriter().*` call, `response-write` matches specifically
  `response.getWriter().*`. Every hit on the specific one is also a hit on
  the general one — same line, two rows.

Two of the three rows are noise, one is a real reach. That's the ratio the
next two versions fix.

## Fix 1: cross-method sanitizer awareness (v3.8)

The v3.7 escape gate already downgraded HIGH → MEDIUM when an
OWASP-standard encoder call was on the same line as the sink
(`StringEscapeUtils.escapeHtml4`, `Encode.forHtml`, `HtmlUtils.htmlEscape`,
...). The CorrelationIdFilter case needed two upgrades:

- **A broader hint pattern.** Local helpers named `sanitize()`, `clean()`,
  `validateInput()`, `filterXxx()`, `stripYyy()`, `encodeZzz()` all follow the
  same shape and same intent. A single regex covers them alongside the
  library encoders:

  ```
  \b\w*(?:sanitiz|clean|validat|escape|escap|htmlspecial|strip|filter|
           encode|purif|Markup|SafeString|bleach|nh3|
           StringEscapeUtils|HtmlUtils|Encode\.forHtml|markupsafe\.escape|
           html\.escape|HtmlEncoder|WebUtility\.HtmlEncode|
           HttpUtility\.HtmlEncode)\w*\s*\(
  ```

  Anywhere this call appears **in the RHS of an assignment**, `compute_taint`
  skips propagation for that line. The tainted variable is treated as
  cleaned.

- **Multi-line statement join, for taint only.** Java ternaries and
  long argument lists frequently span 3-8 lines. To make the sanitize
  hint reachable, `_joined_for_taint(lines, terminator=';')` walks the
  file once and, for every line that doesn't end with `;`, concatenates
  the next lines up to the terminator (capped at 8 to avoid runaway).
  The result has the same length as the original — indexing preserved,
  so `scan_file`'s per-line sink loop still reports at the correct line
  number. Only `compute_taint` sees the joined view. Only Java and C#
  opt in (JS / PHP / Python assignments are single-line by convention).

Together these turn the CorrelationIdFilter block from three separate lines
into one joined statement `String cid = (inbound != null ...) ? sanitize(inbound) : shortUuid();`,
the sanitize hint matches, taint propagation from `inbound` to `cid` is
skipped, and the `setHeader(HEADER, cid)` line no longer finds `cid` in
`tainted`. HIGH drops from 3 to 2.

The catch is the mirror of the win: this is an **aggressive** heuristic. Any
sanitize-family call in the RHS breaks the chain, even if the call happens
to wrap something *other* than the tainted expression. In real code this is
almost always right (people write sanitize wrappers to sanitise the value
they're about to hand off), but it is not sound. A test locks the behaviour
on both directions:

```python
def test_taint_broken_by_local_sanitize_call_java():
    lines = ['String inbound = request.getParameter("q");',
             'String cid = sanitize(inbound);',
             'response.getWriter().write(cid);']
    tainted = dxa.compute_taint(lines, dxa.JAVA_SOURCES, False, dxa.JAVA_ASSIGN)
    assert "inbound" in tainted
    assert "cid" not in tainted

def test_taint_still_flows_without_sanitize_java():
    lines = ['String q = request.getParameter("q");',
             'String out = "hello " + q;']
    tainted = dxa.compute_taint(lines, dxa.JAVA_SOURCES, False, dxa.JAVA_ASSIGN)
    assert "q" in tainted and "out" in tainted
```

## Fix 2: sink-family dedup (v3.9)

The IdempotencyFilter line still fired twice after v3.8. Same code, same
tainted variable, both `servlet-writer` and `response-write` legitimately
match. The right shape here is an explicit **sink suppression table**:

```python
SINK_SUPPRESSIONS = [
    ("src-href",       "navigation"),       # (was hard-coded; now consistent)
    ("response-write", "servlet-writer"),   # v3.9
]
```

`(specific, general)` pairs. `scan_file` computes a per-line
`matched_here` set of every sink pattern that fired, then builds
`suppressed = {specific | (specific, general) in table and both matched}` and
skips them in the emit loop. The pre-existing hardcoded suppression for
`(src-href, navigation)` folded into the same table — one central place,
adding a future overlap is a table row.

Result: the two IdempotencyFilter rows collapse to one. HIGH drops from 2
to 1. Total findings on the file drop from 9 to 7 as the same rule
suppresses duplicate MEDIUMs on other lines too.

## The one remaining HIGH is a real thing

The final row after v3.9:

```
IdempotencyFilter.java:88  sink=servlet-writer  taint=['cached']
    | response.getWriter().write(cached.body());
```

`cached` is a `CachedResponse` object returned by the idempotency service —
its `body()` is a `String` holding a prior successful 2xx response body. On
an idempotency cache hit, the filter writes that string straight to the
current response. The value comes from *the app's own successful past
response*, not from an attacker input in this request, and the response is
served with `Content-Type: application/json` + `X-Content-Type-Options:
nosniff` — so a browser will parse it as JSON, not HTML. In dynamic-mode
terms this would land at `[JSON-ONLY]` under the v3.7 Content-Type gate.

But **statically the reach is real and worth surfacing**: an app that
stores + replays response bodies has to think about (a) whether the
replayed body's original content-type is preserved, and (b) whether the
stored strings ever end up rendered as HTML somewhere else. That is a
review conversation, not a false positive; the bot's job is to bring the
line to a human's attention with the reason. One row, one review — the
right output shape.

## What this journey does not fix

Both fixes are heuristic and stay heuristic. Honest boundaries:

- **No AST, no cross-file taint.** If `sanitize()` is in another file, the
  regex still sees only its name at the call site (which is fine because
  the name is the whole hint). If a wrapper is called `process()` or `run()`
  — nothing sanitize-shaped in its name — the hint doesn't fire and taint
  still propagates. In practice these are the FPs that survive.
- **The 200-char proximity gate on same-line escapes is still there** as
  the first line of defence for the common case; multi-line join is a
  second-line addition for Java/C# ternaries.
- **The sink suppression table is opt-in per pair.** Overlaps we didn't
  add stay double-reporting. If a future language adds another pair
  (e.g. `jsp-el-unescape` vs `<c:out>` variants), it goes in the table.

Precision moves in small, tested increments. The three-line drop on
hotel-platform is what precision looks like when it's real: not a new
detection, three fewer distractions and one row that still deserves your
time.

## Takeaway

The story here isn't that the bot got smarter in some general way. It's
that **each of the three HIGH rows had a specific reason to be there or
not**, and reading each of them turned into a targeted fix with a test
that reproduces the exact real-file shape. This is what precision-first
engineering looks like day to day: a real target reports something, you
read it, you decide whether it's noise or signal, and if it's noise you
add the smallest heuristic that cuts *that* class of noise without
weakening what the tool catches on real problems. Then you write the
test so tomorrow's change doesn't undo it. Repeat until the number the
bot returns matches what a competent human would say by hand.

Same source→sink discipline as the rest of the repo, one target's
worth of engineering shown end to end.

---

*Hands-on, on an authorized local target only: my own hotel-platform
Spring Boot 3 backend (`hotelapp/src/main/java`, 211 files), scanned with
`dxa` at the v3.7 → v3.8 → v3.9 versions. Test additions:
`test_taint_broken_by_local_sanitize_call_java`,
`test_taint_broken_by_local_clean_call_java`,
`test_taint_broken_by_owasp_encoder_java`,
`test_taint_still_flows_without_sanitize_java`,
`test_ternary_with_sanitize_in_one_branch_breaks_taint`,
`test_sanitize_hint_python_variant`,
`test_response_write_suppressed_when_servlet_writer_matches`,
`test_sink_suppression_table_intact`.
79 pytest cases total, CI-gated, zero third-party dependencies.*
