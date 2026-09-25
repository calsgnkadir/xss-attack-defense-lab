# One shape was never enough: payload variants and WAF bypass

> **TL;DR** — Up through v3.9 the bot sent exactly one canary shape:
> `cid"<dXsS>`. It's fine for body-context reflections, but a value that
> lands inside `<title>` / `<script>` / an HTML attribute only scores
> `breakout-req` with that shape — the marker survives raw but the
> browser doesn't execute the class without a follow-on breakout payload
> the operator has to compose by hand. v3.10 fixes this two ways at once.
> **Payload variants** send five context-tuned shapes (body, title-break,
> attr-break, script-break, url-scheme) — each with its own cid so
> verdicts stay independent — and any variant whose marker survived raw
> in an HTML response is upgraded from `breakout-req` to `executable`
> because the marker's presence *proves* the escape worked. **WAF-bypass
> mutations** add four alternate shapes per variant (case-swap,
> split-tag-comment, whitespace, URL-encode), so a regex WAF anchored on
> `<dXsS>` literally still gets bypassed by at least one shape. Same
> flags work in reflected + stored + header-probe modes; total shapes
> per round is `variants × (1 + 4 if waf-bypass else 1)`.

This is the pass that turns the bot from a *"one payload, hope it fires"*
tool into a *"try what the target actually accepts"* tool. Same source→sink
discipline, more of the surface actually reached.

## What one shape couldn't tell you

Writeup 09 walked one target's HIGH count from 3 → 1 by making the bot
quieter. Payload variants are the mirror: making the bot **more specific**
so real HIGHs surface where they belong. The Bludit tag-XSS from
[writeup 06](06-building-an-xss-bot.md) is the clearest example. Bludit
stores the tag value verbatim and renders it on `/tag/<slug>`:

```html
<title>tag: <STORED_VALUE> | Site</title>
```

Send the historical body-shape canary `cid"<dXsS>`, and the response has:

```html
<title>tag: dxaXX"<dXsS> | Site</title>
```

`<dXsS>` survives raw. `verdict()` says **unencoded**. `find_context()`
says **title**. The v3.5 severity ladder says **breakout-req** — the
marker is real but the *browser* won't run `<img onerror>` there without
a `</title>` first. That's an accurate statement but a frustrating one:
the exploit is one payload change away.

If you send `cid</title><dXsS>` instead, the response becomes:

```html
<title>tag: dxaXX</title><dXsS> | Site</title>
```

Now the browser closes the title at the injected `</title>`, and
`<dXsS>` renders in body context. If the marker were `<img onerror=...>`
it *would* execute — the class is now **executable**. Same target, same
sink, different payload shape, different verdict.

v3.10 stops making the operator do that payload change by hand.

## The five payload variants

`PAYLOAD_VARIANTS` is a small dict at the top of `dxadyn.py`. Each entry
is `(suffix_appended_to_cid, marker_that_must_survive_raw)`:

```
body            cid"<dXsS>               (default; body/free context)
title-breakout  cid</title><dXsS>        (closes <title> then marker)
attr-breakout   cid"><dXsS>              (closes attr quote + attr tag)
script-breakout cid';<dXsS>//            (closes JS string, // eats tail)
url-scheme      cidjavascript:/*<dXsS>*/ (href/src -> javascript: URL)
```

The **cid** is a random 8-hex-char prefix; the **suffix** is what actually
does the context work; the **marker** is what `verdict()` looks for
immediately after the cid in the response body. Because each variant
carries its own cid *and* its own marker, they never confuse each other's
verdicts — a single stored round can run all five in parallel and grade
them independently.

CLI:

```bash
--variants title-breakout,attr-breakout          # pick specific ones
--variants all                                   # every registered variant
--variants body                                  # default = historical
```

`make_canaries_for(variants)` yields `(vname, cid, canary, marker)` tuples
one after the other. Every probe path — stored, stored-auto, reflected
crawl, header probe — iterates the yield, so *anywhere* a canary was
being made, N canaries are made now.

## Variant-aware severity: the upgrade rule

The old severity ladder classified by *where the cid landed*
(`find_context`). That's still what happens: cid position drives context.
But for a `-breakout` variant whose marker survived raw, the marker has
*already escaped* that surrounding context — the whole point of the
breakout was to move the marker into body. So the severity should reflect
executability of the *marker*, not of the cid.

The v3.7 CT gate grew a fourth argument:

```python
def _apply_ct_gate(reflection, context, content_type, variant="body"):
    if _is_html_response(content_type):
        if reflection == "unencoded" and variant.endswith("-breakout"):
            return context, "executable"
        return context, _severity(reflection, context)
    ...
```

Concretely:

- `body` variant + `title` context on HTML → `breakout-req` (no
  breakout was attempted; marker is stuck).
- `title-breakout` variant + `title` context on HTML → **`executable`**
  (the marker cleared `</title>`; the class runs).
- Any variant + `json-body` (Content-Type: application/json) → stays
  `json-only` — the browser doesn't parse JSON as HTML no matter what
  the variant did.

Locked in tests:

```python
def test_ct_gate_breakout_variant_upgrades_to_executable():
    ctx, sev = dxadyn._apply_ct_gate("unencoded", "title", "text/html",
                                     variant="title-breakout")
    assert sev == "executable"

def test_ct_gate_breakout_variant_does_not_bypass_json_downgrade():
    ctx, sev = dxadyn._apply_ct_gate("unencoded", "body", "application/json",
                                     variant="title-breakout")
    assert sev == "json-only"
```

## WAF-bypass mutations

Some targets sit behind a regex WAF that anchors on the literal marker
(`<dXsS>` or common event handlers). If the base variant is blocked, no
variant reaches the sink and the tool goes silent — an ambiguous result.
`--waf-bypass` fans each variant into four alternate shapes that keep
the same `cid` prefix but obfuscate the marker so different WAF rules
apply:

```
case        <dXsS> -> <DxSs>          (case-swap)
split-cmt   <dXsS> -> <d<!---->XsS>   (HTML comment splits the tag;
                                      the parser re-forms it downstream)
whitespace  <dXsS> -> <dXsS  >        (extra trailing space in tag)
url-encode  <dXsS> -> %3CdXsS%3E      (URL-encoded angle brackets)
```

Each mutation gets its own fresh cid (re-embedded via a single
`.replace(cid, mut_cid, 1)`), so the four mutations of a single variant
have four independent verdicts. Output tags the mutation on the variant
name: `body/case`, `title-breakout/split-cmt`, etc.

Fan-out math: `len(variants) × (1 + 4 if waf-bypass else 1)`. So
`--variants all --waf-bypass` = 5 × 5 = 25 submits per stored round.
Not a default; use it when you actually suspect a WAF, not on every
target.

Two representative tests:

```python
def test_make_canaries_for_waf_bypass_multiplies_by_five():
    out = list(dxadyn.make_canaries_for(["body"], waf_bypass=True))
    assert len(out) == 5
    assert out[0][0] == "body"                    # base first
    assert {t[0] for t in out[1:]} == {"body/case", "body/split-cmt",
                                        "body/whitespace", "body/url-encode"}

def test_waf_mutations_return_named_triples():
    triples = dxadyn._waf_mutations('dxaAAAA"<dXsS>', '<dXsS>')
    names = [t[0] for t in triples]
    assert names == ["case", "split-cmt", "whitespace", "url-encode"]
```

## Everywhere, not somewhere

The same two flags — `--variants` and `--waf-bypass` — work in every
probe path:

- **Stored mode** (`--stored --check` or `--stored --auto-check`):
  each variant × mutation is a separate submit, own cid, own verdict.
  Auto-check crawls candidate pages once and grades each candidate
  against every submitted cid — one HTTP fetch per candidate, N
  verdicts, cheap.
- **Reflected mode** (`crawl(url, depth, variants=, waf_bypass=)`):
  `probe_form` and `probe_link` iterate variants × field / variants ×
  param. The `crawl()` dedup key now includes the variant name, so a
  body + attr-breakout reflection on the same param stays as two rows
  (correctly — they're different exploits).
- **Header probe** (`--probe-headers` + `--variants`): each header × each
  variant × each mutation is a separate probe. Bludit-shape stored
  header XSS (`True-Client-IP` → Last Login IP) can now be tried with
  attr-breakout automatically if the base doesn't fire.

## Honest boundaries this pass doesn't cross

- **`--waf-bypass` is opt-in.** The four mutations are not defaults
  because a 5× cost multiplier on every stored round is aggressive
  bandwidth on friendly targets. It exists for the case where the base
  clearly isn't reaching (all reflections silent, but you know user
  data lands somewhere).
- **DOM XSS is still out of scope.** All variants inspect the server
  response body — a `location.hash` → `innerHTML` sink executes only in
  the browser's DOM and this bot doesn't drive a browser. Playwright is
  the honest fix; not shipped.
- **Blind XSS is still out of scope.** No callback server, no out-of-band
  channel — the variant that fires on an admin panel viewed by another
  user hours later stays invisible.
- **Variant coverage is HTML-only for now.** JSON API responses always
  stay `json-only` regardless of variant (correctly — no HTML parsing).
  A future round could add JSON-specific *client-side* variants (a value
  that a React frontend hands to `dangerouslySetInnerHTML`), but that
  needs browser rendering to verify — same Playwright thread.

Total pytest cases after this pass: **101**, all green, CI-gated,
still zero third-party dependencies.

## Takeaway

A single payload was never going to be enough. The historical `body`
canary was a strong signal *when it fired*, but silence didn't distinguish
"no reflection" from "reflection I chose the wrong shape for" from
"reflection blocked by a filter I didn't try to defeat." v3.10 answers
all three:

- If the base shape didn't fire, one of five variants might.
- If a variant fires and the marker escaped the surrounding context,
  the class is executable — no operator payload composition step
  between the tool and a real exploit.
- If everything is silent and the target has a WAF, the four mutations
  per variant probe the shape the filter didn't anchor on.

The bot's HIGH-count on Bludit-shape title reflections goes from
`breakout-req` (which most operators would triage as "worth eyes-on
but maybe not exploit") to `executable` (which most operators would
triage as "confirm this in the browser now"). Same reach, cleaner
verdict — and 10 new tests locking the behaviour so tomorrow's change
doesn't undo it.

Same source→sink methodology as the rest of the repo — with the honest
edges of what a regex-plus-canary approach can and cannot see drawn
in ink.

---

*Hands-on, on authorized local targets and fixtures only. Reference:
[writeup 06 (Bludit tag-XSS)](06-building-an-xss-bot.md) for the
title-context scenario this variant addresses; [writeup 09 (hotel-platform
3 → 1)](09-three-high-to-one-a-precision-journey.md) for the precision
work that preceded this shape-diversity pass; and
[writeup 08 (what doesn't shout matters)](08-what-does-not-shout-matters.md)
for the CT gate the v3.10 upgrade rides on. Tool sources:
[`tools/dom-xss-analyzer/dxa.py`](../tools/dom-xss-analyzer/dxa.py) +
[`dxadyn.py`](../tools/dom-xss-analyzer/dxadyn.py) +
[`dxa2dyn.py`](../tools/dom-xss-analyzer/dxa2dyn.py) — 101 pytest cases,
CI-gated, zero third-party dependencies.*
