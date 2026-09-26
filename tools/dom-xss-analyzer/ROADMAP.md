# dxa/dxadyn — Professional Scanner Roadmap

**Started:** 2026-09-26
**Target:** OSS XSS scanner competitive with DalFox / XSStrike at their level;
**not** a Burp Scanner replacement (that's a $30k/yr commercial product with
30+ engineers behind it).

**Honest ceiling:** Even at 100% of this roadmap, the tool won't have Burp's
recon breadth, active/passive scan surface for non-XSS classes, session
handling maturity, or extension marketplace. What it *will* have: XSS-class
depth (static + dynamic + DOM + blind) with a precision discipline most OSS
scanners skip.

---

## Guiding principles (do not violate)

1. **Precision over recall.** A finding the tool reports must be defensible.
   False-positive rate is the metric that separates hobby tools from ones
   people actually use. Every recall boost lands with a precision test.
2. **Zero-dep stays default; heavy deps become opt-in.** Playwright, tree-sitter,
   etc. install with `pip install dxa[browser]` etc. Core install remains stdlib.
3. **Every phase ships a writeup.** Portfolio value is the trail, not the summit.
4. **Tests before merge.** Every phase adds pytest cases; CI stays green.
5. **Turkish/local authorized targets only** — Juice Shop, Bludit lab, PortSwigger
   Academy, own projects, bug-bounty programs with explicit scope.

---

## Phase overview

| Phase | Focus | Time | Ships | Depends on |
|---|---|---|---|---|
| **0** | Foundation cleanup | 2-3 gün | Quick-win fixes, honesty logging | — |
| **1** | Recall boost (no browser) | 2 hafta | Concurrency, payload library, workflow chaining, macro auth | 0 |
| **2** | Browser layer (Playwright, opsiyonel dep) | 3 hafta | DOM XSS, JS exec proof, SPA discovery, CSRF rotation | 1 |
| **3** | Blind XSS (out-of-band callback) | 1 hafta | Callback server + payload correlation | 1 |
| **4** | Sound static (tree-sitter AST) | 4 hafta | AST parser, cross-file taint, real sanitize semantics | 0 |
| **5** | Recon | 1-2 hafta | Subdomain enum, endpoint discovery, wordlist | 0 |
| **6** | Product polish | 1-2 hafta | SARIF, plugin API, config file, GH Action | 1-5 |

**Total: ~12-14 hafta full-time** — or ~6 ay part-time (2 gün/hafta).

---

## Phase 0 — Foundation cleanup (2-3 gün)

**Goal:** Fix easy gaps that stayed open through v3.10 so later phases don't
build on a wobbly base.

### 0.1 Sink suppression table widening (30 dk)
- Add rules: `(jquery-html, innerHTML)`, `(react-dangerous, innerHTML)`,
  `(twig-raw, echo)`, `(mustache-triple, template)`
- Test: every rule with `test_sink_dedup_new_family_<name>` fixture
- **DoD:** static findings on hotel-platform stay 1 HIGH; no regression on
  Bludit demo.

### 0.2 False-negative discipline (2-3 saat)
- New `--verbose` flag: when a submit is rejected (400/403/rate-limit),
  the finding row prints `skipped: <reason>` instead of silent
- New `--waf-log`: if a canary is blocked (POST returns 400 or 403 with
  "blocked" in body), log the payload and the reason
- Test: mock server returning 403 → tool prints "skipped: waf-block"
- **DoD:** "no reflections found" turns into "N reflections found, K
  payloads blocked" — silence stops being ambiguous.

### 0.3 Sanitize heuristic tightening (1-2 saat)
- Downgrade sanitize-hint from a strict signal to a weighted score
- If `sanitize()` is followed inline by `+ untrustedString` on same taint path,
  DON'T squelch (the sanitized value was discarded)
- Test fixture: `sanitizeButKeepsHtml(x) + userInput` → HIGH stays HIGH
- **DoD:** the pathological case in [writeup 09](../../writeups/09-three-high-to-one-a-precision-journey.md)
  stays green; false-negative on the new fixture drops.

### 0.4 Cross-file basic taint (4-5 saat)
- Given a project root, scan every file once, build a `{function → returns_tainted}` map
- Second pass: if a sink argument is `foo(x)` and `foo` is in the map as tainted, mark tainted
- No AST yet; regex-based; scope limited to same-package
- Test: two-file fixture `util.py` (returns raw request) + `app.py` (calls util.func in innerHTML)
- **DoD:** Bludit and Juice Shop each pick up one more finding they missed before.

**Phase 0 writeup:** *"The gaps between the writeups: hardening the tool
between versions"* — sink dedup + verbose skip logging + cross-file taint.

---

## Phase 1 — Recall boost, no browser (2 hafta)

**Goal:** Grow reachable surface without adding a browser dependency.
Concurrency, payload library, workflow chaining, macro auth.

### 1.1 Concurrency (2-3 gün)
- `ThreadPoolExecutor(max_workers=10)` — configurable via `--parallel N`
- Rate limiting: `--rate 5/s` token bucket
- Jitter: `--jitter 100-500ms` between requests
- Careful with cookie jar — one lock per session
- Test: mock server with 25 shape probe, wall clock < 3s with `--parallel 10`
- **DoD:** hotel-platform 25-shape stored round drops from ~15s to <3s.

### 1.2 Payload library expansion 25 → 200+ (5-7 gün)
Add mutation families beyond the current 4:
- **Unicode variants**: `<img src=x onerror=alert(1)>` → `<\u{0069}mg ...>`;
  `<script>` → `<script>` etc.
- **HTML entity escaping**: `<img` → `&lt;img`, `&amp;lt;img` (double-encoded)
- **Hex encoding**: `%3Cimg` → `%253Cimg` (double-URL-encoded); the "gadget stack"
- **CSS expression**: `expression()` shape for IE (historical, but some legacy
  admin panels still care)
- **SVG-based**: `<svg><script>...</script></svg>`, `<svg><use href="data:...">`
- **Data URI**: `data:text/html;base64,PHNjcmlwdD5hbGVydDEpPC9zY3JpcHQ+`
- **ES6 template literal breakout**: `${alert(1)}` variants for `` ` ``-quoted contexts
- **Nested comment breakout**: `-->` , `--!>`
- **JS event handler diversification**: currently only `onerror`; add `onload`,
  `onfocus autofocus`, `ontoggle`, `onpointerenter`, `onbeforetoggle`
- Grow `PAYLOAD_VARIANTS` from 5 shapes to ~50 shapes; grow `_WAF_MUTATIONS`
  from 4 to ~20 named mutations
- Total canary shapes with `--variants all --waf-bypass`: ~50 × 20 = 1000+
  (down-samplable via `--variants top-10`, `--waf-bypass basic`)
- Test: every mutation family has 2+ tests; total pytest 101 → ~180
- **DoD:** Bludit test picks up EXECUTABLE via at least 3 different variants;
  Juice Shop reflections rise from 4 to 6+.

### 1.3 Workflow chaining / state-machine (3-4 gün)
- New CLI: `--flow steps.yaml`
- YAML syntax:
  ```yaml
  - name: register
    method: POST
    url: /api/auth/register
    body: {email: "bob-{RND}@x.com", password: "P@ss1234"}
    save: {token: "$.token"}
  - name: submit-comment
    method: POST
    url: /api/comments
    headers: {Authorization: "Bearer {token}"}
    body: {text: "{CANARY}"}
  - name: check
    method: GET
    url: /comments
    verdict: yes
  ```
- Save/restore vars between steps (JSON path)
- Test: mock 3-step server, canary lands after step 2, verdict fires on step 3
- **DoD:** wallet-api register → deposit → transfer with canary works from
  single YAML.

### 1.4 CSRF token rotation (1-2 gün)
- New `--csrf-refresh URL` — before each submit, GET this URL, extract token,
  set header
- `--csrf-header X-CSRF-Token` (some frameworks want header not form field)
- Test: mock server with per-request rotating token, tool succeeds
- **DoD:** modern Rails/Laravel demo target works without hand-plumbing tokens.

### 1.5 Macro-based auth (2-3 gün)
- New CLI: `--auth-flow flow.yaml` — mini-workflow for login (may include
  captcha placeholder, OTP field)
- Detect JWT vs cookie session automatically; use rest of run as authenticated
- Test: hotel-platform, wallet-api, Bludit all logged in via single YAML file
  per target
- **DoD:** three own-projects login via one command each; no more `-b JAR` hackery.

**Phase 1 writeup:** *"Growing recall without growing lies: concurrency + a
serious payload library + workflow chains"*.

---

## Phase 2 — Browser layer, Playwright as opt-in dep (3 hafta)

**Goal:** Close the DOM XSS + JS execution proof gap. This is the single
biggest missing class.

### 2.1 Playwright installation & harness (2-3 gün)
- Add `pip install dxa[browser]` extra → installs playwright
- Skip gracefully if not installed (feature-flag on import)
- Headless Chromium session with page.goto + console listener
- Test: verify install path + graceful skip + basic navigation
- **DoD:** `dxadyn --dom` flag exists and either works or exits with clear message.

### 2.2 DOM sink detection (5-7 gün)
- Playwright hook: patch `Element.prototype.innerHTML` setter, `Range.createContextualFragment`,
  `Document.write`, `Location.href` (assignment), `eval`, `Function()`, jQuery `.html()`
- On call, capture stack trace + argument + timestamp → correlate with canary cid
- Test: 5 dedicated DOM XSS fixtures (location.hash, postMessage, URLSearchParams,
  document.referrer, hash router)
- **DoD:** each fixture reproducibly detected; Juice Shop DOM XSS challenge
  autonomously catches.

### 2.3 JS execution proof (2-3 gün)
- Playwright dialog handler: `page.on("dialog", d => alert_fired=True; d.accept())`
- Payload runner: after crawling to target, evaluate the raw injected page,
  wait for load, check `alert_fired` and captured console errors
- Upgrade rule: `reflection=unencoded + alert_fired=True` → severity `proven-executable`
  (new tier above `executable`)
- Test: fixture that renders payload → alert fires → tool reports `proven-executable`
- **DoD:** Bludit tag XSS with `<img src=x onerror=alert(1)>` variant scored
  `proven-executable`, not just `executable`.

### 2.4 SPA hash routing discovery (3-4 gün)
- Playwright: after page.goto, capture all `history.pushState` / router transitions
- Extract all string literals in loaded JS that look like paths (`/foo/:id`, `#/bar`)
- Add to crawl queue
- Test: React Router app fixture, tool discovers 5+ routes beyond direct anchor links
- **DoD:** hotel-platform frontend crawl at depth=2 finds routes it missed before.

### 2.5 CSRF-in-header auto-detection (1-2 gün)
- Playwright captures all XHR/fetch requests during navigation → extract common
  headers, especially `X-CSRF-Token`, `X-Requested-With`, `Authorization`
- Auto-replay them in future submits
- Test: SPA fixture with per-request CSRF header, tool succeeds without config
- **DoD:** modern Angular/React app with anti-CSRF header works out of the box.

**Phase 2 writeup:** *"Adding a browser without losing the discipline: DOM XSS,
JS execution proof, and staying honest about what a headless browser proves"*.

---

## Phase 3 — Blind XSS (out-of-band callback) (1 hafta)

**Goal:** Catch stored payloads that fire only in someone else's session
(admin panels, moderator queues, back-office dashboards).

### 3.1 Callback server (2-3 gün)
- Minimal FastAPI (or stdlib http.server) daemon: `dxa-callback --port 9999`
- Endpoint `/c/{cid}` — logs GET requests with cid, timestamp, user-agent, IP
- Endpoint `/callback` — CORS+creds; used as image/script src target
- Persist hits to `~/.dxa/callbacks.db` (SQLite)
- Test: unit test posts to /c/deadbeef, tool queries and finds it
- **DoD:** `dxa-callback` server runs, receives, logs.

### 3.2 Callback payload integration (2 gün)
- New payload variant family `blind`: replaces `<dXsS>` marker with an image
  tag pointing at the callback: `<img src=http://callback/c/{cid}>`, plus
  `<script src=http://callback/c/{cid}></script>`
- Requires operator to run their own callback server (public IP or ngrok)
- CLI: `--blind-callback http://your.tld:9999` — auto-substitutes into payloads
- Test: fake-callback fixture, tool submits, callback receives cid, dxadyn
  correlates
- **DoD:** submit → callback hit → finding row scored `proven-blind`.

### 3.3 Correlation and reporting (1 gün)
- Extend `_finding` schema: `blind_callback_hit` boolean, `hit_at`, `hit_from`
- HTML report gains a "blind hits" section
- Test: unit + one integration
- **DoD:** callback hits show in HTML report and JSON output.

**Phase 3 writeup:** *"Payloads that fire hours later: blind XSS on callbacks"*.

---

## Phase 4 — Sound static analysis (tree-sitter AST) (4 hafta)

**Goal:** Replace regex-based static analysis with real AST-level data flow.
This is the heaviest phase and the one that separates OSS scanners from
enterprise ones.

### 4.1 Tree-sitter setup (3-4 gün)
- Add `pip install dxa[ast]` extra → installs tree-sitter + language grammars
  (js, ts, py, java, c-sharp, php)
- Parse every source file into AST once; walk with visitor pattern
- Cache: MD5 of file → serialized AST, so re-runs are fast
- Test: parse each fixture, count expected node types
- **DoD:** each language's AST parseable; caching works.

### 4.2 Data-flow graph builder (7-10 gün)
- Nodes: variables, function parameters, function returns, expressions
- Edges: assignment, argument-pass, return, member access
- Per-function control-flow: if/else/loop merging
- Test: 10 canonical fixtures per language showing flow: `x = req.body → y = f(x) → sink(y)`
- **DoD:** taint flows across function calls in every language.

### 4.3 Cross-file / cross-module resolution (5-7 gün)
- JS: resolve `import { foo } from './util'` → walk into util
- TS: same + type resolution
- Python: resolve `from utils import foo`
- Java: package + classpath (simplified)
- C#: using statements
- PHP: require/include + namespace
- Test: 3-file fixture per language showing cross-file taint
- **DoD:** hotel-platform (Java Spring), health-blockchain (Py FastAPI),
  wallet-api (C# .NET) each surface 1+ finding they missed at Phase 0.

### 4.4 Real sanitizer semantics (3-4 gün)
- Deprecate name-based `_SANITIZE_HINT`; replace with:
  - Per-language whitelist of known-safe functions (`escapeHtml`, `htmlSpecialChars`,
    `Sanitize.HTML`, `HtmlEncoder.Encode`, `bleach.clean`, `DOMPurify.sanitize`)
  - AST match: exactly the pattern `sink(known_safe(x))` clears taint
  - Anything else (custom `sanitize(x)` you can't verify): DOWNGRADES confidence,
    doesn't kill the finding
- Test: `sanitizeButKeepsHtml(x)` and other pathological cases stay flagged
- **DoD:** Phase 0.3's fixture still passes; new whitelist-based path shown in output.

### 4.5 Phase 4 lock-in tests (2-3 gün)
- Add 30+ AST-level tests
- Regression suite: every prior fixture still catches what it caught before
- **DoD:** 101 → ~250+ pytest cases; hotel-platform HIGH count re-baselined
  with AST (may increase or decrease — write it up).

**Phase 4 writeup:** *"Retiring the regex: tree-sitter AST + data-flow +
cross-file taint"*.

---

## Phase 5 — Recon (1-2 hafta)

**Goal:** Discover surface before scanning it. Bug-bounty scanners without
this are just directed testers.

### 5.1 Subdomain enumeration (2-3 gün)
- Query `crt.sh` for CT log subdomains
- DNS bruteforce (small wordlist bundled: top-1k subdomains)
- CLI: `dxa recon subs example.com`
- Output: `subs.txt` (deduplicated, live-checked)
- **DoD:** running against a target with known subs discovers them.

### 5.2 Endpoint discovery from JS (3-4 gün)
- Fetch every JS file linked from a page
- Regex extract: URL patterns, API path strings, `fetch("/...")` calls
- Feed into crawl queue
- Test: React app fixture, tool finds 20+ endpoints from bundled JS
- **DoD:** hotel-platform frontend surfaces 30+ endpoint candidates from bundle.

### 5.3 Directory bruteforce (2 gün)
- SecLists common wordlist bundled (or downloaded on demand)
- CLI: `dxa recon dirs https://target.com` — HEAD probe each candidate
- Output: found paths + status codes
- **DoD:** vulnerable target with `/admin`, `/config`, `/backup` finds them.

### 5.4 Wapiti-style form/parameter discovery (2-3 gün)
- Passive: every crawled page's forms + query params logged as candidate targets
- Active: submit dummy value, see if reflected → mark as XSS candidate
- Auto-generate `--target` list for stored-mode second pass
- **DoD:** running recon on Juice Shop discovers 50+ input candidates.

**Phase 5 writeup:** *"Finding the surface before testing it"*.

---

## Phase 6 — Product polish (1-2 hafta)

**Goal:** Make the tool usable by someone who isn't the author.

### 6.1 SARIF output (2 gün)
- New `--output sarif` — industry standard for GitHub/GitLab/Azure DevOps
- Test: schema-validate against SARIF 2.1.0
- **DoD:** GitHub Advanced Security consumes it.

### 6.2 Config file (2 gün)
- `.dxadyn.toml` — repeat CLI flags, target lists, custom sinks
- Precedence: CLI > config > defaults
- Test: fixture config + assertions
- **DoD:** repeated runs on same target become `dxadyn` (no flags).

### 6.3 Plugin API (3-4 gün)
- Entry point: `dxa.plugins` (setuptools)
- Plugin can register: new sinks, new sources, new payload variants,
  new reporters
- Example plugin: WordPress-specific sinks (out-of-repo, docs it)
- **DoD:** external plugin loads and adds sinks without touching core.

### 6.4 GitHub Action (1-2 gün)
- `.github/workflows/dxa.yml` template — checkout, install, run, publish SARIF
- Published as GitHub Marketplace action
- **DoD:** action runs on the tool's own repo and reports its own findings.

### 6.5 Rate limiting / respect (1 gün)
- Auto-detect `Retry-After` header + honor
- `--respect-robots` — skip disallowed paths
- **DoD:** run against a rate-limited target doesn't get banned.

**Phase 6 writeup:** *"From script to tool: what packaging adds"*.

---

## Milestones (portfolio-visible)

- **v4.0** (end of Phase 1): 200+ payloads, concurrent, workflow chains, macro auth
- **v5.0** (end of Phase 2): DOM XSS, JS execution proof, SPA support — **the
  version where the tool becomes actually useful on real modern targets**
- **v5.1** (end of Phase 3): blind XSS
- **v6.0** (end of Phase 4): AST-sound static — **the version most other OSS
  scanners never reach**
- **v6.1** (end of Phase 5): recon
- **v7.0** (end of Phase 6): plugin API + SARIF + GH Action — packaged

---

## Metrics we'll track

Per phase, before merge:

- **False positive rate** on the 4-target reference set (hotel + wallet +
  mahrem + Bludit): must stay ≤10%
- **True positive rate** on Juice Shop (all 8 XSS-related challenges): must
  reach ≥6/8 by v5.0, ≥7/8 by v6.0
- **Wall-clock** on the 25-shape hotel-platform stored round: must stay
  <10s throughout
- **pytest count** and green status: monotonic increase
- **Payload library size**: 25 → 200 → 500+ by v6.0

---

## What this doesn't try to be

Even at v7.0, the tool is honestly **not**:

- A Burp Scanner replacement (missing: recon breadth for classes beyond XSS,
  session handling maturity, extension marketplace, enterprise scaling)
- A CodeQL/Semgrep replacement (missing: mature query language, community
  ruleset, IDE integration)
- A SAST platform (missing: findings management, triage workflow, SLA tracking)

It **is**:

- An OSS XSS scanner that competes with DalFox / XSStrike / dominator at
  their level
- A precision-first, honesty-first, well-documented tool
- A portfolio piece for a security engineer who wants to demonstrate depth,
  not breadth

---

## Progress tracking

Each phase gets its own PR + writeup. Roadmap updates ship with each merge.
`git log --grep="Phase N"` shows what landed when.

Current state (2026-09-26): pre-Phase 0. Payload count 25. pytest 101.
Writeups 11. Zero third-party deps.
