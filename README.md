# Web Application Security — Findings, Tooling & Independent Research

Hands-on web application security work built on four concrete outputs: **confirmed vulnerabilities**
on OWASP Juice Shop, a **working XSS analysis bot** I wrote (`dxa` + `dxadyn` + `dxa2dyn`, 5-language
static + 10-flag dynamic + bridge, 5 payload variants × 4 WAF-bypass mutations, 101 tests, CI),
**independent research on real third-party open-source software** that produced externally-validated
results (a Broken-Access-Control vulnerability confirmed by Patchstack + a SQL-injection variant
re-derived via patch-diffing that was published as a CVE), and **eleven mechanism-first writeups**
(including a field report on v3.10 with the first live `executable` verdict on record)
explaining the reasoning behind each class. The scope spans the **OWASP Top 10** — XSS
(reflected/stored/DOM/mutation), SQL Injection, JWT / broken authentication, access control
(IDOR/BOLA), CSP bypass — each attack paired with its defense.

> XSS is where this work goes deepest (its origin and the tool suite), but the same
> **source → sink** discipline is applied across injection, authentication, and access-control bugs.

The goal was not to collect scoreboard points, but to **understand the mechanisms** behind each
vulnerability class using a repeatable *source → sink* methodology — and to be able to explain every
step, not just paste a payload. The tool suite makes that methodology *runnable*.

> ⚠️ **Scope & ethics.** Everything here was carried out **only** on authorized targets: OWASP Juice
> Shop running locally via Docker on `localhost:3000`, publicly-distributed open-source code verified
> in a private local environment, and one authorized bug-bounty program (assessed under its scope and
> rules, target anonymised). Nothing here targets any unauthorized, third-party, or production system.
> These techniques must only ever be used on systems you own or are explicitly authorized to test.

---

## What this repository shows

- A consistent **methodology** for finding and reasoning about client-side and server-side
  injection bugs (see [`methodology.md`](methodology.md)).
- **Findings** across multiple XSS classes plus SQL Injection and IDOR, including both *positive*
  results (working exploits) and *negative* results (where a defense held — also a valid finding).
- A clear link between **attack** and **defense**: each finding is paired with a remediation, and
  [`defense/`](defense/) collects the secure-coding fix for every class in one place.
- **Independent, real-world research** applying the same method to third-party open-source software,
  with externally-validated results and coordinated disclosure (see
  [`research/`](research/) — *Beyond the Lab*).
- **Tool suite** — the source → sink methodology encoded as a runnable XSS bot
  ([`tools/dom-xss-analyzer/`](tools/dom-xss-analyzer/)): the static analyzer `dxa` (5 languages —
  JS/TS + C#/.NET + PHP + Java + Python — with a 5-layer precision chain: sink patterns, source/taint,
  same-line escape squelch, cross-method sanitizer awareness, multi-line statement join, and sink-family
  dedup), the dynamic verifier `dxadyn` (10 CLI flags — reflected/stored/auto-check/JSON body/header
  target/cookie or bearer session import/PUT-PATCH-DELETE/probe-headers/HTML report/Content-Type gate;
  plus 5 payload variants — body / title-breakout / attr-breakout / script-breakout / url-scheme —
  each with an opt-in 4-shape WAF-bypass mutation library, and a variant-aware severity upgrade so
  a breakout marker that survived raw on HTML is scored `executable` not `breakout-req`), and the
  bridge `dxa2dyn` that feeds static HIGH hints into the dynamic probe. **101 pytest cases**,
  CI-gated, zero third-party dependencies.
- **Writeups** — eleven mechanism-first technical explainers (01-11), each tied to a confirmed finding
  or a documented tool milestone; see [`writeups/`](writeups/). Live raw HTML reports for the
  four-target v3.10 field run are in [`reports/2026-09-26-v310-live/`](reports/2026-09-26-v310-live/).

---

## Tools used (hand & bot)

| Tool | Use |
|------|-----|
| **`dxa`** (own — Python, 0 deps) | Statik: JS/TS + C#/.NET + PHP + Java + Python; source→sink + taint; 5-katman precision chain |
| **`dxadyn`** (own — Python, 0 deps) | Dinamik: reflected + stored + auto-check + JSON body + header target + cookie/bearer + PUT/PATCH/DELETE; HTML report |
| **`dxa2dyn`** (own — Python, 0 deps) | Bridge: static HIGH hints → dynamic probe with those parameter names |
| **Burp Suite** (Community) | Proxy to capture requests; **Repeater** to modify and resend raw HTTP; header injection; API testing without the frontend |
| **Chrome DevTools (F12)** | **Elements** (verify raw HTML vs escaped in the DOM), **Console** (proof of execution), **Network** (request/response inspection) |
| **OWASP Juice Shop** (Docker) | Primary authorized lab target |
| **PortSwigger Web Security Academy** | Additional structured labs (SQL injection, CSP bypass) used to cross-check technique |

---

## Methodology (short)

```
1. SOURCE   – find every attacker-controllable input (URL params, form fields, API fields, headers, file names)
2. SINK     – find where that data is rendered / written (innerHTML, bypassSecurityTrustHtml, a DB field, a file)
3. PROBE    – send an inert marker (<b>test) and check the DOM: is it a real element (raw) or escaped text?
4. ESCALATE – if raw, move up one rung: <img onerror>, <iframe src=javascript:>, <svg onload>, or a sanitizer bypass
5. VERIFY   – prove execution cleanly with console.log(document.domain) before any noisy alert()
6. AUTHZ    – check whether the action even required the privilege used (is there also an access-control bug?)
```

**Key decision — network or browser?**
A vulnerability that stays in the browser (DOM-based XSS, mutation XSS)
is analysed from **DevTools (Console / Elements)** — the Network tab is empty because the payload
never reaches the server. A vulnerability that travels to the server (reflected, stored, header,
API) is analysed from the **Network / Burp** side (payload vs. response). Picking the right layer is
half the work.

Full write-up: see [`methodology.md`](methodology.md).

---

## Findings

**Results at a glance:** eight working vulnerabilities were confirmed on OWASP Juice Shop — an
account-takeover-capable DOM XSS, four stored-XSS paths (feedback, Zip Slip, registration API, and a
header-based one), a CSP bypass, SQL Injection and an IDOR.

Legend — **Confirmed**: working exploit reproduced on the target · **Academy**: also solved on the
corresponding PortSwigger Web Security Academy lab.

| # | Vulnerability | Target | Status | Core mechanism |
|---|---------------|--------|--------|----------------|
| 1 | **DOM-based XSS** (search `?q=`) | Juice Shop | ✅ Confirmed | `q` flows into a `bypassSecurityTrustHtml` → `[innerHTML]` sink; `<img onerror>` executes on the resource-load-failure path (which the "inserted `<script>` won't run" rule doesn't cover) |
| 2 | **Stored XSS — sanitizer bypass** (feedback) | Juice Shop | ✅ Confirmed | A single-pass filter strips `<script>Foo</script>`; the deletion **re-forms** a valid `<iframe src=javascript:>` (mutation) |
| 3 | **Stored XSS — Zip Slip** (subtitle overwrite) | Juice Shop | ✅ Confirmed | Path-traversal in a `.zip` upload overwrites `owasp_promo.vtt`; the `/promotion` page renders the subtitle unsanitized |
| 4 | **Stored XSS — registration API → admin panel** | Juice Shop | ✅ Confirmed | Posting an `<iframe>` email straight to `/api/Users` skips client-side validation; the admin "Registered Users" table renders it raw |
| 5 | **CSP Bypass** (profile page) | Juice Shop / Academy | ✅ Confirmed | User input is reflected into the CSP header; injecting a permissive `script-src` re-opens inline execution (also solved on the PortSwigger CSP lab) |
| 6 | **SQL Injection — login bypass** (login form) | Juice Shop | ✅ Confirmed | `' OR 1=1--` / `administrator'--` in the email field comments out the password check → authenticated as admin (the *Login Admin* challenge) |
| 7 | **IDOR / BOLA** (`/rest/basket/{id}`) | Juice Shop | ✅ Confirmed | Server authenticates the token but does not verify object ownership; changing the basket id returns other users' baskets |
| 8 | **Stored XSS — HTTP header** (`True-Client-IP`) | Juice Shop | ✅ Confirmed | Header reaches `lastLoginIp` behind an allowlist sanitizer; a **nested-tag mutation** (same technique as #2) bypasses it and the payload fires on the Last Login IP page |

---

## Evidence

Selected captures. The full per-finding walkthrough (mechanism, steps, remediation) is in the
[Findings](#findings) table above and the [writeups](writeups/).

**OWASP Juice Shop Score Board** — solved challenges including *Login Admin*, *Password Strength*
(SQL Injection / weak credentials) and *View Basket* (IDOR):

![OWASP Juice Shop Score Board with solved Login Admin, Password Strength and View Basket challenges](screenshots/01-scoreboard-solved-challenges.jpg)

**Burp Suite Repeater** — editing and resending a request during header / API injection testing:

![Burp Suite Repeater request and response panels during injection testing](screenshots/03-burp-repeater-injection-testing.jpg)

**Burp Proxy HTTP history** — locating the target requests (`/rest/saveLoginIp`, `/api/*`) before
replaying them in Repeater:

![Burp Proxy HTTP history list showing captured Juice Shop requests](screenshots/04-burp-http-history.jpg)

More captures in [`screenshots/`](screenshots/).

---

## Beyond the lab — real-world research

The lab work above builds the fundamentals; I then applied the **same source → sink discipline to real
third-party open-source software** (WordPress.org plugins) — reading code for logic and access-control
flaws, patch-diffing recent fixes to find the variants a developer missed, and **verifying every
hypothesis in a local Dockerized environment** before believing it.

That research **independently produced externally-validated findings** — including a Broken-Access-Control
vulnerability confirmed as genuine by **Patchstack** (a CVE Numbering Authority), and a SQL-injection
variant, re-derived via patch-diffing, that was subsequently published as a CVE.

All of it on **public open-source code, verified only in local labs, disclosed responsibly** — no
unpatched details are published. Full methodology and honest results: [`research/`](research/).

---

## The bot pointed at real projects

The tool suite (`dxa` + `dxadyn` + `dxa2dyn`) was live-fired against my own projects — the honest
test of whether a hand-written triage aid is worth pointing at production-shaped code. Every scan on
this list is on code I own and run locally.

| Project | Stack | Static HIGH | Dynamic HIGH | Honest reading |
|---------|-------|-------------|--------------|----------------|
| **[hotel-platform-main](https://github.com/calsgnkadir/hotel-platform-main)** | React 18 SPA + Spring Boot 3 + MySQL + JWT | 0 (frontend) · **1** (backend Java) | 0 (JSON-only responses; `json-only` severity kicks in) | The 1 Java HIGH is `IdempotencyFilter` writing a *previous 2xx JSON body* on cache hit — real reach worth reviewing but not exploitable (CT gate). Down from 3 HIGH before the v3.8 sanitizer gate + v3.9 dedup |
| **[wallet-api](https://github.com/calsgnkadir/wallet-api)** | ASP.NET Core 8 REST | **0** | — | Pure JSON API, no HTML rendering surface, no `@Html.Raw` / views — `dxa` correctly stays quiet |
| **[health-blockchain](https://github.com/calsgnkadir/health-blockchain)** | FastAPI (Python) backend + vanilla JS frontend | **0** Python (`JSONResponse` everywhere) · 78 MEDIUM (JS) | not yet dynamic-scanned | Backend is JSON-only (correct 0 HIGH). Frontend's static/js + js/modules use `innerHTML` in 74 spots at MEDIUM — worth eyes-on manual review, no proven source |

**What this list demonstrates:** the bot's precision discipline. On well-designed API-first
backends, HIGH count is *zero*, not because the tool is blind but because there's no HTML
rendering surface for XSS to fire in. That is the number a real security tool should report on
secure code — and the hotel-platform 3→2→1 progression (via the v3.8 cross-method sanitizer
awareness and v3.9 sink-family dedup) is the receipt that the precision chain is doing work.

The full HTML reports live in `hotel-report/`, `wallet-report/`, and `health-report/` next to this
repo on disk; the tool suite is what produced them, and re-running is a one-liner per target.

---

## Key insights

- **The render decides, not the response.** Seeing raw HTML in an HTTP response does *not* mean XSS
  exists — the code that prints the value must also use a dangerous render. Juice Shop stores raw
  `<b>` in reviews, yet Angular auto-escapes it on render → safe. Conversely the search sink opts out
  of escaping (`bypassSecurityTrustHtml`) → exploitable.
- **Filtering alone is not protection.** A blacklist/single-pass sanitizer can be defeated because
  *removing* a tag can re-form a new dangerous one (findings #2 and #8). Real protection is output
  encoding + a tested DOM-based sanitizer (DOMPurify / sanitize-html) + recursive sanitization + CSP.
- **Client-side validation is not security.** The registration-API XSS (finding #4) skips the form's
  checks entirely by posting straight to the API — validation must be enforced, and output encoded, on
  the server.
- **`<script>` inserted via `innerHTML` does not execute** — escalation needs an event-handler
  attribute (`onerror`) or a `javascript:` URL scheme, a different code path.

---

## Remediation summary

| Class | Fix |
|-------|-----|
| DOM XSS (`bypassSecurityTrustHtml`) | Remove the bypass; rely on auto-escaping; use `DomSanitizer.sanitize` / DOMPurify if raw HTML is truly required |
| Sanitizer bypass / mutation XSS | Allowlist over blocklist; a tested DOM-based library; idempotent single-parse; recursive sanitization |
| CSP | Strict CSP + nonce; **never reflect user input into a security header** |
| SQL Injection | Parameterized queries / ORM bindings; never concatenate input into SQL |
| IDOR / BOLA | Enforce per-object authorization (`resource.ownerId === session.userId`) on every request |
| Zip Slip | Validate/normalize archive entry names; reject `../`; extract only within the target directory |
| Sessions | `HttpOnly` + `Secure` + `SameSite` cookies; keep tokens out of `localStorage` |

---

## Repository structure

```
xss-attack-defense-lab/
├── README.md          – this file
├── methodology.md     – the full source → sink hunting method
├── tools/
│   └── dom-xss-analyzer/
│       ├── dxa.py               – static analyzer (5 lang, taint, 5-layer precision chain)
│       ├── dxadyn.py            – dynamic verifier (reflected/stored/auto/JSON/header/PUT/PATCH…
│       │                          + 5 payload variants + 4 WAF-bypass mutations + severity upgrade)
│       ├── dxa2dyn.py           – static→dynamic bridge (dxa HIGH hints → dxadyn probe list)
│       ├── examples/            – vulnerable + safe corpus per language (JS/CS/PHP/Java/Python)
│       ├── test_dxa.py + test_dxadyn.py + test_dxa2dyn.py   – 101 pytest cases (CI)
│       └── README.md            – tool docs + capability matrix
├── research/          – Beyond the Lab: independent real-world research + externally-validated results
├── writeups/          – 11 mechanism-first explainers (01: filtering, 02: DOM XSS in a React SPA,
│                        03: SQLi, 04: JWT, 05: IDOR/BOLA, 06: building the bot, 07: teaching the
│                        bot to log in and shut up, 08: what the bot doesn't shout about matters,
│                        09: three HIGH to one — precision journey, 10: one shape was never enough —
│                        payload variants + WAF bypass, 11: four targets in one afternoon — v3.10
│                        field report with first live executable verdict)
├── reports/           – raw HTML report artifacts from live tool runs referenced in writeups
├── screenshots/       – selected evidence captures (Burp, DevTools, Juice Shop)
└── defense/           – written secure-coding defenses for every confirmed class
```

📄 **Findings:** each vulnerability — class, how it works, steps taken, impact, and remediation — is in
the [Findings](#findings) table above and expanded in the [`writeups/`](writeups/).

📸 **Evidence:** selected captures in [`screenshots/`](screenshots/) (solved challenges, Burp Repeater,
HTTP history, profile/CSP fields).

🤖 **Bot:** `tools/dom-xss-analyzer/README.md` documents every CLI flag and the precision chain.
Ran on all three of my own projects (see the *bot pointed at real projects* section above).

---

## Disclaimer & License

This repository is for **education and defensive research only**. Every technique was performed on
**authorized** targets (OWASP Juice Shop locally, publicly-distributed open-source code verified in a
private local environment, and PortSwigger Academy). Do **not** use any of it against systems you do
not own or are not explicitly authorized to test — unauthorized testing is illegal.

Released under the [MIT License](LICENSE).

---

*Educational security research · authorized/local targets only.*
