# Live v3.10 dxadyn runs — 2026-09-26

Raw HTML reports for [writeup 11 (Four targets in one afternoon)](../../writeups/11-four-targets-one-afternoon.md).
Every file below was produced by `python dxadyn.py` (no wrappers, no
manual editing) against a running local service on 2026-09-26. Open
any file in a browser to see the full table view.

| File | Target | Mode | Fan-out | Result |
|------|--------|------|---------|--------|
| `A-hotel-platform-25shape.html` | React + Spring Boot 3 (`PUT /api/candidate/profile`) | stored, JWT | 5 variants × 5 = 25 | 25 rows, all `json-only` (CT gate held) |
| `B1-mahrem-static.html` | FastAPI + vanilla JS (source scan) | `dxa` static | 5 languages | 78 JS medium, 0 Python HIGH |
| `B2-mahrem-reflected.html` | FastAPI landing + API | reflected crawl + header probe | 25 shapes × N inputs × 4 headers, depth 2 | 0 reflections |
| `C1-wallet-reflected.html` | ASP.NET Core + Postgres (Swagger UI + `/`) | reflected | 25 shapes × depth 2 + 3 headers | 0 reflections |
| `C2-wallet-stored-25shape.html` | ASP.NET Core (`POST /api/Transactions/transfer`) | stored, JWT | 25 | 25 rows, all `json-only` |
| **`D1-bludit-body-breakout-req.html`** | **Bludit 3.16.2 tag stored XSS** | stored, cookie login, `--variants body` | 1 | 1 row, **`BREAKOUT-REQ` context=title** |
| **`D2-bludit-title-breakout-EXECUTABLE.html`** | **Same Bludit sink, same login** | stored, `--variants title-breakout` | 1 | 1 row, **`EXECUTABLE` context=title variant=title-breakout** |

**D1 vs D2 is the case-of-record for v3.10.** Same sink, same login,
same target — only the payload variant changed. `breakout-req` →
`executable`. That is the [writeup 10](../../writeups/10-one-shape-was-never-enough.md)
severity upgrade rule firing on a real HTML web CMS for the first
time on record.

All commands were single-line invocations; the writeup narrates each.
Content-Type gate is the reason A / C2 stay `json-only` under 25× pressure.
