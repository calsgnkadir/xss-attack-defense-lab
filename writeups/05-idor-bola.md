# IDOR / BOLA: the server checks *who you are*, not *what's yours*

> **TL;DR** — Most injection bugs are about a value being *parsed* in the wrong
> context. Access-control bugs are different: nothing is parsed, nothing executes.
> The server correctly checks that you are **logged in** (authentication) but forgets
> to check that the thing you asked for is actually **yours** (authorization). When an
> object is fetched by an `id` in the URL and no ownership check runs, changing that
> `id` hands you someone else's data — with your own valid token. That's an
> **Insecure Direct Object Reference (IDOR)**, a.k.a. **Broken Object-Level
> Authorization (BOLA)**. The fix is one check the code skipped: *does this object
> belong to the caller?*

Every other writeup in this repo turns on a value being interpreted as code —
markup in HTML, input in SQL, a claim in a JWT. This one has no payload at all.
The request is completely well-formed and completely authenticated; the only thing
"wrong" with it is that it asks for an object the user isn't entitled to. It's the
last step of the repo's [`methodology.md`](../methodology.md) — **AUTHZ: was the
privilege used even required?** — and on modern targets it lands far more often
than XSS, because client-side hardening (auto-escaping, CSP, Trusted Types) does
nothing for it: authorization is server logic, and server logic is where it's
missing.

## The one idea: authentication ≠ authorization

Two different questions, and apps routinely answer only the first:

- **Authentication** — *who are you?* Proven by a session token / login. The server
  checks this well.
- **Authorization** — *are you allowed to touch **this** object?* Proven by an
  ownership/role check on the specific resource. This is the one that gets skipped.

A valid token means the request is *from a real user*. It says **nothing** about
whether *this* user owns *that* record. When the code treats "logged in" as
"allowed," every object becomes reachable by anyone with an account.

## The finding: Juice Shop's basket (`/rest/basket/{id}`)

This is **Finding #7** of the assessment, done entirely in Burp — no exploit
string, just an edited id:

```
1. Sent my own request  GET /rest/basket/1   → Repeater
2. Changed the id:       GET /rest/basket/2
                         GET /rest/basket/3
                         GET /rest/basket/4
3. Each returned 200 OK — a different UserId each time.
```

The basket is fetched by the `id` in the path and returned to whoever asks, as long
as they hold *a* valid token. Mine authenticated me fine; the server never asked the
next question — *is basket #2 mine?* — so it handed over baskets 2, 3, 4: **other
users' data, retrieved with my own session.** No privilege was escalated, nothing
was injected. The authorization check simply wasn't there. (Solved on the score
board as *View Basket*.)

## Why this ships so easily

- **The id is right there in the URL.** Building `GET /rest/basket/:id` and returning
  `Basket.findByPk(id)` reads as obviously correct — the ownership clause is a line
  you have to *remember to add*, and its absence looks like nothing.
- **"Authenticated" feels like "safe."** The route is behind a login wall, so it
  *feels* protected. The wall proves identity, not entitlement.
- **It's invisible to the client stack.** No amount of React escaping, CSP, or
  Trusted Types matters — the bug is in a check the server never ran.
- **Every id-keyed endpoint repeats the pattern.** Baskets, orders, messages,
  invoices, profiles — the same missing clause tends to be missing everywhere the
  same team wrote the same shape of handler.

## Two directions the same bug points

- **Horizontal** (this finding): reach *another user's* object at your own privilege
  level — user A reads user B's basket.
- **Vertical**: reach an object or action that needs *higher* privilege — a normal
  user hitting an admin-only object or endpoint because the role check is missing.

Both are the same root cause (a missing authorization check); they differ only in
whether you move *sideways* to a peer's data or *up* to privileged data.

## Predictable ids make it worse — but obscurity is not the fix

Sequential ids (`1, 2, 3`) make the bug trivial to sweep: you just count. A common
half-fix is to swap them for UUIDs so they can't be guessed. That raises the effort
but is **security by obscurity** — the ids still leak (in URLs, emails, referrers,
API responses, shared links), and once an attacker has one, the *same* missing check
still serves the object. An unguessable id is a lock you left open with a longer key
number painted on it. The real fix doesn't care whether the id is guessable.

## The fix: check ownership on every object, every request

**Enforce per-object authorization at the point of access** — after you know *who*
the caller is, verify the requested object is *theirs* before returning it:

```js
// vulnerable: id from the URL, no ownership check
const basket = await Basket.findByPk(req.params.id);
return res.json(basket);

// fixed: the object must belong to the authenticated user
const basket = await Basket.findByPk(req.params.id);
if (!basket || basket.UserId !== req.user.id) return res.sendStatus(403);
return res.json(basket);
```

Supporting practices:

- **Scope the query to the user, don't filter after.** Prefer
  `Basket.findOne({ where: { id, UserId: req.user.id } })` so a foreign object is
  *never even loaded*, closing timing/error-leak side channels.
- **Centralise it.** A per-resource authorization layer (policy/middleware) applied
  to every id-keyed route, so a new endpoint is authorized by default rather than by
  a line someone must remember.
- **Deny by default.** New routes should require an explicit ownership/role rule to
  return data, not inherit "authenticated is enough."
- **Don't rely on unguessable ids** as the control — treat that only as defence in
  depth on top of a real check.
- **Test it directly.** Two accounts, swap the id, expect `403`/`404` — the exact
  Repeater step that *found* this bug is also the regression test that proves it
  fixed.

## Takeaway

IDOR is the quietest bug in this repo: a perfectly valid, authenticated request that
the server answers too generously because it confirmed *identity* and forgot
*ownership*. There's no payload to filter and no framework that escapes it away — the
missing piece is a single authorization check on the specific object. Ask, on every
request, *does this thing belong to the caller?* — and the id in the URL stops being
a key to everyone's data.

---

*Demonstrated on an authorized, local target only: OWASP Juice Shop running via
Docker (Finding #7 — `/rest/basket/{id}`, ownership never checked), tested by editing
the id in Burp Suite Repeater and observing other users' baskets return under my own
token. Same repo discipline (`source → sink`, then **AUTHZ**), applied at the
access-control layer where identity is checked but entitlement is not.*
