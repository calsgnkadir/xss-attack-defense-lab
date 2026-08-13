# Beyond the Lab — Independent Vulnerability Research

After building the lab foundation in this repository (OWASP Juice Shop, self-authored labs,
PortSwigger Academy), I applied the same **source → sink** discipline to *real, third-party
open-source software*: plugins published in the WordPress.org directory.

> ⚠️ **Scope & ethics.** Only **publicly distributed open-source code** was analysed. Every candidate
> was reproduced **only** in a private, local, Dockerized WordPress instance I control — never against
> any live or third-party site. Findings were handled through **coordinated disclosure** (Patchstack,
> a CVE Numbering Authority). No details of any unpatched issue are published here.

---

## Why this matters

Automated scanners and pattern-matching tools (increasingly AI-assisted) have made *pattern-level*
bug hunting a crowded lane — the easy, greppable bugs get found and reported by many people at once.
The value has shifted to what tooling is **bad** at: reading code for **logic and access-control
flaws**, reasoning about **privilege context**, and — critically — **verifying** a hypothesis in a
real environment before believing it. This is the skill this research set out to build.

---

## Methodology

**1. Target discovery & batch triage.**
Custom Python tooling queries the WordPress.org plugin API, downloads plugins at pinned versions, and
statically triages their source for high-signal sinks (unescaped output, unprepared `$wpdb` queries,
sensitive AJAX/REST handlers). The triage improved over many iterations to cut false positives:

- **Guard-following** — resolve a handler's helper calls one level deep, so authorization checks
  hidden in a `check_permission()` helper are not mistaken for "missing."
- **"Nonce ≠ authorization"** — a CSRF nonce is *not* an access-control check; handlers with a nonce
  but no capability/ownership check are flagged, not cleared.
- **Active-class filtering** — verify a handler's class is actually instantiated; an `add_action()`
  inside a class that is never `new`'d is dead code, not an entry point.

**2. Patch-diffing / variant analysis.**
For a plugin that recently shipped a security fix, diff the vulnerable and patched versions to learn
*exactly* what the developer fixed — then hunt the **sibling code paths they did not fix**. Developers
routinely patch one instance of a bug class and miss its variants.

**3. Verification in a local lab.**
Every surviving candidate is reproduced in a Dockerized WordPress instance (multiple roles, real HTTP
requests from an attacker's perspective) **before** it is treated as real. This step repeatedly caught
static-analysis false positives — e.g. a handler that looked exploitable but whose class was never
loaded, and "missing authorization" that turned out to be an ownership check the grep missed.

**4. Coordinated disclosure.**
Confirmed issues are reported through Patchstack; unpatched details are never disclosed publicly.

---

## Results

- **Independently discovered** a Broken-Access-Control vulnerability in a WordPress plugin, built a
  working local proof-of-concept, and reported it through **Patchstack**, which **validated it as a
  genuine issue** (resolved as a concurrent duplicate — i.e. a second, independent report of a real,
  accepted vulnerability).
- **Independently re-derived, via patch-diffing,** a SQL-injection variant that was subsequently
  **published as a CVE** — confirming the method surfaces real, CVE-class bugs, not false positives.
- Produced reusable, iteratively-hardened **auditing tooling** and a repeatable workflow.

The honest takeaway: the methodology **works** — it produced real, externally-validated findings. The
remaining gap between "valid finding" and "first-to-report CVE" is timing and target selection, not
detection capability.

---

## Disciplines learned (the part that transfers to any target)

- **Severity is contextual.** An admin-only SQL injection is not a meaningful vulnerability (an admin
  already has higher privilege); the same bug reachable by a Subscriber or unauthenticated user is.
- **A guard can be present but insufficient.** A nonce blocks CSRF, not authorization; an ownership
  check is not a capability check; a capability check on the wrong object is a bypass.
- **Static analysis lies without verification.** Dead code, helper-based guards, and framework
  escaping all fool a grep. Reproducing in a real environment is non-negotiable.
- **Read the program's scope before spending effort.** What counts as a valid, in-scope finding is a
  written rule, not a guess — and it changes.
- **Choose under-contested targets.** Heavily-audited components produce duplicates; the same effort
  on an under-watched target is far likelier to land.

---

*Independent, responsible security research · public open-source code · local verification · coordinated disclosure.*
