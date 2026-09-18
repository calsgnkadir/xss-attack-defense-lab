#!/usr/bin/env python3
"""
dxadyn - dynamic reflection verifier, the companion to dxa.

dxa is *static*: it reads code and says "this looks like a source -> sink flow."
dxadyn is *dynamic*: it drives a running target, injects a unique canary into
inputs, and checks whether the injected markup survives **unencoded** somewhere -
in the same response (reflected) or on a later page (stored). That turns dxa's
"suspicious" into an evidence-backed "reflected unencoded here" candidate.

  static  (dxa)     : grep code for innerHTML/eval/... + source -> sink taint
  dynamic (dxadyn)  : send canary -> read response(s) -> did markup survive raw?

Two modes:
  reflected (default): crawl a URL, inject into every form field / GET param, check
                       the same response.
  stored (--stored)  : POST/GET a single form on --target, then look for the canary
                       on each of --check URL(s). Optionally --login first.

Stdlib only (no dependencies), same ethos as dxa. It reports *candidates* - a raw
reflection is a strong signal, not proof of execution; confirm each by hand in the
browser (does the payload actually run?).

Scope & ethics: authorized / local targets only (your own instance or an in-scope
bug-bounty/VDP asset). Never point it at a target you are not allowed to test.

Usage
-----
  # reflected (v1)
  python dxadyn.py http://localhost:8090/
  python dxadyn.py http://localhost:8090/ --depth 1

  # stored, authenticated (v2)  -- Bludit tags-XSS example
  python dxadyn.py --stored \\
      --login http://localhost:8090/admin/login --user admin --pass labpass123 \\
      --target http://localhost:8090/admin/new-content --target-field tags \\
      --extra title=probe,slug=dxaprobe,content=b,type=published \\
      --check http://localhost:8090/tag/CANARY_KEY_HERE
"""

import argparse
import html as htmllib
import http.cookiejar
import secrets
import sys
import urllib.parse
import urllib.request
from html.parser import HTMLParser

UA = "dxadyn/0.1 (authorized local testing)"

# The canary is a unique id + a markup payload. If the payload survives RAW in the
# response, the value was reflected into an HTML context without encoding.
MARKUP = '<dXsS>'          # the tag that must survive raw to count as unencoded
ATTR_MARK = '"'           # a bare double-quote surviving raw = attribute breakout


def make_canary():
    """A fresh, greppable, collision-free marker per injection."""
    cid = "dxa" + secrets.token_hex(4)
    return cid, cid + ATTR_MARK + MARKUP     # e.g. dxa1a2b3c4d"<dXsS>


def _opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


OPENER = _opener()


def fetch(url, data=None):
    """GET (data=None) or POST (data=dict). Returns (status, final_url, body)."""
    body_bytes = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body_bytes, headers={"User-Agent": UA})
    try:
        with OPENER.open(req, timeout=15) as resp:
            return resp.status, resp.geturl(), resp.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, url, e.read().decode("utf-8", "ignore")
    except Exception as e:                                    # noqa: BLE001
        return None, url, f"__error__: {e}"


def verdict(cid, body):
    """Classify how the canary came back.
      unencoded : the raw <dXsS> tag survived  -> HTML injection possible (HIGH)
      attr-only : the raw " survived but not the tag -> attribute breakout (MEDIUM)
      encoded   : the id is present but markup was escaped -> reflected & safe
      absent    : the id is not in the response -> not reflected here
    """
    if cid + ATTR_MARK + MARKUP in body or cid in body and MARKUP in _around(cid, body):
        return "unencoded"
    if cid in body and _raw_quote_after(cid, body):
        return "attr-only"
    if cid in body:
        return "encoded"
    return "absent"


def _around(cid, body, span=40):
    i = body.find(cid)
    return body[i: i + len(cid) + span] if i != -1 else ""


def _raw_quote_after(cid, body):
    seg = _around(cid, body)
    return ATTR_MARK in seg and '&quot;' not in seg and '&#34;' not in seg


class FormParser(HTMLParser):
    """Collect forms (action, method, fields) and links carrying query params."""
    def __init__(self):
        super().__init__()
        self.forms = []
        self.links = []
        self._cur = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action", ""),
                         "method": (a.get("method") or "get").lower(),
                         "fields": {}}
        elif tag in ("input", "textarea", "select") and self._cur is not None:
            name = a.get("name")
            if name and a.get("type") not in ("submit", "button", "file", "image"):
                self._cur["fields"][name] = a.get("value", "")
        elif tag == "a":
            href = a.get("href", "")
            if "?" in href and "=" in href.split("?", 1)[1]:
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def discover(base_url, body):
    p = FormParser()
    try:
        p.feed(body)
    except Exception:                                        # noqa: BLE001
        pass
    forms = [{**f, "action": urllib.parse.urljoin(base_url, f["action"] or base_url)}
             for f in p.forms]
    links = [urllib.parse.urljoin(base_url, h) for h in p.links]
    return forms, links


def probe_form(form):
    """Inject a canary into each field in turn; report unencoded reflections."""
    out = []
    fields = list(form["fields"]) or []
    for target in fields:
        cid, canary = make_canary()
        data = {k: (canary if k == target else (form["fields"][k] or "dxa"))
                for k in fields}
        if form["method"] == "post":
            status, _, body = fetch(form["action"], data=data)
        else:
            url = form["action"] + ("&" if "?" in form["action"] else "?") + \
                urllib.parse.urlencode(data)
            status, _, body = fetch(url)
        v = verdict(cid, body)
        if v in ("unencoded", "attr-only"):
            out.append(_finding(form["action"], form["method"], target, v, status))
    return out


def probe_link(link):
    out = []
    parts = urllib.parse.urlsplit(link)
    params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    for i, (name, _) in enumerate(params):
        cid, canary = make_canary()
        newq = [(n, canary if j == i else v) for j, (n, v) in enumerate(params)]
        url = urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(newq)))
        status, _, body = fetch(url)
        v = verdict(cid, body)
        if v in ("unencoded", "attr-only"):
            out.append(_finding(f"{parts.scheme}://{parts.netloc}{parts.path}",
                                "GET", name, v, status))
    return out


def _finding(where, method, param, v, status):
    conf = "high" if v == "unencoded" else "medium"
    return {"url": where, "method": method.upper(), "param": param,
            "reflection": v, "confidence": conf, "status": status}


def crawl(base_url, depth):
    seen_pages, findings, queue = set(), [], [(base_url, depth)]
    host = urllib.parse.urlsplit(base_url).netloc
    while queue:
        url, d = queue.pop(0)
        if url in seen_pages:
            continue
        seen_pages.add(url)
        status, final, body = fetch(url)
        if not body or body.startswith("__error__"):
            continue
        forms, links = discover(final, body)
        for f in forms:
            findings += probe_form(f)
        for l in links:
            findings += probe_link(l)
        if d > 0:
            for l in links:
                if urllib.parse.urlsplit(l).netloc == host and l not in seen_pages:
                    queue.append((l.split("?")[0], d - 1))
    # de-dupe on (url, param, reflection)
    uniq, keys = [], set()
    for f in findings:
        k = (f["url"], f["param"], f["reflection"])
        if k not in keys:
            keys.add(k)
            uniq.append(f)
    return uniq


# --- v2: authenticated + stored XSS -----------------------------------------

import re


def _extract_csrf(body, field):
    """Grab a CSRF token value out of the login page's HTML (field name-agnostic)."""
    m = re.search(r'name="' + re.escape(field) + r'"[^>]*value="([^"]+)"', body) \
        or re.search(r'value="([^"]+)"[^>]*name="' + re.escape(field) + r'"', body)
    return m.group(1) if m else None


def _cookie_jar():
    """Reach into OPENER for its CookieJar (installed by _opener())."""
    for h in OPENER.handlers:
        if isinstance(h, urllib.request.HTTPCookieProcessor):
            return h.cookiejar
    return None


def login(login_url, user, password, user_field="username", pass_field="password",
          csrf_field="tokenCSRF", extra=None):
    """Log in through a standard HTML form. Session cookies live in `OPENER`.
    Success = the POST either landed us on a different URL (redirect out of
    the login page) *or* set at least one new cookie we did not have before."""
    status, _, body = fetch(login_url)
    if status is None:
        return False

    jar = _cookie_jar()
    before = len(list(jar)) if jar is not None else 0

    data = {user_field: user, pass_field: password}
    tok = _extract_csrf(body, csrf_field) if csrf_field else None
    if tok is not None:
        data[csrf_field] = tok
    if extra:
        data.update(extra)

    st, final_url, _ = fetch(login_url, data=data)
    if st is None:
        return False
    after = len(list(jar)) if jar is not None else 0
    return final_url != login_url or after > before


def probe_stored(target_url, target_field, extra_fields, check_urls,
                 method="post", csrf_field="tokenCSRF"):
    """Submit ONE form with a canary in `target_field`, then look for the canary
    on each URL in `check_urls`. A URL may contain the literal token `{CID}` -
    the canary id is substituted in (useful for slug-derived pages)."""
    cid, canary = make_canary()

    # If the target page carries a CSRF token in a hidden field, pick it up.
    tok = None
    if csrf_field:
        st, _, body = fetch(target_url)
        if st is not None:
            tok = _extract_csrf(body, csrf_field)

    data = dict(extra_fields or {})
    data[target_field] = canary
    if tok is not None and csrf_field:
        data[csrf_field] = tok

    if method.lower() == "post":
        sub_status, _, _ = fetch(target_url, data=data)
    else:
        qs = urllib.parse.urlencode(data)
        sep = "&" if "?" in target_url else "?"
        sub_status, _, _ = fetch(target_url + sep + qs)

    out = []
    for raw_url in check_urls:
        url = raw_url.replace("{CID}", cid)
        st, _, body = fetch(url)
        v = verdict(cid, body or "")
        if v in ("unencoded", "attr-only"):
            out.append({"target": target_url, "field": target_field, "check_url": url,
                        "reflection": v, "confidence": "high" if v == "unencoded" else "medium",
                        "sub_status": sub_status, "check_status": st, "canary_id": cid})
    return out, cid


def _parse_kv_list(text):
    """`a=1,b=hi,c=` -> {'a': '1', 'b': 'hi', 'c': ''} (values may not contain '=' commas)."""
    if not text:
        return {}
    out = {}
    for pair in text.split(","):
        if "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        out[k.strip()] = v
    return out


def main():
    ap = argparse.ArgumentParser(description="dynamic reflection verifier (companion to dxa)")
    ap.add_argument("url", nargs="?", help="target URL for reflected mode (authorized/local only)")
    ap.add_argument("--depth", type=int, default=0,
                    help="reflected mode: follow same-host links this many hops (default 0)")

    ap.add_argument("--stored", action="store_true",
                    help="stored mode: submit --target once, look for the canary on --check URL(s)")
    ap.add_argument("--target", help="stored mode: URL of the form to submit")
    ap.add_argument("--target-field", help="stored mode: form field to inject the canary into")
    ap.add_argument("--extra", default="",
                    help="stored mode: extra form fields, `a=1,b=hi,c=` comma-separated")
    ap.add_argument("--method", default="post", choices=["post", "get"],
                    help="stored mode: submission method (default post)")
    ap.add_argument("--check", default="",
                    help="stored mode: comma-separated URL(s) to check; `{CID}` is replaced with the canary id")
    ap.add_argument("--csrf-field", default="tokenCSRF",
                    help="hidden CSRF field name (default tokenCSRF); empty to disable")

    ap.add_argument("--login", help="log in at this URL before probing (session persists)")
    ap.add_argument("--user", help="username for --login")
    ap.add_argument("--pass", dest="password", help="password for --login")
    ap.add_argument("--user-field", default="username", help="login form username field")
    ap.add_argument("--pass-field", default="password", help="login form password field")

    args = ap.parse_args()

    if args.login:
        if not (args.user and args.password):
            print("[dxadyn] --login requires --user and --pass", file=sys.stderr)
            sys.exit(2)
        ok = login(args.login, args.user, args.password,
                   user_field=args.user_field, pass_field=args.pass_field,
                   csrf_field=args.csrf_field or None)
        print(f"[dxadyn] login {args.login} -> {'OK' if ok else 'FAILED (continuing anyway)'}")

    if args.stored:
        if not (args.target and args.target_field and args.check):
            print("[dxadyn] --stored requires --target, --target-field, and --check",
                  file=sys.stderr)
            sys.exit(2)
        checks = [u.strip() for u in args.check.split(",") if u.strip()]
        print(f"[dxadyn] STORED probe: {args.target} field='{args.target_field}' "
              f"-> checking {len(checks)} URL(s) - authorized/local only\n")
        findings, cid = probe_stored(args.target, args.target_field,
                                     _parse_kv_list(args.extra), checks,
                                     method=args.method,
                                     csrf_field=args.csrf_field or "")
        print(f"[dxadyn] canary id = {cid}")
        if not findings:
            print("No unencoded stored reflection on the given check URL(s).")
            sys.exit(0)
        for f in findings:
            tag = "UNENCODED (HTML injection)" if f["reflection"] == "unencoded" \
                else "attribute-breakout quote"
            print(f"{f['check_url']}  [{f['confidence'].upper()}]  "
                  f"stored via {f['target']} field '{f['field']}'  -> {tag}  "
                  f"(submit HTTP {f['sub_status']}, check HTTP {f['check_status']})")
        highs = sum(1 for f in findings if f["confidence"] == "high")
        print(f"\n{len(findings)} stored candidate(s) - {highs} unencoded. "
              f"Confirm each in the browser (does the payload actually execute?).")
        sys.exit(1)

    # --- reflected (v1) path ---
    if not args.url:
        ap.error("either a positional URL (reflected mode) or --stored is required")
    print(f"[dxadyn] probing {args.url} (depth={args.depth}) - authorized/local only\n")
    findings = crawl(args.url, args.depth)
    if not findings:
        print("No unencoded reflections found. (Inputs may be encoded, POST-guarded, or absent.)")
        sys.exit(0)

    for f in findings:
        tag = "UNENCODED (HTML injection)" if f["reflection"] == "unencoded" \
            else "attribute-breakout quote"
        print(f"{f['url']}  [{f['confidence'].upper()}]  {f['method']} param '{f['param']}'"
              f"  -> {tag}  (HTTP {f['status']})")
    highs = sum(1 for f in findings if f["confidence"] == "high")
    print(f"\n{len(findings)} reflected candidate(s) - {highs} unencoded. "
          f"Confirm each in the browser (does the payload actually execute?).")
    sys.exit(1)


if __name__ == "__main__":
    main()
