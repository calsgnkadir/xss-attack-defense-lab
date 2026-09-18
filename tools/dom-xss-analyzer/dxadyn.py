#!/usr/bin/env python3
"""
dxadyn - dynamic reflection verifier, the companion to dxa.

dxa is *static*: it reads code and says "this looks like a source -> sink flow."
dxadyn is *dynamic*: it drives a running target, injects a unique canary into
every GET parameter and form field it can find, and checks whether the injected
markup survives **unencoded** in the response. That turns dxa's "suspicious" into
an evidence-backed "reflected unencoded here" candidate - the missing half
between "flagged" and "confirmed."

  static  (dxa)     : grep code for innerHTML/eval/... + source -> sink taint
  dynamic (dxadyn)  : send canary -> read response -> did the markup survive raw?

Stdlib only (no dependencies), same ethos as dxa. It reports *candidates* - a raw
reflection is a strong signal, not a proof of execution; confirm each by hand in
the browser (does it actually run?), exactly as with dxa's HIGH findings.

Scope & ethics: authorized / local targets only (your own instance or an in-scope
bug-bounty/VDP asset). Never point it at a target you are not allowed to test.

Usage
-----
    python dxadyn.py http://localhost:8090/            # crawl one page, probe all inputs
    python dxadyn.py http://localhost:8090/ --depth 1  # also follow same-host links one hop
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


def main():
    ap = argparse.ArgumentParser(description="dynamic reflection verifier (companion to dxa)")
    ap.add_argument("url", help="target URL (authorized/local only)")
    ap.add_argument("--depth", type=int, default=0,
                    help="follow same-host links this many hops (default 0 = the one page)")
    args = ap.parse_args()

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
