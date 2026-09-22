#!/usr/bin/env python3
"""
dxa2dyn - the static -> dynamic bridge.

`dxa` reads *code* and flags source -> sink flows heuristically.
`dxadyn` drives a *running target*, injects canaries, and reports where they
survive unencoded.

Each half already works alone. This bridge chains them: run `dxa` on a
codebase, extract likely HTTP parameter names from its HIGH-confidence
findings, then drive `dxadyn` against a running URL with those parameters as
targeted synthetic probes (in addition to the params/forms it discovers on
its own). One command, two lenses.

Usage
-----
    python dxa2dyn.py <codebase-path> <target-url>
    python dxa2dyn.py ./app/routes http://localhost:3000/ --cookie "sid=..."

Ethos & scope
-------------
Authorized/local targets only, same as `dxa` and `dxadyn`. This is glue; both
halves' honest limitations still apply. Confirm each flagged reflection in the
browser.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.parse

import dxadyn


# Patterns that pull likely HTTP parameter names out of source code that dxa
# already flagged as a source read. Deliberately conservative: it must look
# like `container.<name>` or `container["<name>"]` where `container` is one of
# the usual request-object hosts across JS/PHP/C#.
_CONTAINER = (r'(?:req(?:uest)?|params|query|form|Request|Query|Form|'
              r'QueryString|Cookies|Headers|_GET|_POST|_REQUEST)')
_NAME = r'[A-Za-z_$][\w$-]{0,31}'   # allow 1-char params (q, s, t, id...)

PARAM_PATTERNS = [
    # req.query.q, req.params.id, request.form.search (nested Express/Django style)
    re.compile(rf'\breq(?:uest)?\.(?:query|body|params|form|Query|Form|QueryString|Params)\.({_NAME})'),
    # req.query.<name>  |  request.form.<name>  (single-hop shorthand)
    re.compile(rf'\b{_CONTAINER}\.({_NAME})\b'),
    # Request.QueryString["name"], $_GET['k'], params['id']
    re.compile(rf'\b{_CONTAINER}\s*\[\s*[\'"]({_NAME})[\'"]\s*\]'),
    # (URLSearchParams(...).get('token') | .searchParams.get('token'))
    re.compile(rf'searchParams(?:\s*\)\s*)?\.get\s*\(\s*[\'"]({_NAME})[\'"]'),
    re.compile(rf'URLSearchParams\([^)]*\)\.get\s*\(\s*[\'"]({_NAME})[\'"]'),
    re.compile(rf'\.RouteValues\s*\[\s*[\'"]({_NAME})[\'"]\s*\]'),
]

# Boring names that never mean an HTTP parameter (or ARE the container itself,
# which pattern 2 can capture as a false hit): filter noise, case-insensitive.
_STOPWORDS = {"body", "headers", "method", "cookies", "url", "path",
              "session", "user", "params", "query", "form",
              "querystring", "route", "routevalues"}


def extract_param_hints(findings):
    """From dxa HIGH-confidence findings, guess HTTP parameter names to probe.
    Only mines the offending `code` line and the `sources` names dxa emits."""
    hints = set()
    for f in findings:
        if f.get("confidence") != "high":
            continue
        text = f.get("code", "") + " " + " ".join(f.get("sources", []))
        for rx in PARAM_PATTERNS:
            for m in rx.finditer(text):
                name = m.group(1)
                if 1 <= len(name) <= 32 and name.lower() not in _STOPWORDS:
                    hints.add(name)
    return sorted(hints)


def run_dxa(codebase_path):
    """Subprocess dxa (same folder), parse its JSON. Returns [] on failure."""
    here = os.path.dirname(os.path.abspath(__file__))
    dxa_py = os.path.join(here, "dxa.py")
    try:
        proc = subprocess.run(
            [sys.executable, dxa_py, codebase_path, "--json",
             "--min-confidence", "high"],
            capture_output=True, text=True, timeout=60,
        )
    except Exception as e:                                    # noqa: BLE001
        print(f"[dxa2dyn] dxa subprocess failed: {e}", file=sys.stderr)
        return []
    out = proc.stdout.strip()
    if not out:
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return []


def probe_hints(target_url, hint_params):
    """For each hinted parameter name, GET target with ?<name>=<canary> and
    verdict. Returns dxadyn-shaped finding dicts tagged 'dxa-guided'."""
    out = []
    for name in hint_params:
        cid, canary = dxadyn.make_canary()
        sep = "&" if "?" in target_url else "?"
        url = f"{target_url}{sep}{name}={urllib.parse.quote(canary)}"
        status, _, body = dxadyn.fetch(url)
        v = dxadyn.verdict(cid, body or "")
        if v in ("unencoded", "attr-only"):
            out.append({
                "url": target_url, "method": "GET", "param": name,
                "reflection": v,
                "confidence": "high" if v == "unencoded" else "medium",
                "status": status, "origin": "dxa-guided",
            })
    return out


def main():
    ap = argparse.ArgumentParser(
        description="dxa -> dxadyn bridge: static-guided dynamic XSS probing")
    ap.add_argument("codebase", help="path to codebase to scan with dxa first")
    ap.add_argument("url", help="running target URL to probe with dxadyn")
    ap.add_argument("--cookie", default="",
                    help="raw Cookie header attached to every dynamic request")
    ap.add_argument("--header", action="append", default=[],
                    help="extra header 'Name: value' (repeatable)")
    args = ap.parse_args()

    if args.cookie:
        dxadyn.apply_cookie(args.cookie)
    for spec in args.header:
        dxadyn.apply_header(spec)

    print(f"[dxa2dyn] static scan: {args.codebase}")
    dxa_findings = run_dxa(args.codebase)
    highs = [f for f in dxa_findings if f.get("confidence") == "high"]
    print(f"[dxa2dyn] dxa reported {len(dxa_findings)} finding(s), "
          f"{len(highs)} HIGH confidence")

    hints = extract_param_hints(dxa_findings)
    shown = ", ".join(hints[:12]) + ("..." if len(hints) > 12 else "")
    print(f"[dxa2dyn] extracted {len(hints)} parameter hint(s): {shown or '(none)'}")

    print(f"\n[dxa2dyn] dynamic probe: {args.url} - authorized/local only\n")
    dyn_findings = dxadyn.crawl(args.url, 0)
    for f in dyn_findings:
        f["origin"] = "crawl-discovered"
    hint_findings = probe_hints(args.url, hints)
    all_findings = dyn_findings + hint_findings

    if not all_findings:
        print("No unencoded reflections. Static-side flags remain (below);")
        print("they may be internal-only sinks or on routes not reachable here.")
        for f in highs[:10]:
            print(f"  [static HIGH] {f['file']}:{f['line']}  sink={f['sink']}")
        sys.exit(0)

    for f in all_findings:
        tag = "UNENCODED (HTML injection)" if f["reflection"] == "unencoded" \
            else "attribute-breakout quote"
        print(f"{f['url']}  [{f['confidence'].upper()}] [{f['origin']}]  "
              f"{f['method']} param '{f['param']}'  -> {tag}  (HTTP {f['status']})")
    highs_dyn = sum(1 for f in all_findings if f["confidence"] == "high")
    print(f"\n{len(all_findings)} dynamic finding(s), {highs_dyn} HIGH. "
          "Static + dynamic combined; confirm each in the browser.")
    sys.exit(1)


if __name__ == "__main__":
    main()
