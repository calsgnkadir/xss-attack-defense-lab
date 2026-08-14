#!/usr/bin/env python3
"""
dxa - a source-to-sink XSS analyzer for full-stack code.

A heuristic static linter that flags XSS *sources*, *sinks*, and the likely
*source -> sink* flows between them, on both sides of a web app:

  * client side  - JavaScript / TypeScript (DOM XSS)
  * server side  - C# / ASP.NET & Razor (server-rendered XSS)

It is the source->sink methodology documented in this repository, expressed as
code. For JavaScript it also runs a light taint pass so a variable assigned from
a source and later used in a sink is raised to HIGH confidence.

What it is NOT
--------------
A *heuristic* built on regular expressions (plus a small taint pass for JS), not
a sound program analysis. No AST, no precise data-flow graph -> it has false
positives (matches in comments/strings) and false negatives (taint through
calls, aliasing, complex expressions). Use the output to prioritise, then confirm
each finding by hand.

Usage
-----
    python dxa.py <file-or-directory> [--json] [--min-confidence low|medium|high]

Exit code is non-zero when findings are reported, so it can gate a CI pipeline.
"""

import argparse
import json
import os
import re
import sys

# --- JavaScript / TypeScript sinks ------------------------------------------
JS_SINKS = [
    ("innerHTML",         re.compile(r'\.(?:inner|outer)HTML\s*='),
     "high",   "value assigned to (inner|outer)HTML is parsed as HTML"),
    ("insertAdjacentHTML", re.compile(r'\.insertAdjacentHTML\s*\('),
     "high",   "insertAdjacentHTML() parses its argument as HTML"),
    ("document.write",    re.compile(r'\bdocument\.write(?:ln)?\s*\('),
     "high",   "document.write(ln)() writes raw markup into the page"),
    ("eval",              re.compile(r'\beval\s*\('),
     "high",   "eval() executes its argument as JavaScript"),
    ("Function",          re.compile(r'\b(?:new\s+)?Function\s*\('),
     "high",   "the Function() constructor executes a string as code"),
    ("timer-string",      re.compile(r'\b(?:setTimeout|setInterval)\s*\(\s*[\'"`]'),
     "high",   "setTimeout/setInterval with a string argument runs it as code"),
    ("angular-bypass",    re.compile(r'bypassSecurityTrust\w*\s*\('),
     "high",   "Angular DomSanitizer bypass disables the framework's escaping"),
    ("react-dangerous",   re.compile(r'dangerouslySetInnerHTML'),
     "high",   "React dangerouslySetInnerHTML injects raw HTML"),
    ("jquery-html",       re.compile(r'\.(?:html|append|prepend|after|before|replaceWith|wrapAll|wrapInner|wrap)\s*\('),
     "medium", "jQuery HTML sink - inserts its argument as markup"),
    ("jquery-selector",   re.compile(r'\$\(\s*(?![\'"#.\[\]])[A-Za-z_$]'),
     "medium", "$() on a non-literal value can build and run HTML"),
    ("navigation",        re.compile(r'\blocation(?:\.href)?\s*=|\blocation\.(?:assign|replace)\s*\(|\bwindow\.open\s*\('),
     "medium", "navigation sink - a javascript: URL here executes"),
    ("setAttribute",      re.compile(r'\.setAttribute\s*\(\s*[\'"`](?:href|src|on\w+|formaction|xlink:href|data|style)[\'"`]'),
     "medium", "setAttribute() on a dangerous attribute"),
    ("src-href",          re.compile(r'\.(?:src|href)\s*='),
     "low",    "src/href assignment - javascript:/data: URLs may execute"),
]
JS_SOURCES = [
    ("location.hash",     re.compile(r'\blocation\.hash\b')),
    ("location.search",   re.compile(r'\blocation\.search\b')),
    ("location.href",     re.compile(r'\blocation\.href\b')),
    ("location.pathname", re.compile(r'\blocation\.pathname\b')),
    ("document.URL",      re.compile(r'\bdocument\.(?:URL|documentURI|baseURI)\b')),
    ("document.referrer", re.compile(r'\bdocument\.referrer\b')),
    ("window.name",       re.compile(r'\bwindow\.name\b')),
    ("document.cookie",   re.compile(r'\bdocument\.cookie\b')),
    ("web-storage",       re.compile(r'\b(?:local|session)Storage\b')),
    ("URL-params",        re.compile(r'\bURLSearchParams\b|\.searchParams\b')),
    ("history.state",     re.compile(r'\bhistory\.state\b')),
]
MSG_LISTENER = re.compile(r'addEventListener\s*\(\s*[\'"`]message[\'"`]|\.onmessage\s*=')
MSG_DATA = re.compile(r'\b[A-Za-z_$][\w$]*\.data\b')

# --- C# / ASP.NET & Razor sinks (server-rendered XSS) -----------------------
CS_SINKS = [
    ("Html.Raw",       re.compile(r'@?Html\.Raw\s*\('),
     "high",   "@Html.Raw() emits its argument as unescaped HTML"),
    ("Response.Write", re.compile(r'\bResponse\.Write\s*\('),
     "high",   "Response.Write() writes raw output straight into the response"),
    ("HtmlString",     re.compile(r'\bnew\s+(?:Mvc)?HtmlString\s*\('),
     "high",   "HtmlString/MvcHtmlString marks a string as trusted, un-encoded HTML"),
    ("MarkupString",   re.compile(r'\bnew\s+MarkupString\s*\(|\(\s*MarkupString\s*\)'),
     "high",   "Blazor MarkupString renders a string as raw HTML"),
    ("InnerHtml",      re.compile(r'\.InnerHtml\s*='),
     "high",   "control.InnerHtml assignment renders raw HTML"),
    ("Literal.Text",   re.compile(r'\.Text\s*=\s*(?![\'"])'),
     "low",    "Literal/Label .Text set from a dynamic value (raw when Mode=PassThrough)"),
]
CS_SOURCES = [
    ("Request.Query",   re.compile(r'\bRequest\.(?:Query|QueryString)\b')),
    ("Request.Form",    re.compile(r'\bRequest\.Form\b')),
    ("Request.Params",  re.compile(r'\bRequest\.Params\b|\bRequest\s*\[')),
    ("Request.Cookies", re.compile(r'\bRequest\.Cookies\b')),
    ("Request.Headers", re.compile(r'\bRequest\.Headers\b')),
    ("Request.Route",   re.compile(r'\bRequest\.RouteValues\b|\bRouteData\b')),
    ("Request.Body",    re.compile(r'\bRequest\.Body\b')),
]

ASSIGN = re.compile(r'^\s*(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$')
CONF_RANK = {"low": 0, "medium": 1, "high": 2}
JS_EXT = (".js", ".ts", ".jsx", ".tsx", ".mjs")
CS_EXT = (".cs", ".cshtml", ".razor")


def source_hits(text, sources, msg_active):
    """Names of sources *read* in `text`. A source that is the target of an
    assignment (e.g. `location.href = x`) is a write, not a read, so skip it."""
    hits = []
    for name, rx in sources:
        for m in rx.finditer(text):
            after = text[m.end():].lstrip()
            if after[:1] == "=" and after[1:2] != "=":
                continue  # write target, not a read
            hits.append(name)
            break
    if msg_active and MSG_DATA.search(text):
        hits.append("postMessage.data")
    return hits


def compute_taint(lines, sources, msg_active):
    """JS only: a var is tainted if assigned from a source or another tainted
    var. Bounded fix-point - a cheap approximation of straight-line data flow."""
    tainted = set()
    for _ in range(6):
        changed = False
        for line in lines:
            m = ASSIGN.match(line)
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            if source_hits(rhs, sources, msg_active) or any(
                re.search(r'\b' + re.escape(v) + r'\b', rhs) for v in tainted
            ):
                if lhs not in tainted:
                    tainted.add(lhs)
                    changed = True
        if not changed:
            break
    return tainted


def scan_file(path):
    ext = os.path.splitext(path)[1].lower()
    is_js = ext in JS_EXT
    sinks, sources = (JS_SINKS, JS_SOURCES) if is_js else (CS_SINKS, CS_SOURCES)

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().split("\n")
    except OSError:
        return []

    msg_active = is_js and bool(MSG_LISTENER.search("\n".join(lines)))
    tainted = compute_taint(lines, sources, msg_active) if is_js else set()
    dynamic = re.compile(r'[A-Za-z_$@][\w$]*')

    findings = []
    for lineno, line in enumerate(lines, 1):
        matched_here = {sid for sid, rx, *_ in sinks if rx.search(line)}
        for sid, rx, severity, desc in sinks:
            if sid not in matched_here:
                continue
            # `location.href =` is already 'navigation'; don't double-report it.
            if sid == "src-href" and "navigation" in matched_here:
                continue
            srcs = source_hits(line, sources, msg_active)
            tvars = [v for v in tainted if re.search(r'\b' + re.escape(v) + r'\b', line)]
            if srcs or tvars:
                confidence = "high"
            elif dynamic.search(line.split("//", 1)[0]):
                confidence = "medium"
            else:
                confidence = "low"
            findings.append({
                "file": path, "line": lineno, "sink": sid, "lang": "js" if is_js else "cs",
                "severity": severity, "confidence": confidence, "description": desc,
                "code": line.strip()[:200], "sources": srcs, "tainted_vars": tvars,
            })
    return findings


def iter_files(target):
    if os.path.isfile(target):
        yield target
        return
    for root, _, files in os.walk(target):
        if "node_modules" in root or os.sep + ".git" in root:
            continue
        for name in files:
            if name.endswith(JS_EXT + CS_EXT):
                yield os.path.join(root, name)


def main():
    ap = argparse.ArgumentParser(description="source-to-sink XSS analyzer (JS + C#/.NET)")
    ap.add_argument("target", help="file or directory to scan")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("--min-confidence", choices=["low", "medium", "high"],
                    default="low", help="hide findings below this confidence")
    args = ap.parse_args()

    floor = CONF_RANK[args.min_confidence]
    findings = []
    for f in iter_files(args.target):
        findings.extend(scan_file(f))
    findings = [f for f in findings if CONF_RANK[f["confidence"]] >= floor]
    findings.sort(key=lambda f: (-CONF_RANK[f["confidence"]], f["file"], f["line"]))

    if args.json:
        print(json.dumps(findings, indent=2))
        sys.exit(1 if findings else 0)

    if not findings:
        print("No XSS source/sink patterns found (at the chosen confidence).")
        sys.exit(0)

    for f in findings:
        flow = ""
        if f["sources"]:
            flow = "  <- source: " + ", ".join(f["sources"])
        elif f["tainted_vars"]:
            flow = "  <- tainted var: " + ", ".join(f["tainted_vars"])
        print(f"{f['file']}:{f['line']}  [{f['severity'].upper()}/{f['confidence']} "
              f"confidence, {f['lang']}]  sink: {f['sink']}{flow}")
        print(f"    {f['description']}")
        print(f"    | {f['code']}")
        print()

    highs = sum(1 for f in findings if f["confidence"] == "high")
    print(f"{len(findings)} finding(s) - {highs} at HIGH confidence "
          f"(a source or tainted value reaches the sink).")
    sys.exit(1)


if __name__ == "__main__":
    main()
