#!/usr/bin/env python3
"""
dxa - DOM XSS source-to-sink analyzer.

A heuristic static linter that flags DOM-based XSS *sources*, *sinks*, and the
likely *source -> sink* flows between them in JavaScript. It is the source->sink
methodology documented in this repository, expressed as code.

What it does
------------
1. Finds dangerous sinks   (innerHTML, document.write, eval, jQuery .html(), ...)
2. Finds attacker-controllable sources (location.hash, document.referrer, ...)
3. Runs a lightweight taint propagation: variables assigned from a source are
   marked tainted, and any sink that consumes a tainted value (or a source
   directly) is raised to HIGH confidence.

What it is NOT
--------------
This is a *heuristic* built on regular expressions plus a small taint pass, not a
sound program analysis. It does not build a real AST or a precise data-flow
graph, so it produces false positives (matches inside comments/strings) and false
negatives (taint through function calls, aliasing, complex expressions). Treat the
output as a prioritized triage list, then confirm each finding by hand.

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

# --- Sinks: (id, compiled regex, base severity, explanation) ----------------
SINKS = [
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

# --- Sources: attacker-controllable inputs ----------------------------------
SOURCES = [
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
# message-event data (e.data / event.data) counts as a source only in files that
# actually register a message listener - checked per file to cut noise.
MSG_LISTENER = re.compile(r'addEventListener\s*\(\s*[\'"`]message[\'"`]|\.onmessage\s*=')
MSG_DATA = re.compile(r'\b[A-Za-z_$][\w$]*\.data\b')

ASSIGN = re.compile(r'^\s*(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$')
CONF_RANK = {"low": 0, "medium": 1, "high": 2}


def source_hits(text, msg_active):
    """Names of sources *read* in `text`. A source that is the target of an
    assignment (e.g. `location.href = x`) is a sink, not a read, so skip it."""
    hits = []
    for name, rx in SOURCES:
        for m in rx.finditer(text):
            after = text[m.end():].lstrip()
            if after[:1] == "=" and after[1:2] != "=":
                continue  # write target, not a read
            hits.append(name)
            break
    if msg_active and MSG_DATA.search(text):
        hits.append("postMessage.data")
    return hits


def compute_taint(lines, msg_active):
    """Fixpoint: a var is tainted if it is assigned from a source or another
    tainted var. Cheap approximation of data flow across straight-line code."""
    tainted = set()
    for _ in range(6):  # iterate to a fixpoint (bounded)
        changed = False
        for line in lines:
            m = ASSIGN.match(line)
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            if source_hits(rhs, msg_active) or any(
                re.search(r'\b' + re.escape(v) + r'\b', rhs) for v in tainted
            ):
                if lhs not in tainted:
                    tainted.add(lhs)
                    changed = True
        if not changed:
            break
    return tainted


def scan_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().split("\n")
    except OSError:
        return []

    joined = "\n".join(lines)
    msg_active = bool(MSG_LISTENER.search(joined))
    tainted = compute_taint(lines, msg_active)
    dynamic = re.compile(r'[A-Za-z_$][\w$]*')  # any identifier => not a pure literal

    findings = []
    for lineno, line in enumerate(lines, 1):
        matched_here = {sid for sid, rx, *_ in SINKS if rx.search(line)}
        for sid, rx, severity, desc in SINKS:
            if sid not in matched_here:
                continue
            # `location.href =` is already reported as `navigation`; don't also
            # report it as the weaker, overlapping `src-href` sink.
            if sid == "src-href" and "navigation" in matched_here:
                continue
            srcs = source_hits(line, msg_active)
            tvars = [v for v in tainted if re.search(r'\b' + re.escape(v) + r'\b', line)]
            if srcs or tvars:
                confidence = "high"
            elif dynamic.search(line.split("//", 1)[0]):
                confidence = "medium"
            else:
                confidence = "low"
            findings.append({
                "file": path, "line": lineno, "sink": sid,
                "severity": severity, "confidence": confidence,
                "description": desc, "code": line.strip()[:200],
                "sources": srcs, "tainted_vars": tvars,
            })
    return findings


def iter_js(target):
    if os.path.isfile(target):
        yield target
        return
    for root, _, files in os.walk(target):
        if "node_modules" in root or "/.git" in root:
            continue
        for name in files:
            if name.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs")):
                yield os.path.join(root, name)


def main():
    ap = argparse.ArgumentParser(description="DOM XSS source-to-sink analyzer")
    ap.add_argument("target", help="JavaScript file or directory to scan")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("--min-confidence", choices=["low", "medium", "high"],
                    default="low", help="hide findings below this confidence")
    args = ap.parse_args()

    floor = CONF_RANK[args.min_confidence]
    findings = []
    for js in iter_js(args.target):
        findings.extend(scan_file(js))
    findings = [f for f in findings if CONF_RANK[f["confidence"]] >= floor]
    findings.sort(key=lambda f: (-CONF_RANK[f["confidence"]], f["file"], f["line"]))

    if args.json:
        print(json.dumps(findings, indent=2))
        sys.exit(1 if findings else 0)

    if not findings:
        print("No DOM-XSS source/sink patterns found (at the chosen confidence).")
        sys.exit(0)

    for f in findings:
        flow = ""
        if f["sources"]:
            flow = "  <- source: " + ", ".join(f["sources"])
        elif f["tainted_vars"]:
            flow = "  <- tainted var: " + ", ".join(f["tainted_vars"])
        print(f"{f['file']}:{f['line']}  [{f['severity'].upper()}/"
              f"{f['confidence']} confidence]  sink: {f['sink']}{flow}")
        print(f"    {f['description']}")
        print(f"    | {f['code']}")
        print()

    highs = sum(1 for f in findings if f["confidence"] == "high")
    print(f"{len(findings)} finding(s) - {highs} at HIGH confidence "
          f"(a source or tainted value reaches the sink).")
    sys.exit(1)


if __name__ == "__main__":
    main()
