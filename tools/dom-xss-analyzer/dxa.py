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
import html
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

# --- PHP sinks (server-side XSS: unescaped output) --------------------------
PHP_SINKS = [
    ("echo",         re.compile(r'\becho\s+[^;]*\$'),
     "high",   "echo of a variable - unescaped output is XSS unless htmlspecialchars() is applied"),
    ("print",        re.compile(r'\bprint\s+[^;]*\$'),
     "high",   "print of a variable - same class as echo"),
    ("short-echo",   re.compile(r'<\?=[^?]*\$'),
     "high",   "<?= $var ?> renders raw HTML; wrap with htmlspecialchars()"),
    ("printf-family", re.compile(r'\b(?:v?printf)\s*\('),
     "medium", "printf/vprintf can render dynamic content unescaped"),
    ("blade-raw",    re.compile(r'\{!!'),
     "high",   "Laravel Blade {!! !!} disables escaping (the safe form is {{ }})"),
    ("twig-raw",     re.compile(r'\|\s*raw\b'),
     "medium", "Twig |raw filter disables escaping"),
    ("file_put_contents", re.compile(r'\bfile_put_contents\s*\('),
     "low",    "file_put_contents may store attacker HTML that is later rendered raw"),
]
PHP_SOURCES = [
    ("$_GET",         re.compile(r'\$_GET\b')),
    ("$_POST",        re.compile(r'\$_POST\b')),
    ("$_REQUEST",     re.compile(r'\$_REQUEST\b')),
    ("$_COOKIE",      re.compile(r'\$_COOKIE\b')),
    ("$_SERVER",      re.compile(r'\$_SERVER\b')),                # incl. HTTP_* headers
    ("$_FILES",       re.compile(r'\$_FILES\b')),
    ("php://input",   re.compile(r'php://input')),
    ("Laravel-Request", re.compile(r'\bRequest::(?:input|all|get|post|query|cookie|header)\b|'
                                    r'\brequest\(\)\s*->\s*(?:input|all|get|post|query|cookie|header)\b')),
    ("Symfony-Request", re.compile(r'\$request\s*->\s*(?:query|request|cookies|headers|files|attributes)\b')),
]

# --- Python sinks (Flask/Jinja + FastAPI + Django) --------------------------
PY_SINKS = [
    ("markupsafe-markup",   re.compile(r'\bMarkup\s*\('),
     "high",   "markupsafe.Markup(x) marks the string as safe HTML - Jinja will render it raw"),
    ("render-template-str", re.compile(r'\brender_template_string\s*\('),
     "high",   "render_template_string(x) treats x itself as a Jinja template - full server-side template injection surface"),
    ("django-mark-safe",    re.compile(r'\bmark_safe\s*\(|SafeString\s*\('),
     "high",   "Django mark_safe / SafeString bypasses auto-escaping"),
    ("django-format-html",  re.compile(r'\bformat_html(?:_join)?\s*\(\s*[\'"][^\'"]*%s'),
     "medium", "format_html with a raw %s in the template placeholder"),
    ("fastapi-html",        re.compile(r'\bHTMLResponse\s*\('),
     "medium", "FastAPI HTMLResponse renders its argument as raw HTML"),
    ("flask-response-html", re.compile(r'\bResponse\s*\([^)]*mimetype\s*=\s*[\'"]text/html[\'"]|make_response\s*\('),
     "medium", "Flask Response/make_response with text/html mimetype and a dynamic body"),
    ("jinja-safe-filter",   re.compile(r'\|\s*safe\b'),
     "high",   "Jinja |safe filter disables auto-escaping (used on a value = raw HTML)"),
    ("html-tostring",       re.compile(r'\blxml\.html\.tostring\s*\(|\bBeautifulSoup\s*\('),
     "low",    "lxml/BeautifulSoup HTML build - source injection depends on where the result flows"),
    ("os-system",           re.compile(r'\b(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen))\s*\(\s*[a-zA-Z_]'),
     "medium", "OS command sink - not XSS but a Python-only injection class worth flagging"),
]
PY_SOURCES = [
    ("flask-request-arg",   re.compile(r'\brequest\s*\.\s*args\s*(?:\.\s*get\s*\(|\[)')),
    ("flask-request-form",  re.compile(r'\brequest\s*\.\s*form\s*(?:\.\s*get\s*\(|\[)')),
    ("flask-request-values",re.compile(r'\brequest\s*\.\s*values\s*(?:\.\s*get\s*\(|\[)')),
    ("flask-request-json",  re.compile(r'\brequest\s*\.\s*get_json\s*\(|\brequest\s*\.\s*json\b')),
    ("flask-request-cookie",re.compile(r'\brequest\s*\.\s*cookies\s*(?:\.\s*get\s*\(|\[)')),
    ("flask-request-header",re.compile(r'\brequest\s*\.\s*headers\s*(?:\.\s*get\s*\(|\[)')),
    ("flask-view-args",     re.compile(r'\brequest\s*\.\s*view_args\b')),
    ("fastapi-param",       re.compile(r'=\s*(?:Query|Body|Header|Cookie|Path|Form|File)\s*\(')),
    ("django-request-get",  re.compile(r'\brequest\s*\.\s*GET\s*(?:\.\s*get\s*\(|\[)')),
    ("django-request-post", re.compile(r'\brequest\s*\.\s*POST\s*(?:\.\s*get\s*\(|\[)')),
    ("django-request-meta", re.compile(r'\brequest\s*\.\s*META\s*(?:\.\s*get\s*\(|\[)')),
    ("environ",             re.compile(r'\bos\.environ(?:\.\s*get\s*\(|\[)')),
    ("input-stdin",         re.compile(r'\bsys\.stdin\.(?:read|readline)\b|\binput\s*\(')),
]


# --- Java / JSP / Thymeleaf sinks (server-side XSS: unescaped output) -------
JAVA_SINKS = [
    ("servlet-writer",  re.compile(r'\b(?:getWriter\(\)|PrintWriter\s*\.\s*\w+)\s*\.\s*(?:print(?:ln)?|write|append)\s*\('),
     "high",   "Servlet PrintWriter print/println/write emits raw response body"),
    ("servlet-output",  re.compile(r'\bServletOutputStream\b.*\.(?:print|write)\s*\('),
     "high",   "ServletOutputStream writes raw bytes to the response"),
    ("response-write",  re.compile(r'\bresponse\s*\.\s*getWriter\(\)\s*\.\s*(?:print(?:ln)?|write|append)\s*\('),
     "high",   "response.getWriter() writes raw output"),
    ("jsp-expr",        re.compile(r'<%=[^%]*(?:request|param|session|cookie|\bvar\b|\$)'),
     "high",   "JSP <%= %> scriptlet emits value unescaped (unless htmlEscape wraps it)"),
    ("jsp-el-unescape", re.compile(r'<c:out[^>]+escapeXml\s*=\s*"false"'),
     "high",   "<c:out escapeXml=\"false\"> disables the default JSP escaping"),
    ("th-utext",        re.compile(r'\bth:utext\b'),
     "high",   "Thymeleaf th:utext renders content as raw HTML (th:text is the safe form)"),
    ("th-inline-unesc", re.compile(r'\[\(\$\{[^}]+\}\)\]'),
     "high",   "Thymeleaf [(${...})] inline-unescape; [[${...}]] is the escaped form"),
    ("jsoup-html",      re.compile(r'\.html\s*\(\s*(?![\'"`])'),
     "medium", "jsoup Element.html(x) parses its argument as HTML"),
    ("response-header", re.compile(r'\bresponse\s*\.\s*(?:setHeader|addHeader)\s*\('),
     "low",    "response header write - reflecting user input into a header can enable XSS in old browsers or via error pages"),
]
JAVA_SOURCES = [
    ("request.param",       re.compile(r'\brequest\s*\.\s*getParameter(?:Values|Map)?\s*\(')),
    ("request.header",      re.compile(r'\brequest\s*\.\s*getHeader(?:Names|s)?\s*\(')),
    ("request.cookies",     re.compile(r'\brequest\s*\.\s*getCookies\s*\(|\bCookie\s*\.\s*getValue\s*\(')),
    ("request.body",        re.compile(r'\brequest\s*\.\s*getReader\s*\(|\bgetInputStream\s*\(')),
    ("request.uri",         re.compile(r'\brequest\s*\.\s*(?:getRequestURI|getRequestURL|getQueryString|getPathInfo)\s*\(')),
    ("spring-param",        re.compile(r'@RequestParam\b|@RequestHeader\b|@PathVariable\b|@CookieValue\b|@RequestBody\b|@ModelAttribute\b')),
    ("session-attr",        re.compile(r'\bsession\s*\.\s*getAttribute\s*\(')),
    ("system-in-input",     re.compile(r'\bSystem\s*\.\s*in\b|\bnew\s+Scanner\s*\(\s*System\s*\.\s*in\s*\)')),
]

ASSIGN = re.compile(r'^\s*(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+?)\s*;?\s*$')
PHP_ASSIGN = re.compile(r'^\s*(\$[A-Za-z_]\w*)\s*=\s*(.+?)\s*;?\s*$')
# Java: `Type name = expr;` or `name = expr;` (type is optional, may be generic)
JAVA_ASSIGN = re.compile(
    r'^\s*(?:(?:final|static|public|private|protected|volatile|synchronized)\s+)*'
    r'(?:[\w<>\[\],?.\s]{1,80}?\s+)?'
    r'([A-Za-z_]\w*)\s*=\s*(.+?)\s*;?\s*$'
)
# Python: `name = expr` or `name: type = expr` (no ; terminator, no let/var)
PYTHON_ASSIGN = re.compile(
    r'^\s*([A-Za-z_]\w*)\s*(?::\s*[\w\[\], .]+?\s*)?=\s*(.+?)\s*$'
)
# Escape-family calls that, if present on the same line as a source+sink,
# strongly suggest the value was sanitised before hitting the sink. We can't
# prove it (no AST), but we can DOWNGRADE HIGH -> MEDIUM to avoid the obvious
# false positive. Keys are per-language; JS/C# have their own list.
PHP_ESCAPES = re.compile(
    r'\b(?:htmlspecialchars|htmlentities|esc_html|esc_attr|esc_url|esc_js|'
    r'strip_tags|filter_var)\s*\(')
JS_ESCAPES = re.compile(
    r'\b(?:DOMPurify\.sanitize|sanitizeHtml|encodeURIComponent|encodeURI|'
    r'escapeHtml|textContent\s*=)')
CS_ESCAPES = re.compile(
    r'\b(?:HtmlEncoder\.(?:Default\.)?Encode|Html\.Encode|HttpUtility\.'
    r'HtmlEncode|WebUtility\.HtmlEncode|@\s*Html\.Encode)\s*\(')
JAVA_ESCAPES = re.compile(
    r'\b(?:StringEscapeUtils\.(?:escapeHtml|escapeHtml3|escapeHtml4|escapeXml)|'
    r'HtmlUtils\.htmlEscape|Encode\.forHtml(?:Attribute|Content)?|'
    r'ESAPI\.encoder\(\)\.encodeForHTML|SafeString|escapeHtml)\s*\(')
PY_ESCAPES = re.compile(
    r'\b(?:html\.escape|markupsafe\.escape|escape|bleach\.clean|'
    r'django\.utils\.html\.escape|escape_html|nh3\.clean|xml\.sax\.saxutils\.escape)\s*\(')
CONF_RANK = {"low": 0, "medium": 1, "high": 2}
JS_EXT = (".js", ".ts", ".jsx", ".tsx", ".mjs")
CS_EXT = (".cs", ".cshtml", ".razor")
PHP_EXT = (".php", ".phtml", ".php3", ".php4", ".php5", ".phps", ".inc")
JAVA_EXT = (".java", ".jsp", ".jspx", ".tag")
PY_EXT   = (".py", ".pyw")


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


# v3.8 cross-method sanitizer awareness. If a RHS contains a call to any
# name that "looks like" a sanitizer / escape / validate helper (either an
# OWASP-standard one or a local `sanitize(...)` / `cleanInput(...)` /
# `validateXxx(...)` helper), we treat that assignment as breaking the taint
# chain. This is a heuristic (no AST, no follow-into) - matches the exact
# hotel-platform case where CorrelationIdFilter does
#   String cid = ... ? sanitize(inbound) : shortUuid();
# and the older gate had no way to see `sanitize()`. Aggressive: any such
# call in the RHS kills the propagation for THAT line. Conservative: if the
# name doesn't match the hint pattern, taint still flows.
_SANITIZE_HINT = re.compile(
    r'\b\w*(?:sanitiz|clean|validat|escape|escap|htmlspecial|'
    r'strip|filter|encode|purif|Markup|SafeString|bleach|nh3|'
    r'StringEscapeUtils|HtmlUtils|Encode\.forHtml|markupsafe\.escape|'
    r'html\.escape|HtmlEncoder|WebUtility\.HtmlEncode|HttpUtility\.HtmlEncode)'
    r'\w*\s*\(',
    re.IGNORECASE,
)


def _joined_for_taint(lines, terminator=";", max_join=8):
    """Return a list the same length as `lines`. Each entry is the original
    line concatenated with continuation lines up to the next `terminator`
    (default `;`). Preserves indexing so tainted-set computation sees complete
    multi-line statements (Java/C# ternaries, long argument lists) without
    breaking scan_file's per-line reporting. v3.8 addition - needed to catch
    the exact hotel-platform shape:
        String cid = (inbound != null && ...)
                ? sanitize(inbound)
                : shortUuid();
    which otherwise splits across 3 lines and hides the sanitize()."""
    joined = list(lines)
    for i, line in enumerate(lines):
        s = line.strip()
        # already terminated on this line, or a block delimiter, or empty
        if terminator in line or not s or s.endswith(("{", "}")) or s.startswith(("//", "#")):
            continue
        buf = line
        for k in range(1, max_join + 1):
            if i + k >= len(lines):
                break
            nxt = lines[i + k]
            buf = buf + " " + nxt.strip()
            if terminator in nxt:
                break
        joined[i] = buf
    return joined


def compute_taint(lines, sources, msg_active, assign_re=ASSIGN):
    """A var is tainted if assigned from a source or another tainted var.
    Bounded fix-point - a cheap approximation of straight-line data flow.
    Runs on JS, PHP, Java, Python (each with its own assign regex).

    v3.8: if the RHS contains a sanitize-family call (`sanitize(...)`,
    `clean(...)`, `StringEscapeUtils.escapeHtml4(...)`, `html.escape(...)`,
    local `validateXxx(...)`, ...), the assignment BREAKS the taint chain.
    This kills the cross-method-helper false positive that pure same-line
    regex analysis can't otherwise see."""
    tainted = set()
    for _ in range(6):
        changed = False
        for line in lines:
            m = assign_re.match(line)
            if not m:
                continue
            lhs, rhs = m.group(1), m.group(2)
            # cross-method sanitizer wrap -> do not propagate taint
            if _SANITIZE_HINT.search(rhs):
                continue
            if source_hits(rhs, sources, msg_active) or any(
                re.search(r'(?<!\w)' + re.escape(v) + r'\b', rhs) for v in tainted
            ):
                if lhs not in tainted:
                    tainted.add(lhs)
                    changed = True
        if not changed:
            break
    return tainted


def _lang_for(path):
    """Return (lang, sinks, sources, assign_re, wants_taint). lang is one of
    'js', 'cs', 'php', 'java', 'py'; wants_taint tells scan_file whether to run
    compute_taint (JS+PHP+Java+Python yes, C# no - stays sink-only)."""
    ext = os.path.splitext(path)[1].lower()
    if ext in JS_EXT:
        return "js", JS_SINKS, JS_SOURCES, ASSIGN, True
    if ext in PHP_EXT:
        return "php", PHP_SINKS, PHP_SOURCES, PHP_ASSIGN, True
    if ext in JAVA_EXT:
        return "java", JAVA_SINKS, JAVA_SOURCES, JAVA_ASSIGN, True
    if ext in PY_EXT:
        return "py", PY_SINKS, PY_SOURCES, PYTHON_ASSIGN, True
    return "cs", CS_SINKS, CS_SOURCES, ASSIGN, False


def scan_file(path):
    lang, sinks, sources, assign_re, wants_taint = _lang_for(path)

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.read().split("\n")
    except OSError:
        return []

    msg_active = lang == "js" and bool(MSG_LISTENER.search("\n".join(lines)))
    # Java/C# statements often span lines (ternaries, long argument lists,
    # generic types); join by `;` before taint so multi-line sanitize()
    # wraps are visible. JS/PHP/Python usually single-line - default OK.
    taint_view = _joined_for_taint(lines) if lang in ("java", "cs") else lines
    tainted = (compute_taint(taint_view, sources, msg_active, assign_re)
               if wants_taint else set())
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
            tvars = [v for v in tainted
                     if re.search(r'(?<!\w)' + re.escape(v) + r'\b', line)]
            if srcs or tvars:
                confidence = "high"
            elif dynamic.search(line.split("//", 1)[0]):
                confidence = "medium"
            else:
                confidence = "low"
            # False-positive squelch: if an escape-family call appears on the
            # same line as the sink AND close to it (within ~200 chars, i.e.
            # plausibly wrapping the sink's value), downgrade HIGH -> MEDIUM.
            # Proximity matters - on a minified single-line blob a stray
            # `encodeURIComponent` far away from the sink says nothing about
            # THIS sink's value. Long lines (> 500 chars, i.e. minified) skip
            # the squelch entirely: they need eyes-on review anyway.
            if confidence == "high" and len(line) <= 500:
                esc_re = (PHP_ESCAPES if lang == "php"
                          else JAVA_ESCAPES if lang == "java"
                          else PY_ESCAPES if lang == "py"
                          else JS_ESCAPES if lang == "js" else CS_ESCAPES)
                sink_pos = rx.search(line).start()
                for em in esc_re.finditer(line):
                    if abs(em.start() - sink_pos) <= 200:
                        confidence = "medium"
                        break
            findings.append({
                "file": path, "line": lineno, "sink": sid, "lang": lang,
                "severity": severity, "confidence": confidence, "description": desc,
                "code": line.strip()[:200], "sources": srcs, "tainted_vars": tvars,
            })
    return findings


def iter_files(target):
    if os.path.isfile(target):
        yield target
        return
    for root, _, files in os.walk(target):
        if "node_modules" in root or "vendor" in root or os.sep + ".git" in root:
            continue
        for name in files:
            if name.endswith(JS_EXT + CS_EXT + PHP_EXT + JAVA_EXT + PY_EXT):
                yield os.path.join(root, name)


def render_html(findings, target):
    """Self-contained HTML report - no external assets, safe to open/share."""
    def esc(s):
        return html.escape(str(s))

    color = {"high": "#f85149", "medium": "#d29922", "low": "#8b949e"}
    total = len(findings)
    highs = sum(1 for f in findings if f["confidence"] == "high")
    langs = sorted({f["lang"] for f in findings})

    rows = []
    for f in findings:
        if f["sources"]:
            flow = "source: " + esc(", ".join(f["sources"]))
        elif f["tainted_vars"]:
            flow = "tainted: " + esc(", ".join(f["tainted_vars"]))
        else:
            flow = "<span class='muted'>-</span>"
        rows.append(
            "<tr>"
            f"<td><span class='badge' style='background:{color[f['severity']]}'>{esc(f['severity'].upper())}</span></td>"
            f"<td><span class='badge' style='background:{color[f['confidence']]}'>{esc(f['confidence'])}</span></td>"
            f"<td class='mono'>{esc(f['lang'])}</td>"
            f"<td class='mono'>{esc(f['sink'])}</td>"
            f"<td class='mono muted'>{esc(f['file'])}:{f['line']}</td>"
            f"<td class='mono'>{flow}</td>"
            f"<td><code>{esc(f['code'])}</code><div class='desc'>{esc(f['description'])}</div></td>"
            "</tr>"
        )

    return f"""<!doctype html>
<meta charset="utf-8">
<title>dxa report - {esc(target)}</title>
<style>
 body{{font-family:system-ui,Arial,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:28px}}
 h1{{font-size:20px;margin:0 0 4px}} .sub{{color:#8b949e;font-size:13px;margin-bottom:20px}}
 .stats{{display:flex;gap:14px;margin-bottom:22px;flex-wrap:wrap}}
 .stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px 16px;min-width:90px}}
 .stat .n{{font-size:22px;font-weight:700}} .stat .l{{color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:.5px}}
 table{{width:100%;border-collapse:collapse;font-size:13px}}
 th,td{{text-align:left;padding:9px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
 th{{color:#8b949e;text-transform:uppercase;font-size:11px;letter-spacing:.5px}}
 .badge{{color:#0d1117;font-weight:700;font-size:11px;padding:2px 8px;border-radius:10px;text-transform:uppercase}}
 .mono{{font-family:ui-monospace,Consolas,monospace}} .muted{{color:#8b949e}}
 code{{font-family:ui-monospace,Consolas,monospace;color:#79c0ff;word-break:break-all}}
 .desc{{color:#8b949e;font-size:12px;margin-top:3px}}
 footer{{color:#8b949e;font-size:12px;margin-top:22px}}
</style>
<h1>dxa - source&rarr;sink XSS report</h1>
<div class="sub">target: <span class="mono">{esc(target)}</span></div>
<div class="stats">
 <div class="stat"><div class="n">{total}</div><div class="l">findings</div></div>
 <div class="stat"><div class="n" style="color:{color['high']}">{highs}</div><div class="l">high confidence</div></div>
 <div class="stat"><div class="n">{esc(', '.join(langs)) or '-'}</div><div class="l">languages</div></div>
</div>
<table>
 <tr><th>severity</th><th>confidence</th><th>lang</th><th>sink</th><th>location</th><th>flow</th><th>code</th></tr>
 {''.join(rows) if rows else "<tr><td colspan=7 class='muted'>No findings at the chosen confidence.</td></tr>"}
</table>
<footer>Generated by dxa - a heuristic source&rarr;sink linter. Confirm each HIGH finding by hand.</footer>
"""


def main():
    ap = argparse.ArgumentParser(description="source-to-sink XSS analyzer (JS + C#/.NET)")
    ap.add_argument("target", help="file or directory to scan")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    ap.add_argument("--html", metavar="FILE", help="write a self-contained HTML report to FILE")
    ap.add_argument("--min-confidence", choices=["low", "medium", "high"],
                    default="low", help="hide findings below this confidence")
    args = ap.parse_args()

    floor = CONF_RANK[args.min_confidence]
    findings = []
    for f in iter_files(args.target):
        findings.extend(scan_file(f))
    findings = [f for f in findings if CONF_RANK[f["confidence"]] >= floor]
    findings.sort(key=lambda f: (-CONF_RANK[f["confidence"]], f["file"], f["line"]))

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(findings, args.target))
        print(f"HTML report written to {args.html}  ({len(findings)} finding(s))")
        sys.exit(1 if findings else 0)

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
