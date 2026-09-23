"""Tests for dxadyn (dynamic reflection verifier). Run from this directory: pytest -q

Covers the detection core (raw vs encoded vs absent), input discovery, and one
end-to-end run against a throwaway local reflector that echoes one field raw
(vulnerable) and one HTML-escaped (safe) - proving dxadyn flags the first and
ignores the second, with no false positive on the encoded one.
"""

import html
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import dxadyn


# --- detection core ---------------------------------------------------------

def test_verdict_unencoded():
    assert dxadyn.verdict("dxaAAAA", 'x dxaAAAA"<dXsS> y') == "unencoded"


def test_verdict_unencoded_even_if_quote_encoded():
    # the tag survived raw even though the quote was escaped -> still HTML injection
    assert dxadyn.verdict("dxaAAAA", 'x dxaAAAA&quot;<dXsS> y') == "unencoded"


def test_verdict_encoded_is_safe():
    assert dxadyn.verdict("dxaBBBB", 'x dxaBBBB&quot;&lt;dXsS&gt; y') == "encoded"


def test_verdict_attr_only_quote_breakout():
    assert dxadyn.verdict("dxaDDDD", 'value="dxaDDDD" more') == "attr-only"


def test_verdict_absent():
    assert dxadyn.verdict("dxaCCCC", "nothing reflected here") == "absent"


def test_make_canary_is_unique_and_shaped():
    c1, v1 = dxadyn.make_canary()
    c2, v2 = dxadyn.make_canary()
    assert c1.startswith("dxa") and c1 != c2
    assert c1 in v1 and dxadyn.MARKUP in v1


# --- input discovery --------------------------------------------------------

def test_discover_finds_form_and_param_link():
    body = ('<form action="/r" method="get"><input name="q"></form>'
            '<a href="/x?id=1&amp;y=2">l</a>')
    forms, links = dxadyn.discover("http://h/", body)
    assert forms and forms[0]["action"].endswith("/r")
    assert forms[0]["method"] == "get" and "q" in forms[0]["fields"]
    assert any("id=1" in l for l in links)


def test_discover_skips_submit_buttons():
    body = '<form action="/a"><input name="q"><input type="submit" name="go"></form>'
    forms, _ = dxadyn.discover("http://h/", body)
    assert "q" in forms[0]["fields"] and "go" not in forms[0]["fields"]


# --- end-to-end against a throwaway reflector -------------------------------

_INDEX = ('<form action="/r" method="get"><input name="q"></form>'
          '<form action="/rs" method="get"><input name="q"></form>')


class _Reflector(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query).get("q", [""])[0]
        if u.path == "/r":
            body = f"<div>{q}</div>"                    # RAW echo = vulnerable
        elif u.path == "/rs":
            body = f"<div>{html.escape(q)}</div>"       # escaped = safe
        else:
            body = _INDEX
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


def test_end_to_end_flags_raw_not_escaped():
    srv = HTTPServer(("127.0.0.1", 0), _Reflector)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        findings = dxadyn.crawl(f"http://127.0.0.1:{port}/", 0)
    finally:
        srv.shutdown()

    flagged = {(f["url"].rsplit("/", 1)[1], f["reflection"]) for f in findings}
    assert ("r", "unencoded") in flagged          # the raw form is caught
    assert not any(url == "rs" for url, _ in flagged)   # the escaped form is not


# --- v2: auth + stored ------------------------------------------------------

def test_parse_kv_list():
    assert dxadyn._parse_kv_list("a=1,b=hi,c=") == {"a": "1", "b": "hi", "c": ""}
    assert dxadyn._parse_kv_list("") == {}
    # invalid pairs (no =) are skipped, not crashed on
    assert dxadyn._parse_kv_list("bogus,a=1") == {"a": "1"}


def test_extract_csrf_both_orders():
    body_a = '<input type="hidden" name="tokenCSRF" value="abc123">'
    body_b = '<input type="hidden" value="xyz789" name="tokenCSRF">'
    assert dxadyn._extract_csrf(body_a, "tokenCSRF") == "abc123"
    assert dxadyn._extract_csrf(body_b, "tokenCSRF") == "xyz789"
    assert dxadyn._extract_csrf("no token here", "tokenCSRF") is None


# --- End-to-end: stored XSS through an authenticated form -------------------
# Fixture mirrors the Bludit-shaped flow (in miniature): a login-protected
# /new POST stores a `tags` value; the public /view/<id> page renders it RAW
# (vulnerable), the /viewsafe/<id> page HTML-escapes it (safe). dxadyn --stored
# with --login must flag the raw view and skip the escaped one.

_TAGS_DB = {}
_TAGS_COOKIE = "dxa_session=ok"


def _sluggy(s):
    import re as _re
    return _re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-') or "x"


class _StoredApp(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _authed(self):
        return _TAGS_COOKIE in (self.headers.get("Cookie") or "")

    def _send(self, code, body, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        if extra:
            for k, v in extra:
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/login":
            body = ('<form method="post" action="/login">'
                    '<input type="hidden" name="tokenCSRF" value="TOK123">'
                    '<input name="username"><input name="password">'
                    '<input type="submit"></form>')
            return self._send(200, body)
        if p.path == "/new":
            if not self._authed():
                return self._send(403, "login required")
            body = ('<form method="post" action="/new">'
                    '<input type="hidden" name="tokenCSRF" value="TOK123">'
                    '<input name="title"><input name="tags"><input type="submit"></form>')
            return self._send(200, body)
        if p.path.startswith("/view/"):
            key = p.path.split("/", 2)[2]
            return self._send(200, f"<h1>tag: {_TAGS_DB.get(key, '(none)')}</h1>")   # RAW
        if p.path.startswith("/viewsafe/"):
            key = p.path.split("/", 2)[2]
            return self._send(200, f"<h1>tag: {html.escape(_TAGS_DB.get(key, ''))}</h1>")
        return self._send(404, "nope")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        fields = parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        if self.path == "/login":
            u = fields.get("username", [""])[0]
            p = fields.get("password", [""])[0]
            if u == "admin" and p == "labpass" and \
                    fields.get("tokenCSRF", [""])[0] == "TOK123":
                return self._send(302, "", extra=[("Location", "/dashboard"),
                                                  ("Set-Cookie", _TAGS_COOKIE + "; Path=/")])
            return self._send(401, "no")
        if self.path == "/new":
            if not self._authed() or fields.get("tokenCSRF", [""])[0] != "TOK123":
                return self._send(403, "csrf/auth")
            tag = fields.get("tags", [""])[0]
            _TAGS_DB[_sluggy(tag)] = tag
            return self._send(302, "", extra=[("Location", "/dashboard")])
        return self._send(404, "nope")


# --- v3.1: cookie / header injection ----------------------------------------

class _EchoHeaders(BaseHTTPRequestHandler):
    """Reflects the incoming Cookie + selected headers so tests can assert them."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        cookie = self.headers.get("Cookie") or ""
        bearer = self.headers.get("Authorization") or ""
        csrf = self.headers.get("X-CSRF-Token") or ""
        body = f"cookie={cookie}|auth={bearer}|csrf={csrf}"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body.encode())


def test_apply_cookie_rides_every_request():
    dxadyn.EXTRA_HEADERS.clear()
    dxadyn.apply_cookie("sid=abc123; csrf=xyz")
    srv = HTTPServer(("127.0.0.1", 0), _EchoHeaders)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        _, _, body = dxadyn.fetch(f"http://127.0.0.1:{port}/anywhere")
    finally:
        srv.shutdown()
        dxadyn.EXTRA_HEADERS.clear()
    assert "cookie=sid=abc123; csrf=xyz" in body


def test_apply_header_parses_name_value_and_rejects_junk():
    dxadyn.EXTRA_HEADERS.clear()
    assert dxadyn.apply_header("Authorization: Bearer eyJabc.def")
    assert dxadyn.apply_header("X-CSRF-Token: tok-42")
    assert not dxadyn.apply_header("no-colon-here")
    assert not dxadyn.apply_header(": nokey")
    srv = HTTPServer(("127.0.0.1", 0), _EchoHeaders)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        _, _, body = dxadyn.fetch(f"http://127.0.0.1:{port}/")
    finally:
        srv.shutdown()
        dxadyn.EXTRA_HEADERS.clear()
    assert "auth=Bearer eyJabc.def" in body
    assert "csrf=tok-42" in body


# --- v3.3 bonus: header-injection probe (Bludit Finding #8 shape) -----------

class _HeaderEcho(BaseHTTPRequestHandler):
    """Echoes X-Forwarded-For raw (vuln), Referer HTML-escaped (safe)."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        xff = self.headers.get("X-Forwarded-For", "")
        ref = self.headers.get("Referer", "")
        body = f"<p>ip={xff}</p><p>ref={html.escape(ref)}</p>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


def test_probe_headers_flags_raw_and_ignores_escaped():
    dxadyn.EXTRA_HEADERS.clear()
    dxadyn.OPENER = dxadyn._opener()
    srv = HTTPServer(("127.0.0.1", 0), _HeaderEcho)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        findings = dxadyn.probe_headers(
            f"http://127.0.0.1:{port}/", ["X-Forwarded-For", "Referer"])
    finally:
        srv.shutdown()
    flagged = {(f["param"], f["reflection"]) for f in findings}
    assert ("header:X-Forwarded-For", "unencoded") in flagged
    assert not any(p == "header:Referer" for p, _ in flagged)


def test_probe_headers_leaves_no_lingering_headers():
    """Regression: EXTRA_HEADERS must not keep the last canary header set."""
    dxadyn.EXTRA_HEADERS.clear()
    dxadyn.OPENER = dxadyn._opener()
    srv = HTTPServer(("127.0.0.1", 0), _HeaderEcho)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        dxadyn.probe_headers(f"http://127.0.0.1:{port}/", ["X-Forwarded-For"])
    finally:
        srv.shutdown()
    assert "X-Forwarded-For" not in dxadyn.EXTRA_HEADERS


# --- v3.6: PUT/PATCH/DELETE method support ----------------------------------

class _MethodEcho(BaseHTTPRequestHandler):
    """Records the request method + JSON body for the last request; responds
    with a page that reflects whatever was sent so verdict can grade."""
    last = {"method": None, "body": None, "path": None}
    def log_message(self, *a):
        pass
    def _handle(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode() if length else ""
        self.__class__.last = {"method": self.command, "body": raw,
                               "path": self.path}
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        # echo raw body inside <body> so verdict + context detection can run
        self.wfile.write(f"<body>echoed: {raw}</body>".encode())
    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle


def test_fetch_supports_put_and_delete_methods():
    dxadyn.EXTRA_HEADERS.clear()
    dxadyn.OPENER = dxadyn._opener()
    srv = HTTPServer(("127.0.0.1", 0), _MethodEcho)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        dxadyn.fetch(f"http://127.0.0.1:{port}/x", data=b"raw", method="PUT")
        assert _MethodEcho.last["method"] == "PUT"
        assert _MethodEcho.last["body"] == "raw"
        dxadyn.fetch(f"http://127.0.0.1:{port}/x", data=b"", method="DELETE")
        assert _MethodEcho.last["method"] == "DELETE"
    finally:
        srv.shutdown()


def test_submit_json_uses_put_when_asked():
    dxadyn.EXTRA_HEADERS.clear()
    dxadyn.OPENER = dxadyn._opener()
    srv = HTTPServer(("127.0.0.1", 0), _MethodEcho)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # Call _submit_json directly so we can inspect the method it dispatched
        # (going through probe_stored would follow up with a GET check that
        # would overwrite _MethodEcho.last).
        st, _ = dxadyn._submit_json(
            f"http://127.0.0.1:{port}/api/thing",
            '{"name":"{CANARY}"}', "dxaTEST", method="PUT")
    finally:
        srv.shutdown()
    assert _MethodEcho.last["method"] == "PUT"
    assert '"name":"dxaTEST"' in _MethodEcho.last["body"]


def test_submit_form_dispatches_patch():
    dxadyn.EXTRA_HEADERS.clear()
    dxadyn.OPENER = dxadyn._opener()
    srv = HTTPServer(("127.0.0.1", 0), _MethodEcho)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        st, _ = dxadyn._submit_form(
            f"http://127.0.0.1:{port}/api/thing", "name",
            {}, "dxaTEST", method="PATCH", csrf_field="")
    finally:
        srv.shutdown()
    assert _MethodEcho.last["method"] == "PATCH"
    assert "name=dxaTEST" in _MethodEcho.last["body"]


# --- v3.5: sink-context awareness + dedup -----------------------------------

def test_find_context_body_is_free_markup():
    body = "<html><body><div>xxx dxaAAAA\"<dXsS> yyy</div></body></html>"
    assert dxadyn.find_context("dxaAAAA", body) == "body"


def test_find_context_title_needs_breakout():
    body = "<html><head><title>results for dxaAAAA\"<dXsS></title>rest</head>"
    assert dxadyn.find_context("dxaAAAA", body) == "title"


def test_find_context_script_context():
    body = '<html><head><script>var q = "dxaAAAA\\"<dXsS>";</script></head>'
    assert dxadyn.find_context("dxaAAAA", body) == "script"


def test_find_context_url_attribute():
    body = '<html><body><a href="/search?q=dxaAAAA">l</a></body></html>'
    assert dxadyn.find_context("dxaAAAA", body) == "url-attr:href"


def test_find_context_generic_attribute():
    body = '<html><body><input type="text" value="dxaAAAA"></body></html>'
    assert dxadyn.find_context("dxaAAAA", body) == "attr:value"


def test_context_executes_only_body_and_unknown():
    assert dxadyn.context_executes("body")
    assert dxadyn.context_executes("unknown")
    assert not dxadyn.context_executes("title")
    assert not dxadyn.context_executes("script")
    assert not dxadyn.context_executes("attr:value")
    assert not dxadyn.context_executes("url-attr:href")


def test_severity_labels():
    assert dxadyn._severity("unencoded", "body") == "executable"
    assert dxadyn._severity("unencoded", "title") == "breakout-req"
    assert dxadyn._severity("unencoded", "attr:value") == "breakout-req"
    assert dxadyn._severity("attr-only", "body") == "attr-breakout"
    assert dxadyn._severity("encoded", "body") == "-"


def test_dedupe_collapses_same_bug_across_pages():
    findings = [
        {"canary_id": "dxaXX", "reflection": "unencoded", "context": "body",
         "check_url": "http://x/a", "confidence": "high"},
        {"canary_id": "dxaXX", "reflection": "unencoded", "context": "body",
         "check_url": "http://x/b", "confidence": "high"},
        {"canary_id": "dxaXX", "reflection": "unencoded", "context": "body",
         "check_url": "http://x/c", "confidence": "high"},
        {"canary_id": "dxaYY", "reflection": "attr-only", "context": "attr:value",
         "check_url": "http://x/other", "confidence": "medium"},
    ]
    out = dxadyn.dedupe_findings(findings)
    assert len(out) == 2                          # 2 unique bugs
    body_bug = next(f for f in out if f["canary_id"] == "dxaXX")
    assert body_bug["check_url"] == "http://x/a"  # first kept
    assert body_bug["duplicates"] == ["http://x/b", "http://x/c"]


def test_dedupe_leaves_singletons_alone():
    findings = [{"canary_id": "dxaXX", "reflection": "unencoded",
                 "context": "body", "check_url": "http://x/a"}]
    out = dxadyn.dedupe_findings(findings)
    assert out == findings                        # unchanged


# --- HTML report ------------------------------------------------------------

def test_render_html_empty_produces_valid_page():
    out = dxadyn.render_html([], "http://x/", "reflected", {"depth": "0"})
    assert "<title>dxadyn report" in out
    assert "No unencoded reflections found" in out
    assert "http://x/" in out


def test_render_html_with_findings_shows_row_and_badges():
    findings = [
        {"url": "http://x/", "method": "GET", "param": "q",
         "reflection": "unencoded", "confidence": "high", "status": 200,
         "origin": "reflected"},
        {"check_url": "http://x/tag/z", "field": "tags",
         "reflection": "attr-only", "confidence": "medium",
         "sub_status": 200, "check_status": 200, "auto_discovered": True},
    ]
    out = dxadyn.render_html(findings, "http://x/", "stored-auto",
                             {"canary_id": "dxa12345"})
    assert "unencoded" in out and "attr-only" in out
    assert "reflected" in out and "stored-auto" in out
    assert "dxa12345" in out
    # header row and both data rows
    assert out.count("<tr>") >= 3


# --- v3.4: JSON body + stored header target ---------------------------------

_V34_DB = {"json": None, "hdr": None}


class _V34App(BaseHTTPRequestHandler):
    """Two 'stored' surfaces:
      POST /api/tags {"tags": "..."}  stores json -> renders RAW on /viewj
      GET /  with X-Forwarded-Fake header  stores hdr -> renders RAW on /viewh
    """
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/log":
            xff = self.headers.get("X-Forwarded-Fake")
            if xff:
                _V34_DB["hdr"] = xff
            return self._send(200, "logged")
        if p.path == "/viewj":
            return self._send(200, f"<h1>tag: {_V34_DB['json']}</h1>")
        if p.path == "/viewh":
            return self._send(200, f"<p>lastIP: {_V34_DB['hdr']}</p>")
        if p.path == "/":
            return self._send(200, '<a href="/viewj">j</a><a href="/viewh">h</a>')
        return self._send(404, "?")

    def do_POST(self):
        import json as _json
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode()
        if self.path == "/api/tags":
            try:
                obj = _json.loads(raw)
                _V34_DB["json"] = obj.get("tags")
                return self._send(200, "{\"ok\":true}", "application/json")
            except Exception:                                # noqa: BLE001
                return self._send(400, "bad json")
        return self._send(404, "?")


def test_submit_json_stores_canary_and_view_reflects_raw():
    _V34_DB["json"] = None
    dxadyn.EXTRA_HEADERS.clear()
    dxadyn.OPENER = dxadyn._opener()
    srv = HTTPServer(("127.0.0.1", 0), _V34App)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        findings, cid = dxadyn.probe_stored(
            f"http://127.0.0.1:{port}/api/tags", target_field="",
            extra_fields={}, check_urls=[f"http://127.0.0.1:{port}/viewj"],
            json_body='{"tags":"{CANARY}"}', csrf_field="")
    finally:
        srv.shutdown()
    assert findings, "json-body stored XSS must be detected via /viewj"
    assert findings[0]["reflection"] == "unencoded"
    assert findings[0]["field"] == "json"
    assert _V34_DB["json"] == cid + '"<dXsS>'


def test_submit_header_target_stores_canary_and_view_reflects():
    _V34_DB["hdr"] = None
    dxadyn.EXTRA_HEADERS.clear()
    dxadyn.OPENER = dxadyn._opener()
    srv = HTTPServer(("127.0.0.1", 0), _V34App)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        findings, cid = dxadyn.probe_stored(
            f"http://127.0.0.1:{port}/log", target_field="",
            extra_fields={}, check_urls=[f"http://127.0.0.1:{port}/viewh"],
            method="get", header_target="X-Forwarded-Fake", csrf_field="")
    finally:
        srv.shutdown()
    assert findings, "header-target stored XSS must be detected via /viewh"
    assert findings[0]["reflection"] == "unencoded"
    assert findings[0]["field"] == "header:X-Forwarded-Fake"
    # header must not leak into EXTRA_HEADERS after the submit
    assert "X-Forwarded-Fake" not in dxadyn.EXTRA_HEADERS


def test_submit_json_escapes_quote_in_canary_correctly():
    """The canary contains a raw `"` — the json_body template must remain
    valid JSON after {CANARY} substitution."""
    tmpl = '{"tags":"{CANARY}"}'
    fake_cid = 'dxa12345678'
    fake_canary = fake_cid + '"<dXsS>'
    # simulate what _submit_json does internally
    safe = tmpl.replace("{CANARY}", fake_canary
        .replace("\\", "\\\\").replace('"', '\\"'))
    import json as _json
    obj = _json.loads(safe)                                  # must not raise
    assert obj["tags"] == fake_canary


# --- v3.2: auto-discover (crawl-after-submit) -------------------------------

_AUTO_DB = {}


class _AutoApp(BaseHTTPRequestHandler):
    """Bludit-shaped: POST /post stores by slug; homepage has a link to
    /tag/<slug> which renders the stored value raw. Auto-check must find it
    from the homepage crawl - no explicit --check URL given."""
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        p = urlparse(self.path)
        if p.path == "/":
            links = "".join(f'<a href="/tag/{k}">{k}</a> ' for k in _AUTO_DB)
            return self._send(200, f"<html><body>home {links}</body></html>")
        if p.path == "/post":
            return self._send(200, '<form method="post" action="/post">'
                                   '<input name="tag"><input type="submit"></form>')
        if p.path.startswith("/tag/"):
            key = p.path.split("/", 2)[2]
            return self._send(200, f"<h1>tag: {_AUTO_DB.get(key, '(?)')}</h1>")
        return self._send(404, "nope")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        fields = parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        if self.path == "/post":
            tag = fields.get("tag", [""])[0]
            key = _sluggy(tag)
            _AUTO_DB[key] = tag                              # store raw
            return self._send(200, f"stored key={key}")
        return self._send(404, "nope")


def test_auto_check_discovers_and_flags_stored_reflection():
    _AUTO_DB.clear()
    dxadyn.OPENER = dxadyn._opener()
    dxadyn.EXTRA_HEADERS.clear()
    srv = HTTPServer(("127.0.0.1", 0), _AutoApp)
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        findings, cid, meta = dxadyn.probe_stored_auto(
            base + "/post", "tag", extra_fields={},
            seed_urls=[base + "/"], csrf_field=""     # this fixture has no CSRF
        )
    finally:
        srv.shutdown()

    # exactly one page (the /tag/<slug>) should carry the canary raw
    assert findings, "auto-check must locate the /tag page carrying the canary"
    assert findings[0]["reflection"] == "unencoded"
    assert "/tag/" in findings[0]["check_url"]
    assert findings[0]["auto_discovered"] is True
    assert meta["candidates"] >= 2                            # home + at least the tag page


def test_all_links_skips_junk_and_dedupes():
    body = '<a href="/a">A</a><a href="/a">A2</a><a href="mailto:x">M</a>' \
           '<a href="javascript:1">J</a><a href="#top">T</a><a href="/b?x=1">B</a>'
    got = dxadyn._all_links("http://h/", body)
    assert got == ["http://h/a", "http://h/b?x=1"]


def test_stored_mode_auth_and_verdict():
    _TAGS_DB.clear()
    # fresh cookie jar per test so state doesn't bleed
    dxadyn.OPENER = dxadyn._opener()
    srv = HTTPServer(("127.0.0.1", 0), _StoredApp)
    port = srv.server_address[1]
    base = f"http://127.0.0.1:{port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ok = dxadyn.login(base + "/login", "admin", "wrongpw")
        assert not ok, "wrong password must not authenticate"
        ok = dxadyn.login(base + "/login", "admin", "labpass")
        assert ok, "correct credentials should authenticate on the fixture"

        # RAW view page: must flag unencoded
        findings, cid = dxadyn.probe_stored(
            base + "/new", "tags",
            extra_fields={"title": "t"},
            check_urls=[base + "/view/{CID}-dxss"],
        )
        assert findings, "stored XSS must be detected on the raw /view page"
        assert findings[0]["reflection"] == "unencoded"
        assert cid in findings[0]["check_url"]

        # SAFE view page: no finding
        findings2, _ = dxadyn.probe_stored(
            base + "/new", "tags",
            extra_fields={"title": "t"},
            check_urls=[base + "/viewsafe/{CID}-dxss"],
        )
        assert not findings2, "escaped page must not be flagged"
    finally:
        srv.shutdown()
