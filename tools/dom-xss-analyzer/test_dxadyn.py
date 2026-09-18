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
