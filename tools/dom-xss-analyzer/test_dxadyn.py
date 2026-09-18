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
