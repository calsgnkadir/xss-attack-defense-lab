"""Tests for dxa2dyn (static -> dynamic bridge). Run: pytest -q"""

import html
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import dxa2dyn
import dxadyn


HERE = os.path.dirname(os.path.abspath(__file__))
EX = os.path.join(HERE, "examples")


# --- hint extraction --------------------------------------------------------

def _f(code, sources=(), confidence="high"):
    return {"code": code, "sources": list(sources), "confidence": confidence}


def test_extract_param_hints_matches_common_patterns():
    findings = [
        _f("const q = req.query.q;"),
        _f("const s = request.form['search'];"),
        _f('var name = Request.QueryString["name"];'),
        _f("const t = new URLSearchParams(location.search).get('token');"),
        _f("var v = $_GET['keyword'];"),
    ]
    hints = dxa2dyn.extract_param_hints(findings)
    assert set(hints) >= {"q", "search", "name", "token", "keyword"}


def test_extract_param_hints_skips_low_confidence():
    findings = [
        _f("const q = req.query.q;", confidence="low"),
        _f("const s = req.query.s;", confidence="medium"),
    ]
    assert dxa2dyn.extract_param_hints(findings) == []


def test_extract_param_hints_filters_stopwords():
    findings = [_f("const b = req.body;"), _f("var u = req.url;")]
    assert dxa2dyn.extract_param_hints(findings) == []


def test_run_dxa_on_examples_returns_high_findings():
    findings = dxa2dyn.run_dxa(EX)
    assert findings, "dxa should return HIGH findings on the seeded examples/"
    # The bundled examples/vulnerable.js reads URLSearchParams(...).get('q')
    # so 'q' should be one of the extractable hints.
    assert "q" in dxa2dyn.extract_param_hints(findings)


# --- end-to-end: bridge finds a reflected param that dxa hinted -------------

class _HintReflector(BaseHTTPRequestHandler):
    """Two params: 'q' echoes raw (vulnerable), 'safe' HTML-escapes."""
    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        params = parse_qs(u.query)
        q = params.get("q", [""])[0]
        s = params.get("safe", [""])[0]
        body = f"<div>{q}</div><span>{html.escape(s)}</span>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


def test_probe_hints_flags_raw_param_and_ignores_escaped():
    dxadyn.EXTRA_HEADERS.clear()
    dxadyn.OPENER = dxadyn._opener()
    srv = HTTPServer(("127.0.0.1", 0), _HintReflector)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        findings = dxa2dyn.probe_hints(f"http://127.0.0.1:{port}/", ["q", "safe"])
    finally:
        srv.shutdown()
    flagged = {(f["param"], f["reflection"]) for f in findings}
    assert ("q", "unencoded") in flagged
    assert not any(p == "safe" for p, _ in flagged)
