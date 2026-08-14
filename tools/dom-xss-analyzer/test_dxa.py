"""Tests for dxa. Run from this directory with:  pytest -q"""

import os

import dxa

HERE = os.path.dirname(os.path.abspath(__file__))
EX = os.path.join(HERE, "examples")


def scan(name):
    return dxa.scan_file(os.path.join(EX, name))


def by_sink(findings):
    grouped = {}
    for f in findings:
        grouped.setdefault(f["sink"], []).append(f)
    return grouped


# --- JavaScript detection ---------------------------------------------------

def test_js_innerhtml_from_tainted_var_is_high():
    f = by_sink(scan("vulnerable.js"))
    assert "innerHTML" in f
    assert any(x["confidence"] == "high" and "q" in x["tainted_vars"]
               for x in f["innerHTML"])


def test_js_eval_from_source_is_high():
    f = by_sink(scan("vulnerable.js"))
    assert "eval" in f
    assert any(x["confidence"] == "high" and x["sources"] for x in f["eval"])


def test_js_document_write_from_tainted_is_high():
    f = by_sink(scan("vulnerable.js"))
    assert any(x["confidence"] == "high" for x in f["document.write"])


def test_js_literal_innerhtml_is_not_high():
    """A constant-string sink must never be reported as a real flow."""
    f = by_sink(scan("vulnerable.js"))
    literals = [x for x in f["innerHTML"] if "welcome" in x["code"]]
    assert literals and all(x["confidence"] != "high" for x in literals)


def test_js_safe_file_has_no_high_confidence():
    assert all(x["confidence"] != "high" for x in scan("safe.js"))


# --- C# / ASP.NET & Razor detection -----------------------------------------

def test_cs_html_raw_with_request_source_is_high():
    f = by_sink(scan("vulnerable.cshtml"))
    assert "Html.Raw" in f
    assert any(x["confidence"] == "high" and "Request.Query" in x["sources"]
               for x in f["Html.Raw"])


def test_cs_server_sinks_detected():
    f = by_sink(scan("vulnerable.cs"))
    assert "Response.Write" in f
    assert "HtmlString" in f


# --- helper behaviour -------------------------------------------------------

def test_source_write_target_is_not_a_read():
    # `location.href = ...` is a sink target, not a source being read
    assert dxa.source_hits("location.href = next;", dxa.JS_SOURCES, False) == []
    # reading it *is* a source
    assert "location.href" in dxa.source_hits("var x = location.href;",
                                              dxa.JS_SOURCES, False)


def test_source_equality_is_still_a_read():
    # `==` / `===` must not be mistaken for an assignment
    assert "location.hash" in dxa.source_hits("if (location.hash === '#a') {}",
                                              dxa.JS_SOURCES, False)


def test_taint_propagates_across_assignments():
    lines = ["var a = location.hash;", "var b = a + '!';", "el.innerHTML = b;"]
    tainted = dxa.compute_taint(lines, dxa.JS_SOURCES, False)
    assert "a" in tainted and "b" in tainted


def test_navigation_not_double_reported_as_src_href():
    findings = scan("vulnerable.js")
    line29 = [x for x in findings if x["line"] == 29]
    sinks = {x["sink"] for x in line29}
    assert "navigation" in sinks and "src-href" not in sinks
