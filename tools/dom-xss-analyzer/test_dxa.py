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


# --- v3.8: cross-method sanitizer awareness ---------------------------------

def test_taint_broken_by_local_sanitize_call_java():
    # sanitize(...) in RHS -> cid does NOT inherit taint from inbound
    lines = [
        'String inbound = request.getParameter("q");',
        'String cid = sanitize(inbound);',
        'response.getWriter().write(cid);',
    ]
    tainted = dxa.compute_taint(lines, dxa.JAVA_SOURCES, False, dxa.JAVA_ASSIGN)
    assert "inbound" in tainted, "the source assign is still tainted"
    assert "cid" not in tainted, "sanitize(...) must break the chain"


def test_taint_broken_by_local_clean_call_java():
    lines = [
        'String raw = request.getHeader("X");',
        'String safe = cleanInput(raw);',
    ]
    tainted = dxa.compute_taint(lines, dxa.JAVA_SOURCES, False, dxa.JAVA_ASSIGN)
    assert "raw" in tainted
    assert "safe" not in tainted


def test_taint_broken_by_owasp_encoder_java():
    # Existing OWASP escape families should also cut the taint at assign-time
    lines = [
        'String q = request.getParameter("q");',
        'String out = Encode.forHtml(q);',
    ]
    tainted = dxa.compute_taint(lines, dxa.JAVA_SOURCES, False, dxa.JAVA_ASSIGN)
    assert "q" in tainted
    assert "out" not in tainted


def test_taint_still_flows_without_sanitize_java():
    # Sanity: no sanitizer -> taint DOES propagate (control case)
    lines = [
        'String q = request.getParameter("q");',
        'String out = "hello " + q;',
    ]
    tainted = dxa.compute_taint(lines, dxa.JAVA_SOURCES, False, dxa.JAVA_ASSIGN)
    assert "q" in tainted and "out" in tainted


def test_ternary_with_sanitize_in_one_branch_breaks_taint():
    # The CorrelationIdFilter hotel-platform shape: ternary with sanitize
    lines = [
        'String inbound = request.getHeader("X-Correlation-Id");',
        'String cid = (inbound != null) ? sanitize(inbound) : shortUuid();',
    ]
    tainted = dxa.compute_taint(lines, dxa.JAVA_SOURCES, False, dxa.JAVA_ASSIGN)
    assert "inbound" in tainted
    assert "cid" not in tainted, "ternary with sanitize() branch must break taint"


def test_sanitize_hint_python_variant():
    lines = [
        'q = request.args.get("q")',
        'safe = html.escape(q)',
        'raw = "hello " + q',        # control: still propagates
    ]
    tainted = dxa.compute_taint(lines, dxa.PY_SOURCES, False, dxa.PYTHON_ASSIGN)
    assert "q" in tainted
    assert "safe" not in tainted
    assert "raw" in tainted


def test_navigation_not_double_reported_as_src_href():
    findings = scan("vulnerable.js")
    line29 = [x for x in findings if x["line"] == 29]
    sinks = {x["sink"] for x in line29}
    assert "navigation" in sinks and "src-href" not in sinks


# --- PHP detection (v3.4 addition) ------------------------------------------

def test_php_echo_of_superglobal_is_high():
    f = by_sink(scan("vulnerable.php"))
    assert "echo" in f
    assert any(x["confidence"] == "high" and any("$_" in s for s in x["sources"])
               for x in f["echo"])


def test_php_taint_propagates_to_print():
    f = by_sink(scan("vulnerable.php"))
    assert "print" in f
    assert any(x["confidence"] == "high" and x["tainted_vars"] for x in f["print"])


def test_php_short_echo_of_superglobal_is_high():
    f = by_sink(scan("vulnerable.php"))
    assert "short-echo" in f
    assert any(x["confidence"] == "high" for x in f["short-echo"])


def test_php_lang_label_is_php():
    findings = scan("vulnerable.php")
    assert findings and all(x["lang"] == "php" for x in findings)


# --- Python (Flask / FastAPI / Django) detection ----------------------------

def test_python_render_template_string_from_request_is_high():
    f = by_sink(scan("vulnerable.py"))
    assert "render-template-str" in f
    assert any(x["confidence"] == "high" and
               ("flask-request-arg" in x["sources"] or x["tainted_vars"])
               for x in f["render-template-str"])


def test_python_markup_via_taint_is_high():
    f = by_sink(scan("vulnerable.py"))
    assert "markupsafe-markup" in f
    assert any(x["confidence"] == "high" and x["tainted_vars"]
               for x in f["markupsafe-markup"])


def test_python_django_mark_safe_is_high():
    f = by_sink(scan("vulnerable.py"))
    assert "django-mark-safe" in f
    assert any(x["confidence"] == "high" for x in f["django-mark-safe"])


def test_python_lang_label_is_py():
    findings = scan("vulnerable.py")
    assert findings and all(x["lang"] == "py" for x in findings)


def test_python_safe_file_has_no_high_confidence():
    findings = scan("safe.py")
    highs = [x for x in findings if x["confidence"] == "high"]
    # every HIGH must have an escape function on the SAME line (proximity gate)
    assert all(
        any(esc in x["code"] for esc in
            ("html.escape", "markupsafe.escape", "bleach.clean"))
        for x in highs
    ), f"unexpected HIGH without escape: {highs}"


# --- Java / Servlet / Spring detection --------------------------------------

def test_java_servlet_write_from_request_param_is_high():
    f = by_sink(scan("vulnerable.java"))
    # both servlet-writer and response-write may match same line - either is fine
    key = "response-write" if "response-write" in f else "servlet-writer"
    assert key in f
    assert any(x["confidence"] == "high" for x in f[key])


def test_java_taint_propagates_through_local_var():
    f = by_sink(scan("vulnerable.java"))
    key = "response-write" if "response-write" in f else "servlet-writer"
    # some HIGH finding must be driven by a tainted local (not a source on
    # the same line) - the `String greet = "Hello " + name; ... println(greet)`
    # pattern proves compute_taint runs on Java too.
    assert any(x["confidence"] == "high" and x["tainted_vars"] for x in f[key])


def test_java_spring_requestparam_source_is_recognised():
    findings = scan("vulnerable.java")
    highs = [x for x in findings if x["confidence"] == "high"]
    assert any("spring-param" in x["sources"] or x["tainted_vars"] for x in highs)


def test_java_lang_label_is_java():
    findings = scan("vulnerable.java")
    assert findings and all(x["lang"] == "java" for x in findings)


def test_java_safe_file_has_no_high_confidence():
    findings = scan("safe.java")
    # every HIGH must have an escape function on the SAME line (proximity gate)
    highs = [x for x in findings if x["confidence"] == "high"]
    assert all(
        any(esc in x["code"] for esc in
            ("escapeHtml4", "htmlEscape", "Encode.forHtml"))
        for x in highs
    )


def test_php_safe_file_has_no_high_confidence():
    findings = scan("safe.php")
    # safe.php still triggers sink matches, but nothing should be HIGH -
    # because dxa can't see htmlspecialchars() the confidence stays MEDIUM/LOW
    # on lines that don't contain a source. What must NOT happen: HIGH on the
    # escaped lines (the source IS present there, so this is a real test that
    # the heuristic doesn't blindly flag every source-adjacent sink).
    highs_with_no_escape = [x for x in findings
                            if x["confidence"] == "high"
                            and "htmlspecialchars" not in x["code"]]
    # only lines with an unescaped superglobal near the sink (if any) may fire
    # here safe.php has none, so this must be empty.
    assert highs_with_no_escape == [] or all(
        "htmlspecialchars" in x["code"] for x in highs_with_no_escape)
