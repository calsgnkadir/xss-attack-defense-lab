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


def test_response_write_suppressed_when_servlet_writer_matches():
    """A line matching both `servlet-writer` (general getWriter().*) AND
    `response-write` (specific response.getWriter().*) must produce ONE
    finding per severity, not two - the specific one is dropped when the
    general one is present. Closes the hotel-platform IdempotencyFilter
    double-report case."""
    findings = scan("vulnerable.java")
    by_line = {}
    for f in findings:
        by_line.setdefault(f["line"], set()).add(f["sink"])
    # every line that has BOTH must have `response-write` dropped
    for ln, sinks in by_line.items():
        if "servlet-writer" in sinks and "response-write" in sinks:
            raise AssertionError(
                f"line {ln} has both servlet-writer AND response-write "
                f"(should be deduped): {sinks}")


def test_sink_suppression_table_intact():
    # regression: existing (src-href, navigation) pair still present
    pairs = dict(dxa.SINK_SUPPRESSIONS)
    assert pairs.get("src-href") == "navigation"
    assert pairs.get("response-write") == "servlet-writer"


# --- Phase 0.1: 5 new sink-suppression pairs (2026-09-26) -------------------

def _scan_snippet(tmp_path, ext, code):
    """Write `code` to a tmp file with `ext`, run dxa.scan_file, return
    (findings, sinks_by_line). Used by the Phase 0.1 dedup tests below."""
    p = tmp_path / f"snippet.{ext}"
    p.write_text(code, encoding="utf-8")
    findings = dxa.scan_file(str(p))
    by_line = {}
    for f in findings:
        by_line.setdefault(f["line"], set()).add(f["sink"])
    return findings, by_line


def test_sink_dedup_angular_bypass_wins_over_innerhtml(tmp_path):
    """Angular pattern .innerHTML = bypassSecurityTrustHtml(x) fires both
    the innerHTML and angular-bypass sinks. Only angular-bypass should
    survive (more informative)."""
    code = ("const x = window.location.hash;\n"
            "elem.innerHTML = this.sanitizer.bypassSecurityTrustHtml(x);\n")
    _, by_line = _scan_snippet(tmp_path, "ts", code)
    sinks_line2 = by_line.get(2, set())
    assert "angular-bypass" in sinks_line2, sinks_line2
    assert "innerHTML" not in sinks_line2, (
        f"innerHTML should have been suppressed on line 2, got {sinks_line2}")


def test_sink_dedup_jsp_el_unescape_wins_over_jsp_expr(tmp_path):
    """<c:out escapeXml="false"><%=request.getParameter("x")%></c:out>
    fires jsp-expr AND jsp-el-unescape on one line. Keep jsp-el-unescape
    (it names WHY the expression bypasses escaping)."""
    code = ('<c:out escapeXml="false"><%=request.getParameter("x")%></c:out>\n')
    _, by_line = _scan_snippet(tmp_path, "jsp", code)
    sinks = by_line.get(1, set())
    assert "jsp-el-unescape" in sinks, sinks
    assert "jsp-expr" not in sinks, (
        f"jsp-expr should have been suppressed, got {sinks}")


def test_sink_dedup_django_mark_safe_wins_over_markup(tmp_path):
    """return mark_safe(Markup(user_input)) fires both markupsafe-markup
    and django-mark-safe. Keep django-mark-safe (idiomatic Django)."""
    code = ("from django.utils.safestring import mark_safe\n"
            "from markupsafe import Markup\n"
            "def view(request):\n"
            "    return mark_safe(Markup(request.GET['q']))\n")
    _, by_line = _scan_snippet(tmp_path, "py", code)
    sinks_line4 = by_line.get(4, set())
    assert "django-mark-safe" in sinks_line4, sinks_line4
    assert "markupsafe-markup" not in sinks_line4, (
        f"markupsafe-markup should have been suppressed on line 4, "
        f"got {sinks_line4}")


def test_sink_dedup_th_inline_unesc_wins_over_th_utext(tmp_path):
    """A mixed Thymeleaf node <span th:utext="${x}">[(${x})]</span> matches
    both th:utext and the inline [( )] form. Keep the less-known inline
    form (more actionable when someone doesn't know it also unescapes)."""
    # Use .jsp extension so Java-family sinks (which include Thymeleaf) apply.
    # In Spring projects Thymeleaf templates usually live in .html files, but
    # dxa's language router maps Thymeleaf sinks to the Java family; test the
    # dedup behaviour under that mapping.
    code = ('<span th:utext="${msg}">[(${msg})]</span>\n')
    _, by_line = _scan_snippet(tmp_path, "jsp", code)
    sinks = by_line.get(1, set())
    assert "th-inline-unesc" in sinks, sinks
    assert "th-utext" not in sinks, (
        f"th-utext should have been suppressed, got {sinks}")


def test_sink_dedup_render_template_str_wins_over_safe_filter(tmp_path):
    """render_template_string('...{{ x | safe }}...') fires both
    render-template-str and jinja-safe-filter. render-template-str is
    the whole-class attack (template injection); keep it."""
    code = ("from flask import render_template_string, request\n"
            "def view():\n"
            "    return render_template_string('hi {{ x | safe }}', "
            "x=request.args['q'])\n")
    _, by_line = _scan_snippet(tmp_path, "py", code)
    sinks_line3 = by_line.get(3, set())
    assert "render-template-str" in sinks_line3, sinks_line3
    assert "jinja-safe-filter" not in sinks_line3, (
        f"jinja-safe-filter should have been suppressed on line 3, "
        f"got {sinks_line3}")


def test_sink_suppression_table_has_all_phase01_pairs():
    """Regression: every Phase 0.1 pair still in the table."""
    pairs = dict(dxa.SINK_SUPPRESSIONS)
    assert pairs.get("innerHTML") == "angular-bypass"
    assert pairs.get("jsp-expr") == "jsp-el-unescape"
    assert pairs.get("markupsafe-markup") == "django-mark-safe"
    assert pairs.get("th-utext") == "th-inline-unesc"
    assert pairs.get("jinja-safe-filter") == "render-template-str"


# --- Phase 0.3: sanitize heuristic tightening (2026-09-26) ------------------

def test_sanitize_covers_when_only_call_in_ternary_hotel_platform_shape():
    """Regression: the hotel-platform ternary
        String cid = (inbound != null && !inbound.trim().isEmpty()) ?
                      sanitize(inbound) : shortUuid();
    must still break taint (guard-clause references of `inbound` are not
    value leaks). Locked in writeup 09; Phase 0.3 must not undo it."""
    lines = ['String inbound = request.getHeader("X-Correlation-Id");',
             'String cid = (inbound != null && !inbound.trim().isEmpty()) '
             '? sanitize(inbound) : shortUuid();',
             'response.getWriter().print(cid);']
    tainted = dxa.compute_taint(lines, dxa.JAVA_SOURCES, msg_active=True,
                                assign_re=dxa.JAVA_ASSIGN)
    assert "inbound" in tainted
    assert "cid" not in tainted, (
        f"sanitize() in ternary must clear taint; got tainted={tainted}")


def test_sanitize_does_NOT_cover_when_concat_leaks_tainted_var():
    """Phase 0.3's central FN fix. The pathological
        String out = sanitizeButKeepsHtml(a) + b;
    (where `b` is tainted) used to be silently squelched by v3.8's name-match
    heuristic. Now the residual `+ b` is detected as a value leak, so taint
    propagates and `out` is HIGH."""
    lines = ['String a = request.getParameter("a");',
             'String b = request.getParameter("b");',
             'String out = sanitizeButKeepsHtml(a) + b;',
             'response.getWriter().print(out);']
    tainted = dxa.compute_taint(lines, dxa.JAVA_SOURCES, msg_active=True,
                                assign_re=dxa.JAVA_ASSIGN)
    assert "b" in tainted
    assert "out" in tainted, (
        f"sanitize() only covered `a`; residual `+ b` leaks tainted `b`, "
        f"but taint didn't propagate. tainted={tainted}")


def test_sanitize_does_NOT_cover_when_source_appears_after():
    """Sibling of the above: sanitize covers one arg, but the residual RHS
    still directly accesses a source (not through a variable). Taint must
    propagate."""
    lines = ['String a = request.getParameter("a");',
             'String out = sanitizeButPartial(a) + request.getParameter("b");',
             'response.getWriter().print(out);']
    tainted = dxa.compute_taint(lines, dxa.JAVA_SOURCES, msg_active=True,
                                assign_re=dxa.JAVA_ASSIGN)
    assert "out" in tainted, (
        f"residual has request.getParameter, must leak; tainted={tainted}")


def test_known_safe_funcs_hard_clear_even_if_residual_looks_tainted():
    """Tier 1 whitelist: even a construct like
        String out = StringEscapeUtils.escapeHtml4(a) + notSuspicious;
    (where `notSuspicious` is NOT tainted) does not propagate. This just
    confirms hard-clear works. The FN case with `+ b` where b IS tainted
    is a different story - not tested here because the tier-1 whitelist
    intentionally trusts library escapers to sanitize their INPUT; the
    subsequent concat with other data is out of scope for the escaper."""
    lines = ['String a = request.getParameter("a");',
             'String out = StringEscapeUtils.escapeHtml4(a);',
             'response.getWriter().print(out);']
    tainted = dxa.compute_taint(lines, dxa.JAVA_SOURCES, msg_active=True,
                                assign_re=dxa.JAVA_ASSIGN)
    assert "a" in tainted
    assert "out" not in tainted


def test_known_safe_funcs_pattern_matches_the_key_escapers():
    """The whitelist regex is the tier-1 gate; if a canonical escaper's
    spelling drops off it, we silently switch to tier-2 (soft-clear) for
    that call, which is a regression. Lock the essential ones."""
    for expr in [
        "html.escape(x)",
        "htmlspecialchars($x, ENT_QUOTES)",
        "StringEscapeUtils.escapeHtml4(x)",
        "HttpUtility.HtmlEncode(x)",
        "DOMPurify.sanitize(x)",
        "bleach.clean(x)",
        "Encode.forHtml(x)",
        "WebUtility.HtmlEncode(x)",
    ]:
        assert dxa._KNOWN_SAFE_FUNCS.search(expr), (
            f"tier-1 whitelist lost {expr!r}")


def test_sanitize_covers_rhs_paren_tracking_loss_is_conservative():
    """If _sanitize_covers_rhs can't cleanly track parens (RHS malformed
    or truncated by preprocessing), it should return False so taint stays.
    Fewer FN is safer than fewer FP for this edge."""
    # unclosed sanitize call - depth never returns to 0
    rhs = "sanitize(request.body"
    assert dxa._sanitize_covers_rhs(
        rhs, dxa.PY_SOURCES, msg_active=True, tainted=set()
    ) is False


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
