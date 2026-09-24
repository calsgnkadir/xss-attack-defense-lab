// Escaped/safe equivalents. dxa's escape-family gate should keep these
// findings at MEDIUM (or below) - the same-line proximity of an
// StringEscapeUtils / HtmlUtils / OWASP Encoder call is the signal.
package com.example;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.web.util.HtmlUtils;
import org.owasp.encoder.Encode;
import org.springframework.web.bind.annotation.*;

public class SafeController {

    // Apache Commons escape wrapped around the tainted value on the same line
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String q = request.getParameter("q");
        response.getWriter().write("<div>You searched: " + StringEscapeUtils.escapeHtml4(q) + "</div>");
    }

    // Spring HtmlUtils
    @GetMapping(value = "/search", produces = "text/html")
    @ResponseBody
    public String search(@RequestParam String q, HttpServletResponse response) throws Exception {
        response.getWriter().print("<h1>Results for " + HtmlUtils.htmlEscape(q) + "</h1>");
        return "";
    }

    // OWASP Java Encoder
    public void greet(@PathVariable String id, HttpServletResponse response) throws Exception {
        response.getWriter().write("Welcome user " + Encode.forHtml(id));
    }

    // Constant string sink - no attacker data
    public void staticText(HttpServletResponse response) throws Exception {
        response.getWriter().write("<h1>Static welcome</h1>");
    }
}
