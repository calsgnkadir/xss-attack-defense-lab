// Java/Servlet + Spring example for dxa. Every pattern below is intentionally
// unsafe and is for detector testing only.
package com.example;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;

public class VulnerableController {

    // HIGH: servlet request source flows straight into response.getWriter
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String q = request.getParameter("q");
        response.getWriter().write("<div>You searched: " + q + "</div>");
    }

    // HIGH: taint propagates through a local variable, then hits print
    public void handle(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String name = request.getHeader("X-User-Name");
        String greet = "Hello " + name;
        response.getWriter().println(greet);
    }

    // HIGH: Spring @RequestParam source concat'd into response body
    @GetMapping(value = "/search", produces = "text/html")
    @ResponseBody
    public String search(@RequestParam String q, HttpServletResponse response) throws Exception {
        response.getWriter().print("<h1>Results for " + q + "</h1>");
        return "";
    }

    // HIGH: @PathVariable reaches a servlet write
    @GetMapping("/user/{id}/greet")
    public void greet(@PathVariable String id, HttpServletResponse response) throws Exception {
        response.getWriter().write("Welcome user " + id);
    }

    // MEDIUM: jsoup Element.html(x) sink with dynamic value
    public void loadFragment(String rawHtml) {
        org.jsoup.nodes.Element div = new org.jsoup.nodes.Element("div");
        div.html(rawHtml);
    }
}
