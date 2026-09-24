# Python example for dxa (Flask + FastAPI + Django patterns). Every pattern
# below is intentionally unsafe and is for detector testing only.
from flask import Flask, request, render_template_string, Markup, Response, make_response
from fastapi import FastAPI, Query, Header
from fastapi.responses import HTMLResponse
from django.utils.safestring import mark_safe

app = Flask(__name__)
fapi = FastAPI()


# HIGH: request source flows straight into a render_template_string() call
@app.get("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string("<h1>Results for " + q + "</h1>")


# HIGH: taint propagates through a local -> Markup() sink
@app.get("/user")
def user_page():
    name = request.args["name"]
    greeting = "Hello " + name
    return Markup(greeting)


# HIGH: Django mark_safe on an unescaped value
def render_greeting(request):
    who = request.GET.get("who", "")
    return mark_safe("<div>Welcome " + who + "</div>")


# HIGH: FastAPI HTMLResponse with a query param dropped in raw
@fapi.get("/hi", response_class=HTMLResponse)
def hi(q: str = Query("")):
    return "<p>hi " + q + "</p>"


# MEDIUM: Flask make_response with text/html and dynamic body
@app.get("/note")
def note():
    body = request.form.get("body", "")
    resp = make_response("<div>" + body + "</div>")
    resp.mimetype = "text/html"
    return resp


# HIGH: Jinja |safe filter used on a variable
_TEMPLATE = "<article>{{ post|safe }}</article>"


# MEDIUM: os.system with a user value - not XSS but Python-only injection worth flagging
def run(request):
    filename = request.args.get("f", "")
    import os
    os.system("ls " + filename)
