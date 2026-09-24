# Escaped/safe equivalents. dxa's escape-family gate should keep these
# findings at MEDIUM (or below) via the proximity check.
from flask import Flask, request, Markup, render_template_string
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
import html
import markupsafe
import bleach

app = Flask(__name__)
fapi = FastAPI()


# html.escape wraps the tainted value on the same line
@app.get("/search")
def search():
    q = request.args.get("q", "")
    return render_template_string("<h1>Results for " + html.escape(q) + "</h1>")


# markupsafe.escape same-line
@app.get("/user")
def user_page():
    name = request.args["name"]
    return Markup("Hello " + markupsafe.escape(name))


# FastAPI + bleach.clean
@fapi.get("/hi", response_class=HTMLResponse)
def hi(q: str = Query("")):
    return "<p>hi " + bleach.clean(q) + "</p>"


# Constant string - no attacker data at all
@app.get("/static")
def static():
    return "<h1>Static welcome</h1>"
