"""Explicit screen URLs. API routes remain owned by the Flask entrypoint."""
from flask import Blueprint, current_app, send_from_directory

pages = Blueprint("pages", __name__)
PAGE_IDS = ("overview", "home", "analyze", "dashboard", "playbook", "evidence", "iocs", "history")
ANALYSIS_TABS = ("uuid", "import", "url", "file", "ghidra", "demo")
PAGE_PATHS = ("/",) + tuple("/" + page for page in PAGE_IDS) + tuple("/analyze/" + tab for tab in ANALYSIS_TABS)


def index():
    return send_from_directory(current_app.template_folder, "index.html")


for path in PAGE_PATHS:
    pages.add_url_rule(path, endpoint="index", view_func=index, strict_slashes=False)
