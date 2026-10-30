"""Local storage paths; per-browser temporary files for the Vercel demo."""
import os
import re
import tempfile
import uuid
from pathlib import Path


def cloud_mode():
    return os.getenv('VERCEL') == '1'


def reports_dir():
    if not cloud_mode():
        return Path(__file__).resolve().parent / 'reports'
    from flask import g, has_request_context, request
    if not has_request_context():
        return Path(tempfile.gettempdir()) / 'ir-workspace'
    if not hasattr(g, 'workspace_id'):
        candidate = request.cookies.get('ir_workspace', '')
        g.workspace_id = candidate if re.fullmatch(r'[0-9a-f]{32}', candidate) else uuid.uuid4().hex
    return Path(tempfile.gettempdir()) / 'ir-workspace' / g.workspace_id
