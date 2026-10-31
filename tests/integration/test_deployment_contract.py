"""Direct serverless loading and the files available in an upload-only deployment."""
import os
from pathlib import Path
import shutil
import subprocess
import sys


def test_clean_deployment_bundle_starts_without_local_files(tmp_path):
    root = Path(__file__).resolve().parents[2]
    shutil.copy2(root / 'app.py', tmp_path / 'app.py')
    for name in ['ir_workspace', 'static', 'templates', 'data']:
        shutil.copytree(root / name, tmp_path / name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'dashboard-demo', 'dashboard-preview'))
    code = '''import importlib.util, sys, tempfile
from pathlib import Path
from flask import Flask
sys.path.insert(0, str(Path.cwd()))
Path('runtime').mkdir()
tempfile.tempdir = str(Path('runtime').resolve())
spec = importlib.util.spec_from_file_location('deployment_entry', 'app.py')
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
assert isinstance(module.app, Flask)
client = module.app.test_client()
for path in ['/', '/overview', '/analyze/import', '/analyze/ghidra', '/history', '/static/navigation.js']:
    assert client.get(path).status_code == 200, path
assert client.get('/api/config').json['ok']
assert client.get('/api/demo/wannacry').json['ok']
'''
    env = {**os.environ, 'VERCEL': '1', 'AGENT_PROVIDER': 'rules', 'NETWORK_INTEL_LOOKUPS': '0'}
    result = subprocess.run([sys.executable, '-I', '-X', 'utf8', '-c', code], cwd=tmp_path, env=env, capture_output=True, text=True, encoding='utf-8', timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
