"""Cloud demo storage must not mix two browsers' reports or decisions."""
from pathlib import Path
import tempfile


def test_cloud_workspaces_isolate_cases_and_exports(monkeypatch, tmp_path):
    monkeypatch.setenv('VERCEL', '1')
    monkeypatch.setattr(tempfile, 'gettempdir', lambda: str(tmp_path))
    from app import app
    first, second = app.test_client(), app.test_client()
    response = first.get('/api/demo/wannacry', base_url='https://localhost')
    assert response.status_code == 200
    cookie = first.get_cookie('ir_workspace', domain='localhost')
    assert cookie and cookie.secure and cookie.http_only
    payload = response.json['data']
    assert second.get('/api/cases/' + payload['case_id'], base_url='https://localhost').status_code == 404
    export = first.post('/api/export', json={'format': 'json', 'data': payload}, base_url='https://localhost')
    assert export.status_code == 200
    url = export.json['download_url']
    assert first.get(url, base_url='https://localhost').status_code == 200
    assert second.get(url, base_url='https://localhost').status_code == 404
    assert str(tmp_path) in export.json['path']


def test_cloud_hides_server_keys_and_disables_local_jobs(monkeypatch):
    monkeypatch.setenv('VERCEL', '1')
    monkeypatch.setenv('ANYRUN_API_KEY', 'private-test-key-do-not-return')
    from app import app
    client = app.test_client()
    config = client.get('/api/config').json['data']
    assert config['cloud_mode'] and config['api_key'] == ''
    for path in ('/api/submit_analyze/url', '/api/submit_analyze/file'):
        result = client.post(path, json={})
        assert result.status_code == 400
        assert result.json['code'] == 'local_only'
