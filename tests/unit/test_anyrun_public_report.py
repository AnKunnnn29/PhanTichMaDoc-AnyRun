import pytest
import requests
import responses
import json
from urllib.parse import quote
from types import SimpleNamespace
import anyrun_public_report as public

from anyrun_public_report import (
    AnyRunPublicReportError,
    _download_public_vue_data,
    _extract_public_url,
    load_public_report,
)


TASK_UUID = "32c69330-3a1b-4891-99df-9bcb2f96f81e"
PUBLIC_URL = (
    "https://any.run/report/"
    "86f393d07fa3fe2d6027a59bbcea97747908f5aed1fa9fcfc6511b779c8dae3b/"
    f"{TASK_UUID}"
)


def test_extract_public_url_keeps_full_report_reference():
    assert _extract_public_url(PUBLIC_URL) == PUBLIC_URL


def test_uuid_only_resolves_public_report(tmp_path, monkeypatch):
    monkeypatch.setattr(public, 'resolve_public_task', lambda task: PUBLIC_URL)
    monkeypatch.setattr(public, '_download_public_vue_data', lambda url: {'meta':{'uuid':TASK_UUID},'general':{}})
    assert load_public_report(TASK_UUID, source_ref=TASK_UUID, reports_dir=tmp_path)['data']['analysis']['uuid']==TASK_UUID


@responses.activate
def test_task_url_is_requested_before_any_access_error(tmp_path,monkeypatch):
    task_url = f"https://app.any.run/tasks/{TASK_UUID}"
    monkeypatch.setattr(public,'resolve_public_task',lambda task:PUBLIC_URL)
    seen=[]
    def denied(url):
        seen.append(url)
        return SimpleNamespace(status_code=403,text='Cloudflare /cdn-cgi/challenge-platform/')
    monkeypatch.setattr(public,'fetch_public_page',denied)
    with pytest.raises(AnyRunPublicReportError, match="Cloudflare") as error:
        load_public_report(TASK_UUID, source_ref=task_url, reports_dir=tmp_path)
    assert error.value.code == 'anyrun_server_access_blocked'
    assert 'trang task cần đăng nhập' not in str(error.value)
    assert seen == [PUBLIC_URL]


def test_download_public_report_wraps_network_error(monkeypatch):
    def fail_request(*_args, **_kwargs):
        raise requests.ConnectionError("blocked")

    monkeypatch.setattr(public, "fetch_public_page", fail_request)

    with pytest.raises(AnyRunPublicReportError, match="proxy hoặc firewall"):
        _download_public_vue_data(PUBLIC_URL)


@responses.activate
def test_public_task_can_follow_matching_static_report(tmp_path,monkeypatch):
    task_url = f'https://app.any.run/tasks/{TASK_UUID}'
    data={'meta':{'uuid':TASK_UUID},'general':{'mainObject':{'value':'test.exe'},'verdict':{'type':3,'value':'Malicious'}}}
    monkeypatch.setattr(public,'resolve_public_task',lambda task:PUBLIC_URL)
    monkeypatch.setattr(public,'fetch_public_page',lambda url:SimpleNamespace(status_code=200,text='window.vueData = "'+quote(json.dumps(data))+'";'))
    report=load_public_report(TASK_UUID,source_ref=task_url,reports_dir=tmp_path)
    assert report['data']['analysis']['uuid']==TASK_UUID
    assert report['publicReport']['general']['verdict']['type']==3
    from validation import validate_report
    validate_report(report,{})


@responses.activate
def test_task_page_without_embedded_report_has_accurate_error(tmp_path,monkeypatch):
    task_url=f'https://app.any.run/tasks/{TASK_UUID}'
    monkeypatch.setattr(public,'resolve_public_task',lambda task:PUBLIC_URL)
    monkeypatch.setattr(public,'fetch_public_page',lambda url:SimpleNamespace(status_code=200,text='<div id="app"></div>'))
    with pytest.raises(AnyRunPublicReportError,match='JavaScript') as error:
        load_public_report(TASK_UUID,source_ref=task_url,reports_dir=tmp_path)
    assert error.value.code=='anyrun_page_data_unavailable'


def test_task_url_does_not_fetch_other_hosts(tmp_path,monkeypatch):
    monkeypatch.setattr(requests,'get',lambda *a,**kw:pytest.fail('Unexpected network request'))
    with pytest.raises(AnyRunPublicReportError):
        load_public_report(TASK_UUID,source_ref=f'https://app.any.run.attacker.example/tasks/{TASK_UUID}',reports_dir=tmp_path)
