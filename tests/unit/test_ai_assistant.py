from __future__ import annotations

import requests

import pytest

import ai_assistant
from ai_assistant import answer_remediation, get_ai_status

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def clear_ai_env(monkeypatch):
    for key in [
        "AI_PROVIDER",
        "AI_TEMPERATURE",
        "AI_MAX_TOKENS",
        "AI_TIMEOUT",
        "AI_RETRIES",
        "AI_CONTEXT_LIMIT",
        "OPENAI_API_KEY",
        "OPENAI_API_BASE",
        "OPENAI_MODEL",
        "OLLAMA_ENABLED",
        "OLLAMA_BASE_URL",
        "OLLAMA_MODEL",
        "OLLAMA_TIMEOUT",
        "OLLAMA_NUM_PREDICT",
    ]:
        monkeypatch.delenv(key, raising=False)


@pytest.fixture
def ai_payload():
    return {
        "task_uuid": "task-1",
        "analysis_url": "https://app.any.run/tasks/task-1",
        "file": {"name": "invoice.doc", "sha256": "sha256-test"},
        "threat": {"verdict": "Malicious", "threat_level": 3, "threat_name": "Emotet"},
        "network": {"ips": ["192.0.2.10"], "domains": ["evil.example"], "urls": [], "http": []},
        "processes": {"dropped": [], "registry": [], "injected": []},
        "malware_analysis": {
            "behavior": ["Mẫu có hoạt động C2."],
            "spread": ["Vector nghi ngờ là phishing."],
            "origin": ["Nguồn quan sát trực tiếp là sandbox."],
        },
        "playbook": {
            "malware_name": "Emotet",
            "severity": "CRITICAL",
            "ioc_blocklist": {"ip_addresses": ["192.0.2.10"], "domains": ["evil.example"]},
            "actions": [
                {
                    "priority": 1,
                    "phase": "Ngăn chặn (Containment)",
                    "title": "Block C2",
                    "description": "Block outbound C2 traffic.",
                    "commands": [],
                }
            ],
        },
    }


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def test_guardrail_blocks_out_of_scope_question(ai_payload):
    result = answer_remediation("viết thơ tình", ai_payload)

    assert result["mode"] == "guardrail"
    assert result["model"] == "scope-guardrail"


def test_local_provider_returns_metadata(monkeypatch, ai_payload):
    monkeypatch.setenv("AI_PROVIDER", "local")

    result = answer_remediation("ưu tiên xử lý IOC như thế nào?", ai_payload)

    assert result["mode"] == "local"
    assert result["model"] == "rule-based"
    assert isinstance(result["latency_ms"], int)
    assert "Thứ tự" in result["answer"] or "IOC" in result["answer"]


def test_openai_provider_posts_configured_payload(monkeypatch, ai_payload):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return FakeResponse({"choices": [{"message": {"content": "Kế hoạch IR từ LLM"}}]})

    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_MODEL", "test-model")
    monkeypatch.setenv("AI_MAX_TOKENS", "512")
    monkeypatch.setattr(ai_assistant.requests, "post", fake_post)

    result = answer_remediation("phân tích IOC và ưu tiên xử lý", ai_payload)

    assert result["mode"] == "openai"
    assert result["model"] == "test-model"
    assert result["answer"] == "Kế hoạch IR từ LLM"
    assert captured["url"].endswith("/chat/completions")
    assert captured["kwargs"]["json"]["model"] == "test-model"
    assert captured["kwargs"]["json"]["max_tokens"] == 512


def test_openai_failure_falls_back_locally(monkeypatch, ai_payload):
    def fake_post(_url, **_kwargs):
        raise requests.Timeout("timeout")

    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(ai_assistant.requests, "post", fake_post)

    result = answer_remediation("phân tích IOC và ưu tiên xử lý", ai_payload)

    assert result["mode"] == "local_fallback"
    assert result["model"] == "rule-based"
    assert "warning" in result


def test_ai_status_does_not_expose_secret(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "secret-key")
    monkeypatch.setenv("OPENAI_MODEL", "test-model")

    status = get_ai_status()

    assert status["provider"] == "openai"
    assert status["openai_configured"] is True
    assert status["openai_model"] == "test-model"
    assert "secret-key" not in str(status)
