from __future__ import annotations

import requests

import pytest

import ai_assistant
from ai_assistant import answer_remediation, answer_remediation_stream, get_ai_status

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
        "AI_FAST_MODE",
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


@pytest.mark.parametrize(
    "question",
    [
        "thiệt hại gây ra như thế nào",
        "mức độ ảnh hưởng của mã độc này",
        "what is the impact?",
    ],
)
def test_guardrail_allows_impact_questions(monkeypatch, ai_payload, question):
    monkeypatch.setenv("AI_PROVIDER", "local")

    result = answer_remediation(question, ai_payload)

    assert result["mode"] == "local"
    assert "Đánh giá tác động" in result["answer"]
    assert "Rủi ro cần xác minh thêm" in result["answer"]


def test_stream_allows_impact_question(monkeypatch, ai_payload):
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    events = list(answer_remediation_stream("thiệt hại gây ra như thế nào", ai_payload))

    assert events[0]["mode"] == "fast_local"
    assert "Đánh giá tác động" in events[1]["text"]


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


def test_fast_mode_answers_simple_ioc_question_without_llm(monkeypatch, ai_payload):
    def fake_post(_url, **_kwargs):
        raise AssertionError("LLM should not be called for fast local questions")

    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setattr(ai_assistant.requests, "post", fake_post)

    result = answer_remediation("cần chặn IOC nào trước?", ai_payload)

    assert result["mode"] == "fast_local"
    assert result["model"] == "rule-based"
    assert "IOC" in result["answer"]


def test_fast_mode_answers_similar_malware_question(monkeypatch, ai_payload):
    def fake_post(_url, **_kwargs):
        raise AssertionError("LLM should not be called for similar-family questions")

    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.setattr(ai_assistant.requests, "post", fake_post)

    result = answer_remediation("có những malware nào tương tự?", ai_payload)

    assert result["mode"] == "fast_local"
    assert result["answer"].startswith("Đáp án:")
    assert "QakBot" in result["answer"]
    assert "IcedID" in result["answer"]
    assert "không có nghĩa" in result["answer"] or "khong co nghia" in result["answer"]
    assert "Quan sát" not in result["answer"]


def test_related_malware_question_lists_answer_before_explanation(monkeypatch, ai_payload):
    def fake_post(_url, **_kwargs):
        raise AssertionError("LLM should not be called for related-family questions")

    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.setattr(ai_assistant.requests, "post", fake_post)

    result = answer_remediation("có những malware nào liên quan?", ai_payload)

    assert result["mode"] == "fast_local"
    assert result["answer"].splitlines()[0].startswith("Đáp án:")
    assert "QakBot" in result["answer"].splitlines()[0]
    assert "Vì sao liên quan:" in result["answer"]
    assert "Quan sát" not in result["answer"]


@pytest.mark.parametrize(
    ("question", "expected_group", "expected_family"),
    [
        ("các ransomware nào tương tự?", "Ransomware", "LockBit"),
        ("rootkin nào có hành vi tương tự?", "Rootkit/bootkit", "TDSS"),
        ("zombie botnet nào tương tự?", "Botnet/zombie", "Mirai"),
        ("trojan nào giống mẫu này?", "Trojan/loader", "QakBot"),
    ],
)
def test_similar_malware_uses_generic_category_taxonomy(monkeypatch, question, expected_group, expected_family):
    def fake_post(_url, **_kwargs):
        raise AssertionError("LLM should not be called for similar category questions")

    payload = {
        "threat": {"verdict": "Malicious", "threat_level": 3, "threat_name": "Unknown"},
        "network": {},
        "processes": {},
        "malware_analysis": {},
        "playbook": {"malware_name": "Unknown", "ioc_blocklist": {}, "actions": []},
    }
    monkeypatch.setenv("AI_PROVIDER", "ollama")
    monkeypatch.setattr(ai_assistant.requests, "post", fake_post)

    result = answer_remediation(question, payload)

    assert result["mode"] == "fast_local"
    assert expected_group in result["answer"]
    assert expected_family in result["answer"]


def test_stream_returns_meta_delta_and_done_for_fast_mode(monkeypatch, ai_payload):
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    events = list(answer_remediation_stream("cần chặn IOC nào trước?", ai_payload))

    assert [event["event"] for event in events] == ["meta", "delta", "done"]
    assert events[0]["mode"] == "fast_local"
    assert "IOC" in events[1]["text"]
    assert isinstance(events[2]["latency_ms"], int)


def test_ai_status_does_not_expose_secret(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "secret-key")
    monkeypatch.setenv("OPENAI_MODEL", "test-model")

    status = get_ai_status()

    assert status["provider"] == "openai"
    assert status["openai_configured"] is True
    assert status["openai_model"] == "test-model"
    assert "secret-key" not in str(status)
