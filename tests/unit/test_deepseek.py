import json
import responses

from analysis_agent import _call_model, agent_settings
from ai_assistant import _llm_config, _answer_with_openai, _iter_openai_stream, get_ai_status


@responses.activate
def test_deepseek_agent_contract(monkeypatch):
    monkeypatch.setenv("AGENT_PROVIDER", "deepseek")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-placeholder")
    responses.post("https://api.deepseek.com/chat/completions", json={"choices": [{"message": {
        "content": json.dumps({"tool": "get_evidence", "evidence_ids": []})}}]})
    result = _call_model([{"role": "user", "content": "Return JSON"}], agent_settings())
    body = json.loads(responses.calls[-1].request.body)
    assert body["model"] == "deepseek-flash"
    assert body["thinking"] == {"type": "disabled"}
    assert body["response_format"] == {"type": "json_object"}
    assert result["tool"] == "get_evidence"


@responses.activate
def test_deepseek_assistant_and_stream_share_provider(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "deepseek")
    config = _llm_config()
    assert config.openai_base_url == "https://api.deepseek.com"
    responses.post("https://api.deepseek.com/chat/completions", json={"choices": [{"message": {"content": "Đối chiếu bằng chứng."}}]})
    assert _answer_with_openai(config, "Phân tích IOC", "Synthetic report") == "Đối chiếu bằng chứng."
    responses.replace(responses.POST, "https://api.deepseek.com/chat/completions", body='data: {"choices":[{"delta":{"content":"Test"}}]}\n\ndata: [DONE]\n')
    assert list(_iter_openai_stream(config, "Phân tích IOC", "Synthetic report")) == ["Test"]
    status = get_ai_status()
    assert status["provider"] == "deepseek"
    assert "test-placeholder" not in str(status)
    assert "base_url" not in " ".join(status)
