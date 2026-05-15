from __future__ import annotations

import os
from typing import Any

import requests


def answer_remediation(question: str, analysis_payload: dict[str, Any]) -> dict[str, Any]:
    question = (question or "").strip()
    if not question:
        question = "Tôi nên khắc phục sự cố này theo thứ tự nào?"

    context = _build_context(analysis_payload)
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if api_key:
        try:
            return {
                "mode": "openai",
                "answer": _answer_with_openai(api_key, question, context),
            }
        except Exception as exc:
            return {
                "mode": "local_fallback",
                "answer": _answer_locally(question, analysis_payload)
                + f"\n\n(Lưu ý: gọi AI bên ngoài lỗi: {exc})",
            }

    return {
        "mode": "local_fallback",
        "answer": _answer_locally(question, analysis_payload),
    }


def _answer_with_openai(api_key: str, question: str, context: str) -> str:
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini"
    base_url = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1").rstrip("/")
    response = requests.post(
        f"{base_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Bạn là trợ lý Incident Response cho malware. "
                        "Trả lời bằng tiếng Việt, thực tế, ưu tiên thao tác an toàn, "
                        "không bịa IOC ngoài dữ liệu được cung cấp."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Ngữ cảnh phân tích:\n{context}\n\nCâu hỏi: {question}",
                },
            ],
            "temperature": 0.2,
            "max_tokens": 700,
        },
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"].strip()


def _answer_locally(question: str, payload: dict[str, Any]) -> str:
    playbook = payload.get("playbook", {}) or {}
    threat = payload.get("threat", {}) or {}
    blocklist = playbook.get("ioc_blocklist", {}) or {}
    actions = playbook.get("actions", []) or []
    q = question.lower()

    if any(word in q for word in ["ưu tiên", "truoc", "trước", "order", "thu tu", "thứ tự"]):
        selected = actions[:5]
    elif any(word in q for word in ["cach ly", "cô lập", "contain", "ngan chan", "ngăn chặn"]):
        selected = [a for a in actions if "Containment" in a.get("phase", "") or "Contain" in a.get("phase", "")][:5]
    elif any(word in q for word in ["xoa", "xóa", "eradicate", "loại bỏ", "loai bo"]):
        selected = [a for a in actions if "Eradication" in a.get("phase", "") or "Lo" in a.get("phase", "")][:5]
    elif any(word in q for word in ["ioc", "block", "firewall", "domain", "ip"]):
        ips = ", ".join(blocklist.get("ip_addresses", [])[:10]) or "không có IP"
        domains = ", ".join(blocklist.get("domains", [])[:10]) or "không có domain"
        return (
            f"IOC cần xử lý ngay:\n"
            f"1. IP: {ips}\n"
            f"2. Domain: {domains}\n"
            "3. Đẩy blocklist lên firewall/DNS, sau đó truy vấn log proxy/DNS để tìm máy nội bộ từng kết nối tới các IOC này."
        )
    else:
        selected = actions[:4]

    lines = [
        f"Đánh giá nhanh: {playbook.get('malware_name') or threat.get('threat_name') or 'Unknown'} "
        f"mức {playbook.get('severity', 'UNKNOWN')} ({threat.get('verdict', 'Unknown')}).",
        "Các bước nên làm:",
    ]
    for idx, action in enumerate(selected, 1):
        lines.append(f"{idx}. {action.get('title', 'Hành động')}: {action.get('description', '')}")
        commands = [c for c in action.get("commands", []) if c and not c.lstrip().startswith("#")]
        if commands:
            lines.append(f"   Lệnh gợi ý: {commands[0]}")
    lines.append("Sau mỗi bước, kiểm tra lại log endpoint, DNS/proxy và trạng thái tiến trình trước khi đưa máy trở lại mạng.")
    return "\n".join(lines)


def _build_context(payload: dict[str, Any]) -> str:
    threat = payload.get("threat", {}) or {}
    file_info = payload.get("file") or {}
    playbook = payload.get("playbook", {}) or {}
    blocklist = playbook.get("ioc_blocklist", {}) or {}
    actions = playbook.get("actions", []) or []
    action_lines = []
    for action in actions[:10]:
        action_lines.append(
            f"- [{action.get('phase')}] {action.get('title')}: {action.get('description')}"
        )
    return "\n".join(
        [
            f"Malware: {playbook.get('malware_name') or threat.get('threat_name')}",
            f"Verdict: {threat.get('verdict')} | Level: {threat.get('threat_level')}",
            f"File: {file_info.get('name', '')} | SHA256: {file_info.get('sha256', '')}",
            f"IPs: {', '.join(blocklist.get('ip_addresses', [])[:20])}",
            f"Domains: {', '.join(blocklist.get('domains', [])[:20])}",
            "Playbook actions:",
            *action_lines,
        ]
    )
