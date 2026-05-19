from __future__ import annotations

import os
import re
import unicodedata
from typing import Any

import requests


_IR_SCOPE_KEYWORDS = {
    "ai",
    "agent",
    "attack",
    "av",
    "block",
    "blocklist",
    "c2",
    "cach ly",
    "chan",
    "cleanup",
    "contain",
    "containment",
    "dns",
    "domain",
    "edr",
    "email",
    "endpoint",
    "eradicate",
    "file",
    "firewall",
    "hash",
    "host",
    "hunt",
    "ioc",
    "ip",
    "ir",
    "lay lan",
    "log",
    "ma doc",
    "malware",
    "may",
    "mitre",
    "nguon",
    "phan tich",
    "phishing",
    "playbook",
    "process",
    "proxy",
    "ransomware",
    "registry",
    "remediation",
    "sandbox",
    "sha256",
    "soc",
    "sach",
    "su co",
    "threat",
    "tien trinh",
    "triage",
    "url",
    "vector",
    "virus",
    "xac minh",
    "xu ly",
}


def answer_remediation(question: str, analysis_payload: dict[str, Any]) -> dict[str, Any]:
    question = (question or "").strip()
    if not question:
        question = "Hãy chủ động đánh giá sự cố này và đề xuất bước xử lý tiếp theo."

    if not _is_ir_question(question):
        return {
            "mode": "guardrail",
            "answer": _out_of_scope_answer(question),
        }

    context = _build_context(analysis_payload)
    provider = os.getenv("AI_PROVIDER", "auto").strip().lower()
    api_key = os.getenv("OPENAI_API_KEY", "").strip()

    if provider in ("ollama", "local_llm") or (provider == "auto" and not api_key and _ollama_configured()):
        try:
            return {
                "mode": "ollama",
                "answer": _answer_with_ollama(question, context),
            }
        except Exception as exc:
            return {
                "mode": "local_fallback",
                "answer": _answer_locally(question, analysis_payload)
                + f"\n\n(Lưu ý: gọi Ollama lỗi: {exc})",
            }

    if provider in ("openai", "auto") and api_key:
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


def _system_prompt() -> str:
    return (
        "Bạn là trợ lý Incident Response cho malware. "
        "Chỉ trả lời các câu hỏi nằm trong phạm vi phân tích mã độc, IOC, "
        "containment, eradication, recovery, threat hunting và báo cáo sự cố. "
        "Nếu câu hỏi ngoài phạm vi, từ chối ngắn gọn và hướng người dùng quay lại chủ đề IR. "
        "Trả lời bằng tiếng Việt như một trưởng ca SOC chủ động: nêu nhận định, mức khẩn cấp, "
        "giả thuyết lây nhiễm, hành động P0/P1, câu hỏi cần xác minh và điều kiện được phép đưa máy trở lại mạng. "
        "Ưu tiên thao tác an toàn, không bịa IOC ngoài dữ liệu được cung cấp."
    )


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
                    "content": _system_prompt(),
                },
                {
                    "role": "user",
                    "content": f"Ngữ cảnh phân tích:\n{context}\n\nCâu hỏi: {question}",
                },
            ],
            "temperature": 0.25,
            "max_tokens": 1100,
        },
        timeout=30,
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"].strip()


def _answer_with_ollama(question: str, context: str) -> str:
    model = os.getenv("OLLAMA_MODEL", "llama3.1:8b").strip() or "llama3.1:8b"
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    response = requests.post(
        f"{base_url}/api/chat",
        json={
            "model": model,
            "stream": False,
            "messages": [
                {"role": "system", "content": _system_prompt()},
                {
                    "role": "user",
                    "content": f"Ngữ cảnh phân tích:\n{context}\n\nCâu hỏi: {question}",
                },
            ],
            "options": {
                "temperature": 0.2,
                "num_predict": 900,
            },
        },
        timeout=int(os.getenv("OLLAMA_TIMEOUT", "60")),
    )
    response.raise_for_status()
    data = response.json()
    return (data.get("message", {}) or {}).get("content", "").strip() or "Ollama không trả về nội dung."


def _ollama_configured() -> bool:
    return bool(os.getenv("OLLAMA_MODEL", "").strip() or os.getenv("OLLAMA_ENABLED", "").strip() in {"1", "true", "yes"})


def _normalize_text(text: str) -> str:
    decomposed = unicodedata.normalize("NFD", text or "")
    no_marks = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return re.sub(r"\s+", " ", no_marks.lower()).strip()


def _is_ir_question(question: str) -> bool:
    q = _normalize_text(question)
    if not q:
        return True
    for keyword in _IR_SCOPE_KEYWORDS:
        if " " in keyword:
            if keyword in q:
                return True
        elif re.search(rf"\b{re.escape(keyword)}\b", q):
            return True
    if any(keyword in q for keyword in ("hash", "sha256", "malware", "ransomware", "wannacry")):
        return True
    suspicious_artifacts = [
        r"\b[a-f0-9]{32}\b",
        r"\b[a-f0-9]{40}\b",
        r"\b[a-f0-9]{64}\b",
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        r"\bT\d{4}(?:\.\d{3})?\b",
        r"https?://",
        r"\.(exe|dll|docm|ps1|bat|vbs|scr|zip|7z)\b",
    ]
    return any(re.search(pattern, q, re.IGNORECASE) for pattern in suspicious_artifacts)


def _out_of_scope_answer(question: str) -> str:
    return (
        "Mình chỉ xử lý các câu hỏi liên quan đến phân tích mã độc và phản ứng sự cố trong báo cáo hiện tại.\n\n"
        "Câu hỏi vừa rồi nằm ngoài phạm vi IR, nên mình không trả lời để tránh làm sai vai trò của AI Agent.\n"
        "Bạn có thể hỏi theo hướng như:\n"
        "1. Mã độc này lây lan bằng cách nào?\n"
        "2. Cần cô lập và chặn IOC nào trước?\n"
        "3. Làm sao xác minh máy đã sạch?\n"
        "4. Viết kế hoạch hunt các máy có khả năng bị ảnh hưởng."
    )


def _answer_locally(question: str, payload: dict[str, Any]) -> str:
    playbook = payload.get("playbook", {}) or {}
    threat = payload.get("threat", {}) or {}
    file_info = payload.get("file") or {}
    network = payload.get("network", {}) or {}
    processes = payload.get("processes", {}) or {}
    malware_analysis = payload.get("malware_analysis", {}) or {}
    blocklist = playbook.get("ioc_blocklist", {}) or {}
    actions = playbook.get("actions", []) or []
    q = question.lower()
    malware_name = playbook.get("malware_name") or threat.get("threat_name") or "Unknown malware"
    severity = playbook.get("severity", "UNKNOWN")
    verdict = threat.get("verdict", "Unknown")
    level = threat.get("threat_level", "?")

    if any(word in q for word in ["chi tiết", "chi tiet", "cách xử lý", "cach xu ly", "xử lý chi tiết", "xu ly chi tiet", "step by step", "từng bước", "tung buoc"]):
        return _detailed_remediation_response(payload)
    if any(word in q for word in ["chủ động", "chu dong", "brief", "triage", "đánh giá", "danh gia", "tự đánh giá", "tu danh gia"]):
        return _proactive_brief(payload)
    if any(word in q for word in ["ưu tiên", "truoc", "trước", "order", "thu tu", "thứ tự"]):
        return _priority_response(payload)
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
            "3. Đẩy blocklist lên firewall/DNS, sau đó truy vấn log proxy/DNS để tìm máy nội bộ từng kết nối tới các IOC này.\n"
            "4. Nếu là ransomware/critical, cô lập endpoint trước khi chạy dọn dẹp để tránh lây lan hoặc mã hóa tiếp."
        )
    elif any(word in q for word in ["nguồn", "nguon", "lây", "lay", "lan", "vector", "origin"]):
        return _origin_spread_response(payload)
    else:
        return _proactive_brief(payload)

    lines = [
        f"Nhận định nhanh: {malware_name} mức {severity} ({verdict}, threat level {level}/4).",
        f"File chính: {file_info.get('name', 'N/A')} | C2: {len(network.get('ips', []) or [])} IP, {len(network.get('domains', []) or [])} domain | Dropped files: {len(processes.get('dropped', []) or [])}.",
        "",
        "Hướng xử lý trực tiếp:",
    ]
    for idx, action in enumerate(selected, 1):
        lines.append(f"{idx}. {action.get('title', 'Hành động')}: {action.get('description', '')}")
        commands = [c for c in action.get("commands", []) if c and not c.lstrip().startswith("#")]
        if commands:
            lines.append(f"   Lệnh gợi ý: {commands[0]}")
    for item in (malware_analysis.get("behavior") or [])[:2]:
        lines.append(f"Phân tích hành vi: {item}")
    lines.append("Điều kiện dừng: chỉ đưa máy trở lại mạng khi không còn process/dropped file/registry persistence liên quan và log DNS/proxy không còn kết nối IOC.")
    return "\n".join(lines)


def _detailed_remediation_response(payload: dict[str, Any]) -> str:
    playbook = payload.get("playbook", {}) or {}
    threat = payload.get("threat", {}) or {}
    file_info = payload.get("file") or {}
    network = payload.get("network", {}) or {}
    processes = payload.get("processes", {}) or {}
    blocklist = playbook.get("ioc_blocklist", {}) or {}
    actions = playbook.get("actions", []) or []

    malware_name = playbook.get("malware_name") or threat.get("threat_name") or "Unknown malware"
    severity = playbook.get("severity", "UNKNOWN")
    level = threat.get("threat_level", "?")
    ips = blocklist.get("ip_addresses", []) or network.get("ips", []) or []
    domains = blocklist.get("domains", []) or network.get("domains", []) or []
    urls = blocklist.get("urls", []) or network.get("urls", []) or []
    dropped = processes.get("dropped", []) or []
    registry = processes.get("registry", []) or []
    injected = processes.get("injected", []) or []

    phase_actions = {
        "contain": [a for a in actions if "Contain" in a.get("phase", "") or "Ngăn" in a.get("phase", "")],
        "eradicate": [a for a in actions if "Eradication" in a.get("phase", "") or "Loại" in a.get("phase", "")],
        "recover": [a for a in actions if "Recovery" in a.get("phase", "") or "Phục" in a.get("phase", "")],
    }

    lines = [
        f"Kế hoạch xử lý chi tiết cho {malware_name} ({severity}, threat level {level}/4)",
        "",
        "0. Nguyên tắc an toàn trước khi thao tác",
        "- Không mở/chạy file mẫu trên máy thật.",
        "- Nếu nghi ransomware hoặc CRITICAL: cô lập máy trước, không tắt máy vội nếu cần giữ memory evidence.",
        "- Ghi lại thời điểm phát hiện, user đang đăng nhập, hostname, IP nội bộ và đường dẫn file mẫu.",
        "",
        "1. Cô lập và giữ bằng chứng",
        "- Ngắt mạng endpoint bị nhiễm khỏi LAN/VPN/Wi-Fi, hoặc chuyển sang VLAN cách ly.",
        "- Chụp nhanh process list, network connection, scheduled task, service, registry Run keys trước khi xóa.",
        f"- File chính: {file_info.get('name', 'N/A')} | SHA256: {file_info.get('sha256', 'N/A')}",
    ]

    if injected:
        lines.append(f"- Tiến trình nghi bị inject: {', '.join(injected[:8])}. Ưu tiên dump/ghi nhận trước khi kill.")

    lines += [
        "",
        "2. Chặn IOC ở biên mạng và endpoint",
        f"- IP cần chặn: {', '.join(ips[:15]) or 'không có IP trong báo cáo'}",
        f"- Domain cần chặn: {', '.join(domains[:15]) or 'không có domain trong báo cáo'}",
        f"- URL cần kiểm tra/chặn: {', '.join(urls[:8]) or 'không có URL trong báo cáo'}",
        "- Đẩy rule lên firewall/proxy/DNS sinkhole/EDR, sau đó query log 7-30 ngày để tìm host khác từng chạm IOC.",
    ]

    if ips:
        lines.append("Lệnh mẫu chặn IP trên Windows Firewall:")
        for ip in ips[:5]:
            lines.append(f'netsh advfirewall firewall add rule name="IR_Block_{ip}" dir=out action=block remoteip={ip}')
    if domains:
        lines.append("Dòng hosts mẫu nếu cần chặn khẩn cấp trên máy đơn lẻ:")
        for domain in domains[:5]:
            lines.append(f"0.0.0.0 {domain}")

    lines += [
        "",
        "3. Dừng tiến trình và loại bỏ thành phần độc hại",
    ]
    if phase_actions["contain"]:
        for action in phase_actions["contain"][:4]:
            lines.append(f"- {action.get('title')}: {action.get('description')}")
    if dropped:
        lines.append("File được tạo/drop cần xử lý:")
        for item in dropped[:10]:
            lines.append(f"- {item.get('name', 'N/A')} | SHA256: {item.get('sha256', 'N/A')} | {item.get('type', 'N/A')}")
    else:
        lines.append("- Chưa thấy dropped file rõ ràng; vẫn cần quét các đường dẫn TEMP/AppData/ProgramData/Startup.")
    if registry:
        lines.append("Registry/autostart artifact cần kiểm tra:")
        for key in registry[:10]:
            lines.append(f"- {key}")

    lines += [
        "",
        "4. Quét và xác minh sạch",
        "- Chạy full scan bằng EDR/AV đã cập nhật.",
        "- Kiểm tra lại process tree, autoruns, scheduled tasks, services, registry Run/RunOnce, thư mục Startup.",
        "- Kiểm tra DNS/proxy/firewall log sau khi cô lập: không được có kết nối mới tới IOC.",
        "- So khớp hash/filename IOC trên toàn bộ endpoint bằng EDR/SIEM.",
        "",
        "5. Phục hồi",
        "- Chỉ nối mạng lại khi IOC không còn xuất hiện, dropped file/persistence đã gỡ, AV/EDR scan sạch.",
        "- Đổi mật khẩu tài khoản từng đăng nhập trên máy bị nhiễm, đặc biệt nếu có dấu hiệu stealer/ransomware.",
        "- Vá lỗi hệ điều hành/phần mềm, bật firewall và EDR realtime protection.",
        "",
        "6. Hunt mở rộng",
        "- Pivot theo SHA256, filename, domain, URL, user-agent, mutex và registry key.",
        "- Tìm email/web download/share nội bộ là nguồn đưa file vào máy.",
        "- Lập danh sách host từng truy cập IOC, rồi xử lý theo cùng quy trình trên.",
    ]

    if phase_actions["eradicate"] or phase_actions["recover"]:
        lines += ["", "Hành động từ playbook hiện có:"]
        for action in (phase_actions["eradicate"][:3] + phase_actions["recover"][:2]):
            lines.append(f"- {action.get('title')}: {action.get('description')}")

    return "\n".join(lines)


def _proactive_brief(payload: dict[str, Any]) -> str:
    playbook = payload.get("playbook", {}) or {}
    threat = payload.get("threat", {}) or {}
    file_info = payload.get("file") or {}
    network = payload.get("network", {}) or {}
    processes = payload.get("processes", {}) or {}
    malware_analysis = payload.get("malware_analysis", {}) or {}
    actions = playbook.get("actions", []) or []

    malware_name = playbook.get("malware_name") or threat.get("threat_name") or "Unknown malware"
    severity = playbook.get("severity", "UNKNOWN")
    level = threat.get("threat_level", "?")
    p0 = [a for a in actions if a.get("priority") == 1][:3]
    p1 = [a for a in actions if a.get("priority") == 2][:3]

    lines = [
        f"AI briefing: {malware_name} đang ở mức {severity} (threat level {level}/4).",
        f"Điểm đáng chú ý: {file_info.get('name', 'không rõ file')} tạo {len(processes.get('dropped', []) or [])} file, có {len(processes.get('registry', []) or [])} registry artifact, {len(network.get('ips', []) or [])} IP và {len(network.get('domains', []) or [])} domain liên quan.",
        "",
        "Nhận định chủ động:",
    ]
    for item in (malware_analysis.get("behavior") or [])[:4]:
        lines.append(f"- {item}")

    lines += ["", "P0 làm ngay trong 15 phút:"]
    for idx, action in enumerate(p0, 1):
        lines.append(f"{idx}. {action.get('title')}: {action.get('description')}")

    if p1:
        lines += ["", "P1 làm sau khi đã cô lập:"]
        for idx, action in enumerate(p1, 1):
            lines.append(f"{idx}. {action.get('title')}")

    lines += [
        "",
        "Câu hỏi AI muốn bạn xác minh tiếp:",
        "1. Máy nào trong DNS/proxy/EDR từng kết nối tới cùng IP/domain IOC?",
        "2. File đầu vào đến từ email, web download, USB hay share nội bộ?",
        "3. Có tài khoản nào đăng nhập trên máy bị nhiễm trước khi malware chạy không?",
        "",
        "Điều kiện được nối mạng lại: không còn tiến trình nghi vấn, IOC không còn xuất hiện trong log mới, persistence đã bị gỡ và quét EDR/AV full scan sạch.",
    ]
    return "\n".join(lines)


def _priority_response(payload: dict[str, Any]) -> str:
    actions = (payload.get("playbook", {}) or {}).get("actions", []) or []
    priority_groups = [
        ("P0 - Cô lập và chặn lây lan", [a for a in actions if a.get("priority") == 1][:4]),
        ("P1 - Loại bỏ persistence/payload", [a for a in actions if a.get("priority") == 2][:4]),
        ("P2 - Phục hồi và xác minh", [a for a in actions if a.get("priority") in (3, 4)][:4]),
    ]
    lines = ["Thứ tự xử lý đề xuất:"]
    for title, items in priority_groups:
        if not items:
            continue
        lines.append("")
        lines.append(title)
        for idx, action in enumerate(items, 1):
            lines.append(f"{idx}. {action.get('title')}: {action.get('description')}")
    lines.append("")
    lines.append("Không làm recovery trước khi hoàn tất cô lập IOC và gỡ persistence, vì có thể làm malware chạy lại hoặc tiếp tục mã hóa/đánh cắp dữ liệu.")
    return "\n".join(lines)


def _origin_spread_response(payload: dict[str, Any]) -> str:
    malware_analysis = payload.get("malware_analysis", {}) or {}
    lines = ["Phân tích vector lây lan và nguồn gốc quan sát được:"]
    lines.append("")
    lines.append("Cách lây lan / xâm nhập:")
    for item in malware_analysis.get("spread", []) or ["Chưa đủ dữ liệu để kết luận vector lây nhiễm."]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("Nguồn gốc / hạ tầng:")
    for item in malware_analysis.get("origin", []) or ["Chưa đủ dữ liệu threat intelligence để quy kết nguồn gốc."]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("Việc cần làm tiếp: tra log email/web proxy/DNS theo thời điểm mẫu chạy, sau đó pivot theo SHA256, filename, domain và URL để tìm host liên quan.")
    return "\n".join(lines)


def _build_context(payload: dict[str, Any]) -> str:
    threat = payload.get("threat", {}) or {}
    file_info = payload.get("file") or {}
    playbook = payload.get("playbook", {}) or {}
    blocklist = playbook.get("ioc_blocklist", {}) or {}
    malware_analysis = payload.get("malware_analysis", {}) or {}
    network = payload.get("network", {}) or {}
    processes = payload.get("processes", {}) or {}
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
            f"URLs: {', '.join(blocklist.get('urls', [])[:10])}",
            f"HTTP requests: {len(network.get('http', []) or [])}",
            f"Dropped files: {len(processes.get('dropped', []) or [])}",
            f"Registry artifacts: {len(processes.get('registry', []) or [])}",
            "Malware behavior analysis:",
            *[f"- {item}" for item in (malware_analysis.get("behavior") or [])[:6]],
            "Spread/origin analysis:",
            *[f"- {item}" for item in (malware_analysis.get("spread") or [])[:4]],
            *[f"- {item}" for item in (malware_analysis.get("origin") or [])[:4]],
            "Playbook actions:",
            *action_lines,
        ]
    )
