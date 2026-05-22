from __future__ import annotations

import os
import json
import re
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import requests

_BASE_DIR = Path(__file__).resolve().parent
_FAMILY_INTEL_PATH = _BASE_DIR / "data" / "family_intel.json"
_FAMILY_INTEL_CACHE: dict[str, Any] | None = None

_CATEGORY_INTEL: dict[str, dict[str, Any]] = {
    "trojan_loader": {
        "label": "Trojan/loader",
        "aliases": ["trojan", "loader", "banker", "banking", "dropper", "downloader"],
        "similar_families": [
            {
                "name": "QakBot",
                "why": "Trojan/loader qua phishing, co C2 va co the tai payload tiep theo.",
                "hunt_hint": "Hunt Office child process, rundll32/regsvr32, C2 HTTP(S), mailbox co cung attachment/link.",
            },
            {
                "name": "IcedID",
                "why": "Banking trojan/loader nhieu stage, thuong dung email phishing va C2.",
                "hunt_hint": "Kiem tra email gateway, PowerShell/cmd child process, proxy/DNS va dropped DLL/EXE.",
            },
            {
                "name": "Dridex",
                "why": "Trojan ngan hang phat tan qua macro document va tai thanh phan tiep theo.",
                "hunt_hint": "Pivot theo sender/subject, document macro, Office process bat thuong va IOC C2.",
            },
            {
                "name": "TrickBot",
                "why": "Modular trojan co credential theft va lateral movement sau xam nhap ban dau.",
                "hunt_hint": "Kiem tra credential access, SMB/RDP bat thuong, scheduled task/service va C2.",
            },
        ],
    },
    "ransomware": {
        "label": "Ransomware",
        "aliases": ["ransomware", "ransom", "encrypt", "encrypted", "ma hoa", "ma doc ma hoa", "t1486"],
        "similar_families": [
            {
                "name": "LockBit",
                "why": "Ransomware tac dong cao, thuong co ma hoa file va extortion.",
                "hunt_hint": "Hunt file encryption burst, ransom note, C2/leak infra va lateral movement truoc ma hoa.",
            },
            {
                "name": "Ryuk",
                "why": "Ransomware thuong xuat hien sau loader/credential compromise trong moi truong doanh nghiep.",
                "hunt_hint": "Tim dau hieu credential theft, SMB/RDP, PsExec/WMI va ma hoa tren nhieu endpoint.",
            },
            {
                "name": "Conti",
                "why": "Ransomware nham doanh nghiep, thuong co di chuyen ngang va dung cong cu admin.",
                "hunt_hint": "Kiem tra beacon/C2, remote admin tools, privilege escalation va file encryption timeline.",
            },
            {
                "name": "BlackCat/ALPHV",
                "why": "Ransomware hien dai, co double extortion va hoat dong theo affiliate.",
                "hunt_hint": "Hunt exfiltration truoc ma hoa, unusual archive tools, cloud upload va ransom artifacts.",
            },
        ],
    },
    "rootkit": {
        "label": "Rootkit/bootkit",
        "aliases": ["rootkit", "rootkin", "bootkit", "kernel", "driver", "ring0", "mbr", "uefi"],
        "similar_families": [
            {
                "name": "TDSS/Alureon",
                "why": "Rootkit an minh o muc kernel/driver, co the che giau process/file/network.",
                "hunt_hint": "Kiem tra driver la, kernel callbacks, hidden service va offline scan tu trusted media.",
            },
            {
                "name": "ZeroAccess",
                "why": "Rootkit/botnet che giau thanh phan va duy tri persistence sau khi nhiem.",
                "hunt_hint": "So sanh view tu EDR voi offline scanner, kiem tra service/driver va network P2P/C2.",
            },
            {
                "name": "Necurs",
                "why": "Rootkit/botnet dung driver de an minh va bao ve payload spam/malware.",
                "hunt_hint": "Kiem tra driver unsigned/suspicious, boot persistence, DNS/C2 va spam/bot activity.",
            },
            {
                "name": "LoJax",
                "why": "UEFI bootkit co persistence rat sau, song sot qua cai lai OS thong thuong.",
                "hunt_hint": "Kiem tra firmware/UEFI integrity, SPI flash, boot chain va can nhac reflash firmware.",
            },
        ],
    },
    "botnet_zombie": {
        "label": "Botnet/zombie",
        "aliases": ["botnet", "zombie", "bot", "ddos", "irc", "p2p"],
        "similar_families": [
            {
                "name": "Mirai",
                "why": "Botnet bien thiet bi thanh zombie de DDoS va scan/lay lan qua credential yeu.",
                "hunt_hint": "Hunt outbound scanning, telnet/SSH brute force, C2 beacon va traffic DDoS bat thuong.",
            },
            {
                "name": "Necurs",
                "why": "Botnet lon dung may nhiem de spam, phat tan malware va dieu khien tu xa.",
                "hunt_hint": "Kiem tra spam outbound, DNS/C2, scheduled task/service va network beacon dinh ky.",
            },
            {
                "name": "Sality",
                "why": "File infector/botnet co P2P C2 va kha nang lan truyen qua executable/share.",
                "hunt_hint": "Hunt file infection, P2P traffic, removable media va executable bi sua doi.",
            },
            {
                "name": "Ramnit",
                "why": "Botnet/file infector co credential theft va C2, bien host thanh node bi dieu khien.",
                "hunt_hint": "Pivot theo C2, injected browser/process, credential theft va file infection.",
            },
        ],
    },
    "infostealer": {
        "label": "Infostealer",
        "aliases": ["stealer", "infostealer", "password", "cookie", "wallet", "credential", "token"],
        "similar_families": [
            {
                "name": "Vidar",
                "why": "Danh cap credential, cookie, browser data va wallet.",
                "hunt_hint": "Hunt Downloads/AppData/Temp, browser profile access, C2 exfiltration va login bat thuong.",
            },
            {
                "name": "Lumma",
                "why": "Commodity stealer nham vao browser/session token/wallet.",
                "hunt_hint": "Kiem tra token/session abuse, proxy/DNS C2 va cac hash/filename cung chien dich.",
            },
            {
                "name": "Raccoon Stealer",
                "why": "Stealer pho bien, thu thap browser credential/cookie va thong tin he thong.",
                "hunt_hint": "Reset mat khau, revoke sessions va hunt C2/proxy quanh thoi diem chay mau.",
            },
            {
                "name": "Agent Tesla",
                "why": "Spyware/stealer thuong danh cap credential va gui qua SMTP/FTP/HTTP.",
                "hunt_hint": "Kiem tra outbound SMTP/FTP, keylogging/screenshot behavior va credential access.",
            },
        ],
    },
    "worm": {
        "label": "Worm",
        "aliases": ["worm", "smb", "ms17", "eternalblue", "self-propagat", "tu lan", "lan truyen"],
        "similar_families": [
            {
                "name": "Conficker",
                "why": "Worm Windows lan truyen qua loi dich vu va share/credential yeu.",
                "hunt_hint": "Hunt SMB/RPC scanning, failed logon, autorun va patch gap tren Windows.",
            },
            {
                "name": "WannaCry",
                "why": "Ransomware-worm lan truyen qua SMB/EternalBlue.",
                "hunt_hint": "Kiem tra TCP/445 bat thuong, MS17-010, kill-switch/C2 va ransom artifacts.",
            },
            {
                "name": "Sasser",
                "why": "Worm khai thac dich vu Windows de tu lan truyen.",
                "hunt_hint": "Tim scanning bat thuong, crash/restart service va host chua va loi.",
            },
        ],
    },
    "backdoor_rat": {
        "label": "Backdoor/RAT",
        "aliases": ["backdoor", "rat", "remote access", "remote control", "cobalt", "beacon"],
        "similar_families": [
            {
                "name": "AsyncRAT",
                "why": "RAT dieu khien tu xa, co C2 va kha nang thu thap thong tin.",
                "hunt_hint": "Hunt beacon dinh ky, persistence, suspicious .NET process va C2 domain/IP.",
            },
            {
                "name": "njRAT",
                "why": "RAT pho bien cho remote control, keylogging va exfiltration.",
                "hunt_hint": "Kiem tra startup persistence, unusual outbound ports va process/user activity.",
            },
            {
                "name": "PlugX",
                "why": "Backdoor/RAT modular, thuong dung DLL side-loading va C2.",
                "hunt_hint": "Hunt side-loaded DLL, signed binary abuse, C2 va persistence service/task.",
            },
        ],
    },
    "wiper": {
        "label": "Wiper/destructive malware",
        "aliases": ["wiper", "wipe", "destructive", "pha huy", "xoa du lieu"],
        "similar_families": [
            {
                "name": "Shamoon",
                "why": "Wiper pha huy du lieu/MBR, tac dong manh den kha nang van hanh.",
                "hunt_hint": "Kiem tra mass file overwrite, MBR changes, scheduled execution va lateral staging.",
            },
            {
                "name": "HermeticWiper",
                "why": "Wiper dung driver de pha huy du lieu tren Windows.",
                "hunt_hint": "Hunt suspicious driver, disk corruption behavior va timeline phat tan noi bo.",
            },
            {
                "name": "NotPetya",
                "why": "Wiper gia ransomware, lan truyen noi bo va pha huy he thong.",
                "hunt_hint": "Kiem tra SMB/lateral movement, credential reuse, MBR/file table damage.",
            },
        ],
    },
    "cryptominer": {
        "label": "Cryptominer",
        "aliases": ["miner", "cryptominer", "coinminer", "xmrig", "monero", "dao tien ao"],
        "similar_families": [
            {
                "name": "XMRig miner",
                "why": "Dung CPU/GPU de dao Monero, thuong ket noi mining pool.",
                "hunt_hint": "Kiem tra CPU cao, process xmrig/stratum, mining pool DNS va persistence.",
            },
            {
                "name": "LemonDuck",
                "why": "Botnet/miner co kha nang lan truyen va cai miner.",
                "hunt_hint": "Hunt SMB/RDP exploit, scheduled task, PowerShell va mining pool traffic.",
            },
        ],
    },
}


_IR_SCOPE_KEYWORDS = {
    "ai",
    "agent",
    "attack",
    "av",
    "backdoor",
    "block",
    "blocklist",
    "botnet",
    "bootkit",
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
    "miner",
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
    "stealer",
    "soc",
    "sach",
    "su co",
    "threat",
    "tien trinh",
    "triage",
    "trojan",
    "url",
    "vector",
    "virus",
    "worm",
    "xac minh",
    "xu ly",
    "zombie",
    "rootkit",
    "rootkin",
}


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    openai_api_key: str
    openai_model: str
    openai_base_url: str
    ollama_model: str
    ollama_base_url: str
    temperature: float
    max_tokens: int
    timeout_seconds: int
    retries: int
    context_limit: int
    fast_mode: bool
    ollama_num_predict: int
    ollama_timeout_seconds: int


def get_ai_status() -> dict[str, Any]:
    config = _llm_config()
    return {
        "provider": config.provider,
        "openai_configured": bool(config.openai_api_key),
        "openai_model": config.openai_model,
        "openai_base_url": config.openai_base_url,
        "ollama_configured": _ollama_configured(config),
        "ollama_model": config.ollama_model,
        "ollama_base_url": config.ollama_base_url,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "context_limit": config.context_limit,
        "fast_mode": config.fast_mode,
        "retries": config.retries,
    }


def _env_int(name: str, default: int, minimum: int = 1, maximum: int = 100000) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _env_float(name: str, default: float, minimum: float = 0.0, maximum: float = 2.0) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, value))


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _llm_config() -> LLMConfig:
    return LLMConfig(
        provider=os.getenv("AI_PROVIDER", "auto").strip().lower() or "auto",
        openai_api_key=os.getenv("OPENAI_API_KEY", "").strip(),
        openai_model=os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip() or "gpt-4o-mini",
        openai_base_url=os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1").rstrip("/"),
        ollama_model=os.getenv("OLLAMA_MODEL", "llama3.1:8b").strip() or "llama3.1:8b",
        ollama_base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/"),
        temperature=_env_float("AI_TEMPERATURE", 0.25),
        max_tokens=_env_int("AI_MAX_TOKENS", 1100, minimum=128, maximum=8000),
        timeout_seconds=_env_int("AI_TIMEOUT", 45, minimum=5, maximum=300),
        retries=_env_int("AI_RETRIES", 2, minimum=1, maximum=5),
        context_limit=_env_int("AI_CONTEXT_LIMIT", 12000, minimum=2000, maximum=50000),
        fast_mode=_env_bool("AI_FAST_MODE", True),
        ollama_num_predict=_env_int("OLLAMA_NUM_PREDICT", 700, minimum=128, maximum=8000),
        ollama_timeout_seconds=_env_int("OLLAMA_TIMEOUT", 120, minimum=5, maximum=600),
    )


def _answer_remediation_legacy(question: str, analysis_payload: dict[str, Any]) -> dict[str, Any]:
    started = time.perf_counter()
    question = (question or "").strip()
    if not question:
        question = "Hãy chủ động đánh giá sự cố này và đề xuất bước xử lý tiếp theo."

    if not _is_ir_question(question):
        return {
            "mode": "guardrail",
            "answer": _out_of_scope_answer(question),
        }

    config = _llm_config()
    context = _clip_text(_build_context(analysis_payload), config.context_limit)
    provider = config.provider
    api_key = config.openai_api_key

    if config.provider == "local":
        return _llm_result("local", _answer_locally(question, analysis_payload), "rule-based", started)

    if provider in ("ollama", "local_llm") or (provider == "auto" and not api_key and _ollama_configured()):
        try:
            return {
                "mode": "ollama",
                "answer": _answer_with_ollama(question, context),
            }
        except Exception as exc:
            return {
                "mode": "ollama_fallback",
                "answer": _answer_locally(question, analysis_payload),
                "warning": f"Ollama không phản hồi kịp, đã dùng Local assistant. Chi tiết: {exc}",
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
                "answer": _answer_locally(question, analysis_payload),
                "warning": f"OpenAI không phản hồi được, đã dùng Local assistant. Chi tiết: {exc}",
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
        "Khi trả lời, phải phân biệt rõ: (1) Quan sát từ sandbox/report, "
        "(2) Suy luận theo malware family/threat intelligence, (3) Cách xác minh bằng log/EDR. "
        "Trả lời bằng tiếng Việt như một trưởng ca SOC chủ động: nêu nhận định, mức khẩn cấp, "
        "giả thuyết lây nhiễm, hành động P0/P1, câu hỏi cần xác minh và điều kiện được phép đưa máy trở lại mạng. "
        "Ưu tiên thao tác an toàn, không bịa IOC ngoài dữ liệu được cung cấp."
    )


def _answer_with_openai_legacy(api_key: str, question: str, context: str) -> str:
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


def _answer_with_ollama_legacy(question: str, context: str) -> str:
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
                "num_predict": int(os.getenv("OLLAMA_NUM_PREDICT", "500")),
            },
        },
        timeout=int(os.getenv("OLLAMA_TIMEOUT", "120")),
    )
    response.raise_for_status()
    data = response.json()
    return (data.get("message", {}) or {}).get("content", "").strip() or "Ollama không trả về nội dung."


def _ollama_configured_legacy() -> bool:
    return bool(
        os.getenv("OLLAMA_MODEL", "").strip() or os.getenv("OLLAMA_ENABLED", "").strip() in {"1", "true", "yes"}
    )


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


def _should_use_fast_local(question: str) -> bool:
    q = _normalize_text(question)
    if not q:
        return True
    similar_markers = [
        "tuong tu",
        "giong",
        "similar",
        "related",
        "lien quan",
        "co lien quan",
        "cung loai",
        "cung nhom",
        "family nao",
        "malware nao",
    ]
    if any(marker in q for marker in similar_markers):
        return True
    deep_markers = [
        "phan tich",
        "analysis",
        "chi tiet",
        "giai thich",
        "bao cao",
        "report",
        "so sanh",
        "tai sao",
        "why",
        "day du",
        "full",
    ]
    if any(marker in q for marker in deep_markers):
        return False
    fast_markers = [
        "ioc",
        "block",
        "blocklist",
        "firewall",
        "domain",
        "ip",
        "uu tien",
        "thu tu",
        "p0",
        "p1",
        "cach ly",
        "contain",
        "containment",
        "ngan chan",
        "xoa",
        "eradicate",
        "loai bo",
        "cleanup",
        "brief",
        "triage",
        "danh gia nhanh",
        "nguon lay",
        "lay lan",
        "vector",
        "origin",
        "tuong tu",
        "giong",
        "similar",
        "related",
        "lien quan",
        "co lien quan",
        "cung loai",
        "cung nhom",
        "family nao",
        "malware nao",
    ]
    return any(marker in q for marker in fast_markers)


def _load_family_intel() -> dict[str, Any]:
    global _FAMILY_INTEL_CACHE
    if _FAMILY_INTEL_CACHE is not None:
        return _FAMILY_INTEL_CACHE
    try:
        _FAMILY_INTEL_CACHE = json.loads(_FAMILY_INTEL_PATH.read_text(encoding="utf-8"))
    except Exception:
        _FAMILY_INTEL_CACHE = {"default": {}}
    return _FAMILY_INTEL_CACHE


def _payload_malware_name(payload: dict[str, Any]) -> str:
    playbook = payload.get("playbook", {}) or {}
    threat = payload.get("threat", {}) or {}
    return playbook.get("malware_name") or threat.get("threat_name") or "Unknown malware"


def _family_intel_for(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    intel = _load_family_intel()
    malware_name = _payload_malware_name(payload)
    normalized = _normalize_text(malware_name)
    for family, info in intel.items():
        aliases = [family, *(info.get("aliases", []) or [])]
        if any(_normalize_text(alias) and _normalize_text(alias) in normalized for alias in aliases):
            return family, info
    return "default", intel.get("default", {})


def _payload_text_for_classification(payload: dict[str, Any], question: str = "") -> str:
    threat = payload.get("threat", {}) or {}
    playbook = payload.get("playbook", {}) or {}
    malware_analysis = payload.get("malware_analysis", {}) or {}
    mitre_items = threat.get("mitre", []) or []
    mitre_text = []
    for item in mitre_items:
        if isinstance(item, dict):
            mitre_text.extend(str(item.get(key, "")) for key in ("id", "name", "tactic"))
        else:
            mitre_text.append(str(item))
    fields = [
        question,
        _payload_malware_name(payload),
        threat.get("verdict", ""),
        " ".join(str(tag) for tag in (threat.get("tags", []) or [])),
        " ".join(mitre_text),
        playbook.get("severity", ""),
        " ".join(str(item) for item in (malware_analysis.get("behavior", []) or [])),
        " ".join(str(item) for item in (malware_analysis.get("spread", []) or [])),
        " ".join(str(item) for item in (malware_analysis.get("origin", []) or [])),
    ]
    family, intel = _family_intel_for(payload)
    if family != "default":
        fields.append(family)
    fields.append(str(intel.get("summary", "")))
    return _normalize_text(" ".join(str(field) for field in fields if field))


def _category_intel_for(payload: dict[str, Any], question: str = "") -> tuple[str, dict[str, Any]]:
    question_text = _normalize_text(question)
    for key, info in _CATEGORY_INTEL.items():
        aliases = info.get("aliases", []) or []
        if any(alias and alias in question_text for alias in aliases):
            return key, info

    haystack = _payload_text_for_classification(payload, question)
    if "t1486" in haystack:
        return "ransomware", _CATEGORY_INTEL["ransomware"]
    for key, info in _CATEGORY_INTEL.items():
        aliases = info.get("aliases", []) or []
        if any(alias and alias in haystack for alias in aliases):
            return key, info
    return "unknown", {
        "label": "Unknown/uncategorized malware",
        "similar_families": [],
    }


def _format_bullets(items: list[str], fallback: str) -> list[str]:
    return [f"- {item}" for item in items] if items else [f"- {fallback}"]


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
    qn = _normalize_text(question)
    malware_name = playbook.get("malware_name") or threat.get("threat_name") or "Unknown malware"
    severity = playbook.get("severity", "UNKNOWN")
    verdict = threat.get("verdict", "Unknown")
    level = threat.get("threat_level", "?")

    if any(
        word in qn
        for word in [
            "tuong tu",
            "giong",
            "similar",
            "related",
            "lien quan",
            "co lien quan",
            "cung loai",
            "cung nhom",
            "family nao",
            "malware nao",
        ]
    ):
        return _similar_malware_response(payload, question)
    if any(
        word in q
        for word in [
            "chi tiết",
            "chi tiet",
            "cách xử lý",
            "cach xu ly",
            "xử lý chi tiết",
            "xu ly chi tiet",
            "step by step",
            "từng bước",
            "tung buoc",
        ]
    ):
        return _detailed_remediation_response(payload)
    if any(
        word in q
        for word in ["chủ động", "chu dong", "brief", "triage", "đánh giá", "danh gia", "tự đánh giá", "tu danh gia"]
    ):
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
    elif any(
        word in q for word in ["nguồn", "nguon", "lây", "lay", "lan", "vector", "origin", "smb", "ms17", "eternalblue"]
    ):
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
    lines.append(
        "Điều kiện dừng: chỉ đưa máy trở lại mạng khi không còn process/dropped file/registry persistence liên quan và log DNS/proxy không còn kết nối IOC."
    )
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
            lines.append(
                f"- {item.get('name', 'N/A')} | SHA256: {item.get('sha256', 'N/A')} | {item.get('type', 'N/A')}"
            )
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
        for action in phase_actions["eradicate"][:3] + phase_actions["recover"][:2]:
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
    lines.append(
        "Không làm recovery trước khi hoàn tất cô lập IOC và gỡ persistence, vì có thể làm malware chạy lại hoặc tiếp tục mã hóa/đánh cắp dữ liệu."
    )
    return "\n".join(lines)


def _origin_spread_response(payload: dict[str, Any]) -> str:
    malware_analysis = payload.get("malware_analysis", {}) or {}
    network = payload.get("network", {}) or {}
    processes = payload.get("processes", {}) or {}
    family, intel = _family_intel_for(payload)
    malware_name = _payload_malware_name(payload)

    lines = [
        f"Phân tích lây lan cho {malware_name}",
        "",
        "1. Quan sát từ sandbox/report",
    ]
    lines.extend(
        _format_bullets(
            malware_analysis.get("spread", []) or [],
            "Report hiện chưa ghi nhận trực tiếp vector ban đầu; cần xác minh bằng log nội bộ.",
        )
    )
    if network.get("ips") or network.get("domains") or network.get("urls"):
        lines.append(
            f"- Report ghi nhận hoạt động mạng: {len(network.get('ips', []) or [])} IP, "
            f"{len(network.get('domains', []) or [])} domain, {len(network.get('urls', []) or [])} URL."
        )
    if processes.get("dropped") or processes.get("registry"):
        lines.append(
            f"- Artifact hệ thống: {len(processes.get('dropped', []) or [])} dropped file, "
            f"{len(processes.get('registry', []) or [])} registry/autostart artifact."
        )

    lines += [
        "",
        f"2. Suy luận theo threat intelligence/family ({family})",
    ]
    if intel.get("summary"):
        lines.append(f"- {intel['summary']}")
    lines.extend(
        _format_bullets(
            intel.get("common_spread", []) or [],
            "Chưa có threat intel riêng cho family này; không kết luận thêm ngoài dữ liệu quan sát.",
        )
    )

    lines += ["", "3. Cách xác minh"]
    lines.extend(
        _format_bullets(
            intel.get("verify", []) or [], "Đối chiếu log endpoint, DNS/proxy/firewall/EDR quanh thời điểm mẫu chạy."
        )
    )

    lines += ["", "4. Hunt phạm vi ảnh hưởng"]
    lines.extend(
        _format_bullets(
            intel.get("hunt", []) or [], "Pivot theo hash, filename, domain, URL, process tree và registry artifact."
        )
    )

    lines += ["", "5. Biện pháp chặn/khắc phục"]
    lines.extend(
        _format_bullets(
            intel.get("remediation", []) or [],
            "Cô lập endpoint, chặn IOC, gỡ persistence/dropped file, scan full và chỉ nối mạng lại khi sạch.",
        )
    )

    lines += [
        "",
        "Kết luận: phần 'quan sát' là dữ liệu từ report hiện tại; phần 'suy luận' là kiến thức theo malware family và phải được xác minh bằng log trước khi kết luận phạm vi thật.",
    ]
    return "\n".join(lines)


def _similar_malware_response(payload: dict[str, Any], question: str = "") -> str:
    family, intel = _family_intel_for(payload)
    _category_key, category_intel = _category_intel_for(payload, question)
    malware_name = _payload_malware_name(payload)
    category_label = category_intel.get("label", "Unknown/uncategorized malware")
    combined: list[dict[str, str]] = []
    seen: set[str] = set()
    for source in (intel.get("similar_families", []) or []) + (category_intel.get("similar_families", []) or []):
        if not isinstance(source, dict):
            continue
        name = str(source.get("name", "")).strip()
        if not name or _normalize_text(name) in seen:
            continue
        seen.add(_normalize_text(name))
        combined.append(source)

    if not combined:
        return "\n".join(
            [
                "Đáp án: Chưa có danh sách malware liên quan đủ tin cậy trong threat intel local.",
                "",
                f"Nhóm suy ra: {category_label}",
                "",
                "Có thể tự so sánh theo các trục: vector lây nhiễm, C2, persistence, payload dropped, MITRE techniques và mục tiêu cuối.",
            ]
        )

    names = [str(item.get("name", "Unknown family")).strip() for item in combined[:8]]
    lines = [
        "Đáp án: " + ", ".join(name for name in names if name),
        "",
        f"Nhóm suy ra: {category_label}",
        "",
        "Vì sao liên quan:",
    ]
    for idx, item in enumerate(combined[:8], 1):
        name = item.get("name", "Unknown family")
        why = item.get("why", "Co mot so hanh vi trung voi family hien tai.")
        hunt_hint = item.get("hunt_hint", "Pivot theo IOC, process tree, dropped file va log endpoint/proxy.")
        lines.append(f"{idx}. {name}: {why}")
        lines.append(f"   - Nên hunt/xác minh: {hunt_hint}")

    lines += [
        "",
        "Lưu ý:",
        "- Đây là threat intelligence để so sánh/hunt, không có nghĩa là tất cả các family trên đã xuất hiện trong sandbox.",
        "- Muốn kết luận trùng family nào thì cần đối chiếu hash, YARA/AV name, C2 infrastructure, process tree, dropped file và log EDR/proxy/DNS.",
    ]
    return "\n".join(lines)


def _build_context(payload: dict[str, Any]) -> str:
    threat = payload.get("threat", {}) or {}
    file_info = payload.get("file") or {}
    playbook = payload.get("playbook", {}) or {}
    blocklist = playbook.get("ioc_blocklist", {}) or {}
    malware_analysis = payload.get("malware_analysis", {}) or {}
    network = payload.get("network", {}) or {}
    processes = payload.get("processes", {}) or {}
    family, intel = _family_intel_for(payload)
    _category_key, category_intel = _category_intel_for(payload)
    actions = playbook.get("actions", []) or []
    action_lines = []
    for action in actions[:10]:
        action_lines.append(f"- [{action.get('phase')}] {action.get('title')}: {action.get('description')}")
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
            f"Known family intelligence: {family}",
            f"- Summary: {intel.get('summary', '')}",
            "- Common spread:",
            *[f"  - {item}" for item in (intel.get("common_spread", []) or [])[:5]],
            "- Verification:",
            *[f"  - {item}" for item in (intel.get("verify", []) or [])[:5]],
            "- Hunting:",
            *[f"  - {item}" for item in (intel.get("hunt", []) or [])[:5]],
            "- Remediation:",
            *[f"  - {item}" for item in (intel.get("remediation", []) or [])[:5]],
            f"- Malware category: {category_intel.get('label', 'Unknown/uncategorized malware')}",
            "- Similar malware/families:",
            *[
                f"  - {item.get('name')}: {item.get('why', '')}"
                for item in ((intel.get("similar_families", []) or []) + (category_intel.get("similar_families", []) or []))[:8]
                if isinstance(item, dict)
            ],
            "Playbook actions:",
            *action_lines,
        ]
    )


def _clip_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    head = max(1, int(limit * 0.7))
    tail = max(1, limit - head - 80)
    return text[:head] + "\n\n...[context truncated for LLM budget]...\n\n" + text[-tail:]


def _llm_result(mode: str, answer: str, model: str, started: float, warning: str = "") -> dict[str, Any]:
    result = {
        "mode": mode,
        "model": model,
        "latency_ms": int((time.perf_counter() - started) * 1000),
        "answer": answer,
    }
    if warning:
        result["warning"] = warning
    return result


def _post_json_with_retries(
    url: str,
    *,
    payload: dict[str, Any],
    headers: dict[str, str],
    timeout: int,
    retries: int,
    stream: bool = False,
):
    last_error: Exception | None = None
    for attempt in range(max(1, retries)):
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=timeout, stream=stream)
            if response.status_code >= 500 and attempt + 1 < retries:
                if stream:
                    response.close()
                time.sleep(0.5 * (attempt + 1))
                continue
            return response
        except (requests.ConnectionError, requests.Timeout) as exc:
            last_error = exc
            if attempt + 1 >= retries:
                raise
            time.sleep(0.5 * (attempt + 1))
    if last_error:
        raise last_error
    raise RuntimeError("LLM provider did not return a response")


def _user_prompt(question: str, context: str) -> str:
    return (
        "Ngữ cảnh phân tích:\n"
        f"{context}\n\n"
        f"Câu hỏi: {question}\n\n"
        "Yêu cầu trả lời:\n"
        "0. Nếu hỏi malware/family liên quan hoặc tương tự: bắt đầu bằng 'Đáp án:' và liệt kê tên family trước; sau đó mới giải thích vì sao liên quan và cách hunt/xác minh. Không đọc lại quan sát từ report cho dạng câu hỏi này.\n"
        "1. Nêu quan sát chắc chắn từ report khi có liên quan.\n"
        "2. Tách riêng phần suy luận/threat intelligence.\n"
        "3. Đưa hành động ưu tiên theo P0/P1/P2 nếu câu hỏi yêu cầu xử lý.\n"
        "4. Nêu log hoặc nguồn dữ liệu cần kiểm chứng."
    )


def _answer_with_openai(config: LLMConfig, question: str, context: str) -> str:
    response = _post_json_with_retries(
        f"{config.openai_base_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {config.openai_api_key}",
            "Content-Type": "application/json",
        },
        payload={
            "model": config.openai_model,
            "messages": [
                {"role": "system", "content": _system_prompt()},
                {"role": "user", "content": _user_prompt(question, context)},
            ],
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
        },
        timeout=config.timeout_seconds,
        retries=config.retries,
    )
    response.raise_for_status()
    data = response.json()
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("OpenAI response is missing assistant content") from exc


def _answer_with_ollama(config: LLMConfig, question: str, context: str) -> str:
    response = _post_json_with_retries(
        f"{config.ollama_base_url}/api/chat",
        headers={"Content-Type": "application/json"},
        payload={
            "model": config.ollama_model,
            "stream": False,
            "messages": [
                {"role": "system", "content": _system_prompt()},
                {"role": "user", "content": _user_prompt(question, context)},
            ],
            "options": {
                "temperature": config.temperature,
                "num_predict": config.ollama_num_predict,
            },
        },
        timeout=config.ollama_timeout_seconds,
        retries=config.retries,
    )
    response.raise_for_status()
    data = response.json()
    return (data.get("message", {}) or {}).get("content", "").strip() or "Ollama không trả về nội dung."


def _iter_openai_stream(config: LLMConfig, question: str, context: str) -> Iterator[str]:
    response = _post_json_with_retries(
        f"{config.openai_base_url}/chat/completions",
        headers={
            "Authorization": f"Bearer {config.openai_api_key}",
            "Content-Type": "application/json",
        },
        payload={
            "model": config.openai_model,
            "messages": [
                {"role": "system", "content": _system_prompt()},
                {"role": "user", "content": _user_prompt(question, context)},
            ],
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            "stream": True,
        },
        timeout=config.timeout_seconds,
        retries=config.retries,
        stream=True,
    )
    try:
        response.raise_for_status()
        for raw_line in response.iter_lines(decode_unicode=True):
            if not raw_line:
                continue
            line = raw_line.strip()
            if line.startswith("data:"):
                line = line[5:].strip()
            if line == "[DONE]":
                break
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            choice = (data.get("choices") or [{}])[0]
            delta = ((choice.get("delta") or {}).get("content")) or ((choice.get("message") or {}).get("content")) or ""
            if delta:
                yield delta
    finally:
        response.close()


def _iter_ollama_stream(config: LLMConfig, question: str, context: str) -> Iterator[str]:
    response = _post_json_with_retries(
        f"{config.ollama_base_url}/api/chat",
        headers={"Content-Type": "application/json"},
        payload={
            "model": config.ollama_model,
            "stream": True,
            "messages": [
                {"role": "system", "content": _system_prompt()},
                {"role": "user", "content": _user_prompt(question, context)},
            ],
            "options": {
                "temperature": config.temperature,
                "num_predict": config.ollama_num_predict,
            },
        },
        timeout=config.ollama_timeout_seconds,
        retries=config.retries,
        stream=True,
    )
    try:
        response.raise_for_status()
        for raw_line in response.iter_lines(decode_unicode=True):
            if not raw_line:
                continue
            try:
                data = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            chunk = ((data.get("message") or {}).get("content")) or data.get("response") or ""
            if chunk:
                yield chunk
            if data.get("done"):
                break
    finally:
        response.close()


def _stream_result(
    mode: str,
    model: str,
    started: float,
    chunks: Iterator[str],
    warning: str = "",
) -> Iterator[dict[str, Any]]:
    meta: dict[str, Any] = {"event": "meta", "mode": mode, "model": model}
    if warning:
        meta["warning"] = warning
    yield meta
    emitted = False
    for chunk in chunks:
        emitted = True
        yield {"event": "delta", "text": chunk}
    if not emitted:
        yield {"event": "delta", "text": ""}
    yield {"event": "done", "latency_ms": int((time.perf_counter() - started) * 1000)}


def _ollama_configured(config: LLMConfig | None = None) -> bool:
    config = config or _llm_config()
    enabled = os.getenv("OLLAMA_ENABLED", "").strip().lower()
    explicit_model = os.getenv("OLLAMA_MODEL", "").strip()
    return bool(explicit_model or enabled in {"1", "true", "yes"})


def answer_remediation(question: str, analysis_payload: dict[str, Any]) -> dict[str, Any]:
    started = time.perf_counter()
    question = (question or "").strip()
    if not question:
        question = "Hãy chủ động đánh giá sự cố này và đề xuất bước xử lý tiếp theo."

    if not _is_ir_question(question):
        return {
            "mode": "guardrail",
            "model": "scope-guardrail",
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "answer": _out_of_scope_answer(question),
        }

    config = _llm_config()
    if config.provider == "local":
        return _llm_result("local", _answer_locally(question, analysis_payload), "rule-based", started)

    if config.fast_mode and _should_use_fast_local(question):
        return _llm_result("fast_local", _answer_locally(question, analysis_payload), "rule-based", started)

    context = _clip_text(_build_context(analysis_payload), config.context_limit)

    if config.provider in ("ollama", "local_llm") or (
        config.provider == "auto" and not config.openai_api_key and _ollama_configured(config)
    ):
        try:
            return _llm_result("ollama", _answer_with_ollama(config, question, context), config.ollama_model, started)
        except Exception as exc:
            return _llm_result(
                "ollama_fallback",
                _answer_locally(question, analysis_payload),
                "rule-based",
                started,
                warning=f"Ollama không phản hồi kịp, đã dùng Local assistant. Chi tiết: {exc}",
            )

    if config.provider in ("openai", "auto") and config.openai_api_key:
        try:
            return _llm_result("openai", _answer_with_openai(config, question, context), config.openai_model, started)
        except Exception as exc:
            return _llm_result(
                "local_fallback",
                _answer_locally(question, analysis_payload),
                "rule-based",
                started,
                warning=f"OpenAI không phản hồi được, đã dùng Local assistant. Chi tiết: {exc}",
            )

    return _llm_result("local_fallback", _answer_locally(question, analysis_payload), "rule-based", started)


def answer_remediation_stream(question: str, analysis_payload: dict[str, Any]) -> Iterator[dict[str, Any]]:
    started = time.perf_counter()
    question = (question or "").strip()
    if not question:
        question = "HĂ£y chá»§ Ä‘á»™ng Ä‘Ă¡nh giĂ¡ sá»± cá»‘ nĂ y vĂ  Ä‘á» xuáº¥t bÆ°á»›c xá»­ lĂ½ tiáº¿p theo."

    if not _is_ir_question(question):
        yield from _stream_result("guardrail", "scope-guardrail", started, iter([_out_of_scope_answer(question)]))
        return

    config = _llm_config()
    if config.provider == "local":
        yield from _stream_result("local", "rule-based", started, iter([_answer_locally(question, analysis_payload)]))
        return

    if config.fast_mode and _should_use_fast_local(question):
        yield from _stream_result("fast_local", "rule-based", started, iter([_answer_locally(question, analysis_payload)]))
        return

    context = _clip_text(_build_context(analysis_payload), config.context_limit)

    if config.provider in ("ollama", "local_llm") or (
        config.provider == "auto" and not config.openai_api_key and _ollama_configured(config)
    ):
        try:
            yield from _stream_result("ollama", config.ollama_model, started, _iter_ollama_stream(config, question, context))
            return
        except Exception as exc:
            yield from _stream_result(
                "ollama_fallback",
                "rule-based",
                started,
                iter([_answer_locally(question, analysis_payload)]),
                warning=f"Ollama khĂ´ng pháº£n há»“i ká»‹p, Ä‘Ă£ dĂ¹ng Local assistant. Chi tiáº¿t: {exc}",
            )
            return

    if config.provider in ("openai", "auto") and config.openai_api_key:
        try:
            yield from _stream_result("openai", config.openai_model, started, _iter_openai_stream(config, question, context))
            return
        except Exception as exc:
            yield from _stream_result(
                "local_fallback",
                "rule-based",
                started,
                iter([_answer_locally(question, analysis_payload)]),
                warning=f"OpenAI khĂ´ng pháº£n há»“i Ä‘Æ°á»£c, Ä‘Ă£ dĂ¹ng Local assistant. Chi tiáº¿t: {exc}",
            )
            return

    yield from _stream_result("local_fallback", "rule-based", started, iter([_answer_locally(question, analysis_payload)]))
