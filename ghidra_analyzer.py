"""
Optional Ghidra integration for local malware static analysis.

The app can run without Ghidra installed. When GHIDRA_HOME or analyzeHeadless is
available, this module invokes Ghidra headless and merges its summary with a
small local triage pass.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


URL_RE = re.compile(rb"https?://[^\s\"'<>]{4,}", re.IGNORECASE)
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(rb"\b(?:[a-z0-9-]{2,63}\.)+[a-z]{2,12}\b", re.IGNORECASE)
REGISTRY_RE = re.compile(rb"\bHK(?:LM|CU|CR|U|CC)\\[A-Za-z0-9_\\ .-]{4,}", re.IGNORECASE)
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{5,}")

SUSPICIOUS_APIS = [
    "CreateRemoteThread",
    "VirtualAlloc",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "LoadLibrary",
    "GetProcAddress",
    "WinExec",
    "ShellExecute",
    "URLDownloadToFile",
    "InternetOpen",
    "InternetConnect",
    "HttpSendRequest",
    "RegSetValue",
    "CryptEncrypt",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
]


def find_analyze_headless() -> str:
    """Return an analyzeHeadless executable path if Ghidra is configured."""
    env_candidates = [os.environ.get("GHIDRA_HEADLESS")]
    for env_name in ("GHIDRA_HOME", "GHIDRA_INSTALL_DIR"):
        home = os.environ.get(env_name)
        if home:
            env_candidates.extend(
                [
                    str(Path(home) / "support" / "analyzeHeadless.bat"),
                    str(Path(home) / "support" / "analyzeHeadless"),
                ]
            )
    env_candidates.extend(
        [
            shutil.which("analyzeHeadless.bat"),
            shutil.which("analyzeHeadless"),
        ]
    )
    for candidate in env_candidates:
        if candidate and Path(candidate).exists():
            return str(Path(candidate))
    return ""


def ghidra_status() -> dict:
    headless = find_analyze_headless()
    return {
        "available": bool(headless),
        "analyze_headless": headless,
        "ghidra_home": os.environ.get("GHIDRA_HOME") or os.environ.get("GHIDRA_INSTALL_DIR") or "",
        "configured_by": "GHIDRA_HEADLESS/GHIDRA_HOME/PATH" if headless else "",
        "setup_hint": "Cài Ghidra và đặt GHIDRA_HOME trỏ tới thư mục Ghidra, ví dụ C:\\Tools\\ghidra_<version>_PUBLIC",
    }


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    value = 0.0
    for count in counts:
        if count:
            p = count / total
            value -= p * math.log2(p)
    return round(value, 3)


def _decode_matches(matches: list[bytes], limit: int = 50) -> list[str]:
    seen: list[str] = []
    for item in matches:
        text = item.decode("utf-8", errors="ignore").strip("\x00")
        if text and text not in seen:
            seen.append(text)
        if len(seen) >= limit:
            break
    return seen


def lightweight_static_triage(path: str) -> dict:
    sample = Path(path)
    data = sample.read_bytes()
    lower = data.lower()
    strings = _decode_matches(PRINTABLE_RE.findall(data), limit=200)
    api_hits = [api for api in SUSPICIOUS_APIS if api.lower().encode("ascii") in lower]
    urls = _decode_matches(URL_RE.findall(data), limit=40)
    ips = _decode_matches(IP_RE.findall(data), limit=40)
    domains = _decode_matches(DOMAIN_RE.findall(data), limit=40)
    registry = _decode_matches(REGISTRY_RE.findall(data), limit=40)
    file_type = "PE executable" if data[:2] == b"MZ" else "Unknown/binary"
    if data[:4] == b"\x7fELF":
        file_type = "ELF executable"
    elif data[:4] == b"PK\x03\x04":
        file_type = "ZIP/Office container"

    findings = []
    if _entropy(data) >= 7.2:
        findings.append("Entropy cao, có thể bị pack/encrypt.")
    if api_hits:
        findings.append("Có API thường gặp trong malware loader/injection/networking.")
    if urls or ips or domains:
        findings.append("Có chuỗi mạng để đối chiếu với IOC Any.Run.")
    if registry:
        findings.append("Có registry path phục vụ kiểm tra persistence.")

    return {
        "filename": sample.name,
        "size": len(data),
        "file_type": file_type,
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": _entropy(data),
        "strings": strings[:80],
        "urls": urls,
        "ips": ips,
        "domains": domains[:40],
        "registry": registry,
        "suspicious_apis": api_hits,
        "findings": findings,
    }


def run_ghidra_headless(path: str, timeout: int = 180) -> dict:
    headless = find_analyze_headless()
    if not headless:
        return {"available": False, "status": "not_configured", "error": ghidra_status()["setup_hint"]}

    scripts_dir = Path(__file__).resolve().parent / "scripts" / "ghidra"
    script_name = "MalwareSummaryExporter.java"
    with tempfile.TemporaryDirectory(prefix="ir_ghidra_") as tmp:
        project_dir = Path(tmp) / "project"
        output_json = Path(tmp) / "ghidra_summary.json"
        project_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            headless,
            str(project_dir),
            "IRStaticAnalysis",
            "-import",
            str(Path(path).resolve()),
            "-overwrite",
            "-analysisTimeoutPerFile",
            str(timeout),
            "-scriptPath",
            str(scripts_dir),
            "-postScript",
            script_name,
            str(output_json),
            "-deleteProject",
        ]
        started = time.time()
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 60,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "available": True,
                "status": "timeout",
                "error": f"Ghidra vượt quá thời gian {timeout}s",
                "stdout": (exc.stdout or "")[-4000:],
                "stderr": (exc.stderr or "")[-4000:],
            }

        result = {
            "available": True,
            "status": "ok" if completed.returncode == 0 else "error",
            "returncode": completed.returncode,
            "duration_seconds": round(time.time() - started, 2),
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
        }
        if output_json.exists():
            try:
                result["summary"] = json.loads(output_json.read_text(encoding="utf-8"))
            except Exception as exc:
                result["summary_error"] = str(exc)
        elif completed.returncode == 0:
            result["status"] = "no_summary"
            result["error"] = "Ghidra chạy xong nhưng không tạo được summary JSON"
        return result


def analyze_sample(path: str, timeout: int = 180) -> dict:
    triage = lightweight_static_triage(path)
    ghidra = run_ghidra_headless(path, timeout=timeout)
    return {
        "triage": triage,
        "ghidra": ghidra,
        "ir_enrichment": build_ir_enrichment(triage, ghidra),
    }


def build_ir_enrichment(triage: dict, ghidra: dict) -> dict:
    static_iocs = {
        "urls": triage.get("urls", []),
        "ips": triage.get("ips", []),
        "domains": triage.get("domains", []),
        "registry": triage.get("registry", []),
        "hashes": [triage.get("md5", ""), triage.get("sha1", ""), triage.get("sha256", "")],
    }
    actions = [
        "Đối chiếu hash và chuỗi mạng từ Ghidra/static triage với IOC Any.Run.",
        "Ưu tiên reverse các function liên quan network, injection, persistence hoặc crypto.",
        "Dùng strings/API/registry để bổ sung hunting query và bằng chứng trong IR playbook.",
    ]
    if ghidra.get("status") == "not_configured":
        actions.insert(0, "Cấu hình GHIDRA_HOME để bật decompile/headless analysis đầy đủ.")
    return {
        "static_iocs": static_iocs,
        "recommended_ir_actions": actions,
        "evidence_note": "Static analysis bổ sung nguyên nhân kỹ thuật; Any.Run vẫn là nguồn chính cho hành vi runtime.",
    }
