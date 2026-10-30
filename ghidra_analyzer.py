"""
Optional Ghidra integration for local malware static analysis.

The app can run without Ghidra installed. When GHIDRA_HOME or analyzeHeadless is
available, this module invokes Ghidra headless and merges its summary with a
small local triage pass.
"""

from __future__ import annotations

import hashlib
import base64
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from functools import lru_cache

PROJECT_ROOT = Path(__file__).resolve().parent


@lru_cache(maxsize=4)
def _runtime_alias(project_root: str) -> Path:
    """An ASCII junction avoids the Windows native-Java codepage limitation.

    This is a directory link, not another installation or a runtime copy.
    """
    root = Path(project_root).resolve()
    alias = Path(tempfile.gettempdir()) / 'anyrun-ir-runtime' / hashlib.sha256(str(root).encode('utf-8')).hexdigest()[:16]
    if not str(alias).isascii() or any(c in str(root) + str(alias) for c in '%"\r\n'):
        raise OSError('Use an ASCII local project path or an ASCII TEMP directory for Ghidra')
    alias.parent.mkdir(parents=True, exist_ok=True)
    if not alias.exists():
        quote = lambda value: "'" + str(value).replace("'", "''") + "'"
        script = f"New-Item -ItemType Junction -Path {quote(alias)} -Target {quote(root)} -ErrorAction Stop | Out-Null"
        encoded = base64.b64encode(script.encode('utf-16-le')).decode('ascii')
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                                capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode and not alias.exists():
            raise OSError('Could not create a temporary runtime directory link')
    if alias.resolve() != root:
        raise OSError('Runtime directory link points to an unexpected location')
    return alias


def runtime_path(path) -> str:
    """Use an existing NTFS short alias for native launchers in Unicode folders."""
    path = str(Path(path).resolve())
    if os.name == 'nt':
        root = PROJECT_ROOT.resolve()
        if not path.isascii() and Path(path).is_relative_to(root):
            return str(_runtime_alias(str(root)) / Path(path).relative_to(root))
        import ctypes
        from ctypes import wintypes
        get_short = ctypes.windll.kernel32.GetShortPathNameW
        get_short.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
        get_short.restype = wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        if get_short(path, buffer, len(buffer)):
            return buffer.value
    return path


URL_RE = re.compile(rb"https?://[^\s\"'<>]{4,}", re.IGNORECASE)
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(rb"\b(?:[a-z0-9-]{2,63}\.)+[a-z]{2,12}\b", re.IGNORECASE)
REGISTRY_RE = re.compile(rb"\bHK(?:LM|CU|CR|U|CC)\\[A-Za-z0-9_\\ .-]{4,}", re.IGNORECASE)
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{5,}")
NON_DOMAIN_SUFFIXES = {"dll", "exe", "sys", "ocx", "mui", "pdb", "tmp", "dat", "bin", "hostname"}

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


def _find_java_home() -> str:
    """Find a local JDK suitable for Ghidra headless without prompting."""
    candidates = [
        os.environ.get("JAVA_HOME", ""),
        r"C:\Program Files\Eclipse Adoptium\jdk-21.0.8.9-hotspot",
        r"C:\Program Files\Java\jdk-25.0.2",
        r"C:\Program Files\Java\jdk-24",
    ]
    java_on_path = shutil.which("java")
    if java_on_path:
        candidates.append(str(Path(java_on_path).resolve().parents[1]))
    for candidate in candidates:
        if candidate and (Path(candidate) / "bin" / "java.exe").exists():
            return str(Path(candidate))
    return ""


def find_analyze_headless() -> str:
    """Return an analyzeHeadless executable path if Ghidra is configured."""
    name = 'analyzeHeadless.bat' if os.name == 'nt' else 'analyzeHeadless'
    bundled = PROJECT_ROOT / 'tools' / 'ghidra'
    for home in [bundled, *sorted(bundled.glob('ghidra_*'), reverse=True)]:
        launcher = home / 'support' / name
        if launcher.is_file():
            return str(launcher.resolve())
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
        if candidate:
            path = Path(candidate)
            path = path if path.is_absolute() else PROJECT_ROOT / path
            if path.is_file():
                return str(path.resolve())
    return ""


@lru_cache(maxsize=8)
def _java_major(executable: str, modified: int) -> int:
    try:
        result = subprocess.run([executable, '-version'], capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=8,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        match = re.search(r'version "(?:1\.)?(\d+)', result.stderr + result.stdout)
        return int(match.group(1)) if result.returncode == 0 and match else 0
    except (OSError, subprocess.TimeoutExpired):
        return 0


def find_java_home() -> str:
    executable = 'java.exe' if os.name == 'nt' else 'java'
    compiler = 'javac.exe' if os.name == 'nt' else 'javac'
    candidates = [PROJECT_ROOT / 'tools/java/jdk-21']
    if os.environ.get('JAVA_HOME'):
        home = Path(os.environ['JAVA_HOME'])
        candidates.append(home if home.is_absolute() else PROJECT_ROOT / home)
    system_java = shutil.which(executable)
    if system_java:
        candidates.append(Path(system_java).resolve().parent.parent)
    for home in candidates:
        java = home / 'bin' / executable
        try:
            if java.is_file() and (home / 'bin' / compiler).is_file() and _java_major(runtime_path(java), java.stat().st_mtime_ns) >= 21:
                return str(home.resolve())
        except OSError:
            continue
    return ''


def headless_command(headless, java_home):
    """Launch the same Java main class without cmd/batch argument reinterpretation."""
    home = Path(headless).parent.parent
    properties = home / 'support/launch.properties'
    options = ['-Djava.system.class.loader=ghidra.GhidraClassLoader', '-Dfile.encoding=UTF8']
    platform_key = 'VMARGS_WINDOWS' if os.name == 'nt' else 'VMARGS_MACOS' if sys.platform == 'darwin' else 'VMARGS_LINUX'
    if properties.is_file():
        for line in properties.read_text(encoding='utf-8').splitlines():
            key, separator, value = line.partition('=')
            if separator and key in {'VMARGS', platform_key} and value.strip():
                options.append(value.strip())
    return [runtime_path(Path(java_home) / 'bin' / ('java.exe' if os.name == 'nt' else 'java')),
            *options, '-Xmx2G', '-XX:ParallelGCThreads=2', '-XX:CICompilerCount=2', '-Djava.awt.headless=true',
            '-cp', runtime_path(home / 'Ghidra/Framework/Utility/lib/Utility.jar'),
            'ghidra.Ghidra', 'ghidra.app.util.headless.AnalyzeHeadless']


def ghidra_status() -> dict:
    headless = find_analyze_headless()
    java_home = find_java_home() if headless else ''
    return {
        "available": bool(headless and java_home),
        "installed": bool(headless),
        "java_available": bool(java_home),
        "analyze_headless": headless,
        "ghidra_home": str(Path(headless).parent.parent) if headless else '',
        "configured_by": "project" if headless and Path(headless).is_relative_to(PROJECT_ROOT / 'tools') else "external" if headless else '',
        "setup_hint": "Chạy python start.py để chuẩn bị Ghidra và Java trong dự án.",
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


def _filter_domains(domains: list[str]) -> list[str]:
    filtered = []
    for domain in domains:
        suffix = domain.rsplit(".", 1)[-1].lower()
        if suffix in NON_DOMAIN_SUFFIXES:
            continue
        if domain not in filtered:
            filtered.append(domain)
    return filtered


def lightweight_static_triage(path: str) -> dict:
    sample = Path(path)
    data = sample.read_bytes()
    lower = data.lower()
    strings = _decode_matches(PRINTABLE_RE.findall(data), limit=200)
    api_hits = [api for api in SUSPICIOUS_APIS if api.lower().encode("ascii") in lower]
    urls = _decode_matches(URL_RE.findall(data), limit=40)
    ips = _decode_matches(IP_RE.findall(data), limit=40)
    domains = _filter_domains(_decode_matches(DOMAIN_RE.findall(data), limit=80))[:40]
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
    java_home = find_java_home()
    if not java_home:
        return {"available": False, "status": "java_unavailable", "error": ghidra_status()["setup_hint"]}
    environment = os.environ.copy()
    environment['JAVA_HOME'] = runtime_path(java_home)
    environment['PATH'] = runtime_path(Path(java_home) / 'bin') + os.pathsep + environment.get('PATH', '')

    scripts_dir = Path(__file__).resolve().parent / "scripts" / "ghidra"
    script_name = "MalwareSummaryExporter.java"
    temp_root = Path(os.environ.get("GHIDRA_TMPDIR") or Path(__file__).resolve().parent / "ghidra_tmp")
    temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ir_ghidra_", dir=str(temp_root)) as tmp:
        project_dir = Path(tmp) / "project"
        output_json = Path(tmp) / "ghidra_summary.json"
        user_profile = Path(tmp) / "profile"
        appdata = user_profile / "AppData" / "Roaming"
        local_appdata = user_profile / "AppData" / "Local"
        project_dir.mkdir(parents=True, exist_ok=True)
        appdata.mkdir(parents=True, exist_ok=True)
        local_appdata.mkdir(parents=True, exist_ok=True)
        env = environment.copy()
        env["USERPROFILE"] = str(user_profile)
        env["APPDATA"] = str(appdata)
        env["LOCALAPPDATA"] = str(local_appdata)
        env["TEMP"] = tmp
        env["TMP"] = tmp
        cmd = [
            *headless_command(headless, java_home),
            runtime_path(project_dir),
            "IRStaticAnalysis",
            "-import",
            runtime_path(path),
            "-overwrite",
            "-analysisTimeoutPerFile",
            str(timeout),
            "-scriptPath",
            runtime_path(scripts_dir),
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
                encoding='utf-8',
                errors='replace',
                cwd=PROJECT_ROOT,
                stdin=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                timeout=timeout + 60,
                check=False,
                env=env,
            )
        except subprocess.TimeoutExpired as exc:
            return {
                "available": True,
                "status": "timeout",
                "error": f"Ghidra vượt quá thời gian {timeout}s",
                "stdout": (exc.stdout.decode('utf-8', errors='replace') if isinstance(exc.stdout, bytes) else exc.stdout or '')[-4000:],
                "stderr": (exc.stderr.decode('utf-8', errors='replace') if isinstance(exc.stderr, bytes) else exc.stderr or '')[-4000:],
            }
        except OSError as exc:
            return {"available": True, "status": "error", "error": f"Không khởi động được Ghidra ({type(exc).__name__})"}

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
    summary = ghidra.get("summary") or {}
    suspicious_apis = sorted(set((triage.get("suspicious_apis") or []) + (summary.get("suspicious_imports") or [])))
    evidence = []
    if suspicious_apis:
        evidence.append("Suspicious APIs: " + ", ".join(suspicious_apis[:8]))
    if triage.get("entropy", 0) >= 7.2:
        evidence.append("High entropy may indicate packing, encryption, or obfuscation.")
    if triage.get("urls") or triage.get("ips") or triage.get("domains"):
        evidence.append("Network strings are present and should be checked against sandbox/proxy/DNS evidence.")
    if triage.get("registry"):
        evidence.append("Registry paths are present and should be checked for persistence.")
    if not evidence:
        evidence.append("No strong malicious static indicator was found in this triage pass.")

    suspicious_score = 0
    suspicious_score += 2 if suspicious_apis else 0
    suspicious_score += 2 if triage.get("entropy", 0) >= 7.2 else 0
    suspicious_score += 1 if triage.get("urls") or triage.get("ips") or triage.get("domains") else 0
    suspicious_score += 1 if triage.get("registry") else 0
    suspicious_score += 1 if ghidra.get("status") == "ok" and summary.get("function_count", 0) > 0 else 0
    if suspicious_score >= 5:
        verdict = "Nghi vấn cao"
        confidence = "medium"
    elif suspicious_score >= 2:
        verdict = "Có dấu hiệu nghi vấn"
        confidence = "low-medium"
    else:
        verdict = "Chưa đủ bằng chứng kết luận mã độc"
        confidence = "low"

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
        "analysis_type": "static",
        "dynamic_analysis": False,
        "malicious_assessment": {
            "verdict": verdict,
            "confidence": confidence,
            "evidence": evidence,
            "limits": [
                "Ghidra/static triage does not execute the file, so it cannot prove runtime behavior.",
                "APIs such as VirtualAlloc, LoadLibrary, or GetProcAddress can also appear in legitimate software.",
                "Use dynamic sandbox evidence such as Any.Run/Cuckoo/EDR logs to confirm behavior.",
            ],
        },
        "static_iocs": static_iocs,
        "recommended_ir_actions": actions,
        "evidence_note": "Đây là phân tích tĩnh: Ghidra không thực thi file. Any.Run/dynamic sandbox mới xác nhận được hành vi runtime.",
    }
