"""Per-destination network profiles built from sandbox evidence, plus read-only abuse.ch lookups.

A profile answers "what is this IP/domain/URL in this case": who talked to it, on which
ports, what was requested, how ANY.RUN rated it, and what external intel says. The role
is a rule-based reading of those facts for analysts; it is not proof of C2 on a real host.
"""
from __future__ import annotations

import ipaddress
import os
import re
import threading
import time
from urllib.parse import urlsplit

import requests

from response_policy import is_protected_destination

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_HOST_URL = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_URL_URL = "https://urlhaus-api.abuse.ch/v1/url/"
MAX_LOOKUPS = 15
LOOKUP_BUDGET_SECONDS = 20
SMB_PORTS = {139, 445}
SMB_SCAN_MIN_TARGETS = 5
REPUTATION_RANK = {"malicious": 3, "suspicious": 2, "unknown": 1, "": 1, "whitelisted": 0}
PAYLOAD_TYPES = {"binary", "executable", "application/x-dosexec", "application/octet-stream"}
PAYLOAD_EXT = re.compile(r"\.(exe|dll|bin|scr|ps1|vbs|js|hta|msi|zip|rar|7z|iso|lnk)(?:$|\?)", re.IGNORECASE)
_cache: dict = {}
_lock = threading.Lock()

ROLE_TEXT = {
    "config_c2": ("Địa chỉ C2 nằm trong cấu hình mã độc mà ANY.RUN trích xuất từ bộ nhớ tiến trình.",
                  "Đây là máy chủ điều khiển của mẫu: máy nhiễm nhận lệnh và gửi dữ liệu đánh cắp (nếu có) tới đây.",
                  "Tìm mọi kết nối tới đích này (kể cả port khác) trong log firewall/proxy/DNS để xác định máy nhiễm thật.",
                  "block_after_verification"),
    "kill_switch": ("Domain kill-switch của WannaCry. Mã độc dừng mã hóa khi truy cập được domain này.",
                    "Chặn domain này có thể làm mã độc tiếp tục mã hóa.",
                    "Giữ cho domain phân giải và truy cập được; ghi nhận máy nào đã truy vấn để khoanh vùng nhiễm.",
                    "do_not_block"),
    "known_c2": ("Nguồn threat intel ghi nhận đích này là hạ tầng điều khiển (C2) của mã độc.",
                 "Máy nhiễm có thể nhận lệnh, tải thêm payload hoặc gửi dữ liệu ra ngoài qua đích này.",
                 "Tìm kết nối tới đích này trong log firewall/proxy/DNS của tổ chức để xác định máy nhiễm thật.",
                 "block_after_verification"),
    "malware_distribution": ("URLhaus ghi nhận đích này phát tán mã độc.",
                             "Máy truy cập có thể đã tải payload độc hại.",
                             "Tìm lượt tải từ đích này trong log proxy; kiểm tra tệp tải về trên endpoint.",
                             "block_after_verification"),
    "smb_propagation": ("Mẫu kết nối SMB tới nhiều địa chỉ khác nhau, dấu hiệu quét/lây lan qua mạng nội bộ.",
                        "Có thể lây sang các máy Windows chưa vá lỗ hổng SMB (ví dụ MS17-010) trong cùng mạng.",
                        "Kiểm tra log firewall nội bộ cho lưu lượng 445/139 bất thường; rà soát máy chưa vá MS17-010.",
                        "contain_segment"),
    "payload_download": ("Tiến trình của mẫu tải nội dung nhị phân/thực thi từ đích này.",
                         "Có thể là giai đoạn tải payload tiếp theo; tệp tải về cần được phân tích.",
                         "Tìm cùng URL/host trong log proxy; đối chiếu hash tệp tải về trên endpoint.",
                         "block_after_verification"),
    "malicious_reported": ("ANY.RUN đánh giá đích này là độc hại.",
                           "Có thể là hạ tầng của mã độc; cần xác định vai trò cụ thể (C2, tải payload, exfiltration).",
                           "Tìm kết nối tới đích này trong log của tổ chức trước khi chặn.",
                           "block_after_verification"),
    "local_network": ("Địa chỉ nội bộ/broadcast trong môi trường sandbox.",
                      "Bản thân địa chỉ này không phải hạ tầng tấn công; chỉ có ý nghĩa nếu đi kèm dấu hiệu quét.",
                      "Không cần tra trên log Internet; chỉ xem xét nếu có lưu lượng SMB/quét đi kèm.",
                      "ignore"),
    "benign_infrastructure": ("ANY.RUN đánh giá whitelisted: lưu lượng hệ thống/dịch vụ phổ biến (ví dụ Microsoft, CDN, OCSP).",
                              "Không có dấu hiệu là hạ tầng của mã độc; thường do Windows hoặc ứng dụng nền tạo ra.",
                              "Không cần chặn. Chỉ xem lại nếu chính tiến trình của mẫu tạo kết nối bất thường tới đích này.",
                              "do_not_block"),
    "dns_only": ("Domain chỉ được phân giải, không thấy kết nối hay HTTP request trong sandbox.",
                 "Chưa có dấu hiệu trao đổi dữ liệu; có thể là kiểm tra kết nối hoặc hạ tầng dự phòng.",
                 "Tìm truy vấn DNS tới domain này trong log DNS của tổ chức.",
                 "monitor"),
    "unverified_destination": ("Đích mạng chưa được xếp loại: không có trong whitelist, chưa có ghi nhận threat intel.",
                               "Chưa đủ bằng chứng để kết luận vai trò; cần đối chiếu thêm.",
                               "Tra cứu thêm và tìm trong log firewall/proxy/DNS trước khi quyết định chặn.",
                               "monitor"),
}
ROLE_SEVERITY = {"config_c2": "critical", "known_c2": "high", "malware_distribution": "high", "smb_propagation": "high", "payload_download": "medium",
                 "malicious_reported": "medium", "kill_switch": "low", "dns_only": "low", "unverified_destination": "unknown",
                 "benign_infrastructure": "low", "local_network": "low"}


def _is_private(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_reserved or str(ip).endswith(".255")


def _worst(reputations) -> str:
    known = [r for r in reputations if r is not None]
    return max(known, key=lambda r: REPUTATION_RANK.get(r, 1)) if known else ""


def build_network_profiles(bundle) -> dict:
    """Aggregate every evidence row of each network observable into one profile."""
    evidence = {e["id"]: e for e in bundle["evidence"]}
    configs = [e for e in bundle["evidence"] if e["type"] == "malware_config"]
    profiles = {}
    smb_targets = {}
    for obs in bundle["observables"]:
        if obs["type"] not in {"ip", "domain", "url"} or not obs["valid"]:
            continue
        p = {"ioc_id": obs["id"], "type": obs["type"], "value": obs["value"], "connections": 0, "ports": set(),
             "processes": {}, "asn": "", "country": "", "reputations": [], "resolved_from": set(), "resolves_to": set(),
             "http": [], "evidence_ids": list(obs["evidence_ids"]), "threat_intel": []}
        for eid in obs["evidence_ids"]:
            row = evidence.get(eid)
            if not row:
                continue
            ctx, path = row["context"], row["source_path"]
            if ctx.get("relation") == "dns_answer":
                p["resolved_from"].add(ctx.get("domain", ""))
            elif "/connections/" in path:
                p["connections"] += 1
                if ctx.get("domain"):
                    p["resolved_from"].add(ctx["domain"])
            elif "/httpRequests/" in path:
                p["http"].append({k: ctx.get(k, "") for k in ("method", "url", "status", "contentType", "size")})
            elif "/dnsRequests/" in path:
                p["resolves_to"].update(ctx.get("ips") or [])
            if isinstance(ctx.get("port"), int):
                p["ports"].add(ctx["port"])
            if ctx.get("process") or ctx.get("pid"):
                p["processes"][f"{ctx.get('process', '')}|{ctx.get('pid')}"] = {"name": ctx.get("process", ""), "pid": ctx.get("pid")}
            p["asn"] = p["asn"] or ctx.get("asn", "")
            p["country"] = p["country"] or ctx.get("country", "")
            if "reputation" in ctx:
                p["reputations"].append(ctx.get("reputation") or "")
            if obs["type"] == "ip" and isinstance(ctx.get("port"), int) and ctx["port"] in SMB_PORTS:
                smb_targets.setdefault(ctx.get("pid") or ctx.get("process"), set()).add(obs["id"])
        # A destination named in the extracted malware config is the sample's own C2 setting.
        for config in configs:
            text = config["value"].lower()
            if obs["value"].lower() in text:
                p["config_family"] = (re.search(r'"family":\s*"([^"]*)"', config["value"]) or [None, ""])[1]
                p["evidence_ids"].append(config["id"])
        profiles[obs["id"]] = p
    # SMB to many distinct hosts from one process reads as scanning/propagation, not as many C2 servers.
    scanners = {pid: targets for pid, targets in smb_targets.items() if len(targets) >= SMB_SCAN_MIN_TARGETS}
    for p in profiles.values():
        p["smb_scan_peers"] = max((len(t) for t in scanners.values() if p["ioc_id"] in t), default=0)
        p["ports"] = sorted(p["ports"])
        p["processes"] = list(p["processes"].values())[:10]
        p["resolved_from"] = sorted(x for x in p["resolved_from"] if x)
        p["resolves_to"] = sorted(p["resolves_to"])[:20]
        p["http"] = p["http"][:10]
        p["reputation"] = _worst(p.pop("reputations"))
        classify(p)
    return profiles


def classify(p: dict) -> dict:
    """Pick one role from the facts (and intel, when present) and write the analyst-facing text."""
    host = urlsplit(p["value"]).hostname if p["type"] == "url" else p["value"]
    intel = p.get("threat_intel", [])
    downloads = [h for h in p["http"] if str(h.get("contentType", "")).lower() in PAYLOAD_TYPES or PAYLOAD_EXT.search(str(h.get("url", "")))]
    if host and is_protected_destination(host):
        role = "kill_switch"
    elif "config_family" in p:
        role = "config_c2"
    elif any(i["found"] and i["source"] == "threatfox" for i in intel):
        role = "known_c2"
    elif any(i["found"] and i["source"] == "urlhaus" for i in intel):
        role = "malware_distribution"
    elif p.get("smb_scan_peers"):
        role = "smb_propagation"
    elif p["type"] == "ip" and _is_private(p["value"]):
        role = "local_network"
    elif p["reputation"] == "malicious":
        role = "malicious_reported"
    elif downloads and p["reputation"] != "whitelisted":
        role = "payload_download"
    elif p["reputation"] == "whitelisted":
        role = "benign_infrastructure"
    elif p["type"] == "domain" and not p["connections"] and not p["http"]:
        role = "dns_only"
    else:
        role = "unverified_destination"
    meaning, impact, verify, response = ROLE_TEXT[role]
    facts = []
    if p["processes"]:
        facts.append("tiến trình " + ", ".join(f"{x['name'] or '?'}" + (f" (PID {x['pid']})" if x["pid"] else "") for x in p["processes"][:3]))
    if p["connections"]:
        facts.append(f"{p['connections']} kết nối" + (f" tới port {', '.join(map(str, p['ports']))}" if p["ports"] else ""))
    if p["http"]:
        first = p["http"][0]
        facts.append(f"{len(p['http'])} HTTP request (ví dụ {first.get('method', '')} {str(first.get('url', ''))[:80]})")
    if p["resolved_from"]:
        facts.append("được phân giải từ " + ", ".join(p["resolved_from"][:3]))
    if p["resolves_to"]:
        facts.append("phân giải ra " + ", ".join(p["resolves_to"][:3]) + ("…" if len(p["resolves_to"]) > 3 else ""))
    if p["asn"] or p["country"]:
        facts.append("mạng " + " / ".join(x for x in (p["asn"], p["country"]) if x))
    if "config_family" in p:
        facts.append(f"có trong cấu hình {p['config_family'] or 'mã độc'} trích xuất được")
    if p.get("smb_scan_peers"):
        facts.append(f"cùng tiến trình kết nối SMB tới {p['smb_scan_peers']} địa chỉ")
    for i in intel:
        if i["found"]:
            facts.append(f"{i['source']}: " + ", ".join(str(x) for x in (i.get("malware"), i.get("threat_type")) if x))
    p.update({"role": role, "meaning": meaning, "impact": impact, "verify": verify, "response": response,
              "severity": ROLE_SEVERITY[role],
              "summary": meaning + (" Dữ kiện: " + "; ".join(facts) + "." if facts else "") +
                         (f" ANY.RUN: {p['reputation']}." if p["reputation"] else "")})
    return p


def _auth_key() -> str:
    return (os.getenv("ABUSECH_AUTH_KEY") or os.getenv("MALWAREBAZAAR_AUTH_KEY", "")).strip()


def lookups_enabled() -> bool:
    return bool(_auth_key()) and os.getenv("NETWORK_INTEL_LOOKUPS", "1") != "0"


def _post(url, **kwargs):
    response = requests.post(url, headers={"Auth-Key": _auth_key()}, timeout=(4, 8), **kwargs)
    response.raise_for_status()
    body = response.json()
    if not isinstance(body, dict):
        raise ValueError("unexpected response")
    return body


def _threatfox(term: str) -> dict:
    body = _post(THREATFOX_URL, json={"query": "search_ioc", "search_term": term})
    rows = body.get("data") if body.get("query_status") == "ok" and isinstance(body.get("data"), list) else []
    row = next((r for r in rows if isinstance(r, dict)), None)
    if not row:
        return {"source": "threatfox", "term": term, "found": False}
    return {"source": "threatfox", "term": term, "found": True, "malware": str(row.get("malware_printable") or "")[:100],
            "threat_type": str(row.get("threat_type") or "")[:60], "confidence": row.get("confidence_level"),
            "first_seen": str(row.get("first_seen") or "")[:40], "last_seen": str(row.get("last_seen") or "")[:40],
            "reference": f"https://threatfox.abuse.ch/ioc/{row.get('id')}/" if row.get("id") else ""}


def _urlhaus(kind: str, value: str) -> dict:
    body = _post(URLHAUS_URL_URL if kind == "url" else URLHAUS_HOST_URL, data={"url" if kind == "url" else "host": value})
    if body.get("query_status") != "ok":
        return {"source": "urlhaus", "term": value, "found": False}
    urls = body.get("urls") if isinstance(body.get("urls"), list) else []
    return {"source": "urlhaus", "term": value, "found": True,
            "threat_type": str(body.get("threat") or (urls[0].get("threat") if urls and isinstance(urls[0], dict) else "") or "")[:60],
            "malware": ", ".join(sorted({str(t) for u in urls if isinstance(u, dict) for t in (u.get("tags") or [])}))[:120],
            "url_count": body.get("url_count") or len(urls), "reference": str(body.get("urlhaus_reference") or "")[:200]}


def _cached(key, fn):
    with _lock:
        hit = _cache.get(key)
        if hit and hit[0] > time.monotonic():
            return dict(hit[1])
    result = fn()
    with _lock:
        if len(_cache) >= 512:
            _cache.pop(next(iter(_cache)))
        _cache[key] = (time.monotonic() + 600, dict(result))
    return result


def enrich_network_profiles(profiles: dict, enabled: bool = True) -> dict:
    """Look up the most relevant non-whitelisted public destinations; never the whole list."""
    status = {"enabled": enabled and lookups_enabled(), "looked_up": 0, "errors": 0, "skipped": 0,
              "sources": ["ThreatFox", "URLhaus"], "note": "Thông tin tham khảo bên ngoài, không phải bằng chứng trên endpoint."}
    if not status["enabled"]:
        return status
    candidates = [p for p in profiles.values() if p["role"] not in {"benign_infrastructure", "local_network", "kill_switch"}]
    candidates.sort(key=lambda p: (-REPUTATION_RANK.get(p["reputation"], 1), -p["connections"], -len(p["http"])))
    started = time.monotonic()
    for p in candidates:
        if status["looked_up"] >= MAX_LOOKUPS or time.monotonic() - started > LOOKUP_BUDGET_SECONDS:
            status["skipped"] += 1
            continue
        terms = [p["value"]] + ([f"{p['value']}:{port}" for port in p["ports"][:2]] if p["type"] == "ip" else [])
        try:
            for term in terms:
                hit = _cached(("tf", term), lambda t=term: _threatfox(t))
                if hit["found"] or term == terms[-1]:
                    p["threat_intel"].append(hit)
                    break
            if p["type"] in {"domain", "url"}:
                p["threat_intel"].append(_cached(("uh", p["type"], p["value"]), lambda: _urlhaus(p["type"], p["value"])))
            status["looked_up"] += 1
        except (requests.RequestException, ValueError):
            status["errors"] += 1
        classify(p)
    return status
