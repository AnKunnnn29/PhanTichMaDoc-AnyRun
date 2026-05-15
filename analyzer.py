"""
analyzer.py
~~~~~~~~~~~
Phân tích kết quả trả về từ Any.Run API và trích xuất
các thông tin quan trọng phục vụ quy trình phản ứng sự cố.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FileInfo:
    name: str
    size: int
    md5: str
    sha1: str
    sha256: str
    file_type: str
    mime_type: str


@dataclass
class ThreatInfo:
    verdict: str          # "Malicious" | "Suspicious" | "No threats detected"
    threat_level: int     # 0-4
    threat_name: str
    tags: List[str]
    mitre_techniques: List[Dict[str, str]]


@dataclass
class NetworkActivity:
    ip_addresses: List[str]
    domains: List[str]
    urls: List[str]
    http_requests: List[Dict]
    dns_queries: List[str]


@dataclass
class ProcessActivity:
    processes: List[Dict]
    injected_processes: List[str]
    dropped_files: List[Dict]
    registry_keys: List[str]
    mutexes: List[str]


@dataclass
class IOCData:
    ips: List[str]
    domains: List[str]
    urls: List[str]
    file_hashes: List[Dict[str, str]]   # [{"md5": ..., "sha256": ...}]
    filenames: List[str]


@dataclass
class MalwareAnalysisResult:
    task_uuid: str
    file_info: Optional[FileInfo]
    threat_info: ThreatInfo
    network: NetworkActivity
    processes: ProcessActivity
    iocs: IOCData
    analysis_url: str
    duration_seconds: int
    os_env: str
    raw_report: Dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Parser / Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class MalwareAnalyzer:
    """
    Phân tích JSON trả về từ Any.Run API và chuẩn hóa thành
    MalwareAnalysisResult để sử dụng trong quy trình phản ứng sự cố.
    """

    # Map threat_level -> verdict label (fallback)
    _VERDICT_MAP = {
        0: "No threats detected",
        1: "Suspicious",
        2: "Malicious",
        3: "Malicious",
        4: "Malicious",
    }

    def parse_report(self, report_json: dict, ioc_json: dict) -> MalwareAnalysisResult:
        """
        Nhận report JSON + IOC JSON từ API, trả về MalwareAnalysisResult.
        """
        data = report_json.get("data", {})
        analysis = data.get("analysis", {})
        content  = data.get("content", {})

        task_uuid    = analysis.get("uuid", "unknown")
        analysis_url = f"https://app.any.run/tasks/{task_uuid}"
        duration     = analysis.get("duration", 0)
        os_env       = analysis.get("options", {}).get("os", {}).get("version", "Unknown OS")

        file_info  = self._parse_file_info(content)
        threat     = self._parse_threat_info(analysis, content)
        network    = self._parse_network(content)
        processes  = self._parse_processes(content)
        iocs       = self._parse_iocs(ioc_json, content)

        return MalwareAnalysisResult(
            task_uuid=task_uuid,
            file_info=file_info,
            threat_info=threat,
            network=network,
            processes=processes,
            iocs=iocs,
            analysis_url=analysis_url,
            duration_seconds=duration,
            os_env=os_env,
            raw_report=report_json,
        )

    # ── Private helpers ──────────────────────────────────────────────────── #

    def _parse_file_info(self, content: dict) -> Optional[FileInfo]:
        main_obj = content.get("mainObject", {})
        if not main_obj:
            return None
        hashes = main_obj.get("hashes", {})
        return FileInfo(
            name      = main_obj.get("filename", "unknown"),
            size      = main_obj.get("size", 0),
            md5       = hashes.get("md5", ""),
            sha1      = hashes.get("sha1", ""),
            sha256    = hashes.get("sha256", ""),
            file_type = main_obj.get("type", ""),
            mime_type = main_obj.get("mime", ""),
        )

    def _parse_threat_info(self, analysis: dict, content: dict) -> ThreatInfo:
        scores = content.get("scores", {})
        verdict_raw = scores.get("verdict", {})
        threat_level = verdict_raw.get("threatLevel", 0)
        verdict_str  = verdict_raw.get("threat", self._VERDICT_MAP.get(threat_level, "Unknown"))
        threat_name  = scores.get("specs", {}).get("knownThreat", "")

        # Tags từ analysis tags
        tags = analysis.get("tags", []) or []

        # MITRE ATT&CK
        mitre = []
        for technique in content.get("mitre", []) or []:
            mitre.append({
                "id":   technique.get("id", ""),
                "name": technique.get("name", ""),
                "tactic": technique.get("tactic", ""),
            })

        return ThreatInfo(
            verdict           = verdict_str,
            threat_level      = threat_level,
            threat_name       = threat_name,
            tags              = tags,
            mitre_techniques  = mitre,
        )

    def _parse_network(self, content: dict) -> NetworkActivity:
        network_data = content.get("network", {}) or {}

        ips     = []
        domains = []
        urls    = []
        http_reqs = []
        dns_queries = []

        # HTTP connections
        for conn in network_data.get("connections", []) or []:
            ip = conn.get("ip", "")
            if ip and ip not in ips:
                ips.append(ip)

        # HTTP requests
        for req in network_data.get("httpRequests", []) or []:
            url = req.get("url", "")
            if url and url not in urls:
                urls.append(url)
            domain = req.get("domain", "")
            if domain and domain not in domains:
                domains.append(domain)
            http_reqs.append({
                "method":      req.get("method", ""),
                "url":         url,
                "status":      req.get("status", ""),
                "user_agent":  req.get("userAgent", ""),
            })

        # DNS
        for dns in network_data.get("dnsRequests", []) or []:
            domain = dns.get("domain", "")
            if domain:
                dns_queries.append(domain)
                if domain not in domains:
                    domains.append(domain)

        return NetworkActivity(
            ip_addresses = ips,
            domains      = domains,
            urls         = urls,
            http_requests= http_reqs,
            dns_queries  = dns_queries,
        )

    def _parse_processes(self, content: dict) -> ProcessActivity:
        procs_raw      = content.get("processes", []) or []
        dropped_files  = content.get("dropped", []) or []
        reg_keys       = []
        mutexes        = []
        injected       = []

        processes = []
        for p in procs_raw:
            proc = {
                "pid":        p.get("pid", 0),
                "ppid":       p.get("ppid", 0),
                "name":       p.get("name", ""),
                "cmd":        p.get("cmd", ""),
                "is_injected": p.get("isInjected", False),
                "score":      p.get("scores", {}).get("verdict", {}).get("threatLevel", 0),
            }
            processes.append(proc)
            if proc["is_injected"]:
                injected.append(proc["name"])

        # Registry keys
        for reg in content.get("registry", []) or []:
            key = reg.get("key", "")
            if key:
                reg_keys.append(key)

        # Mutexes
        for mutex in content.get("synchronization", []) or []:
            name = mutex.get("name", "")
            if name:
                mutexes.append(name)

        return ProcessActivity(
            processes         = processes,
            injected_processes= injected,
            dropped_files     = [
                {
                    "name":   d.get("filename", ""),
                    "sha256": d.get("hashes", {}).get("sha256", ""),
                    "type":   d.get("type", ""),
                }
                for d in dropped_files
            ],
            registry_keys = list(set(reg_keys)),
            mutexes       = list(set(mutexes)),
        )

    def _parse_iocs(self, ioc_json: dict, content: dict) -> IOCData:
        """Parse IOC endpoint response."""
        if isinstance(ioc_json, list):
            ioc_data = ioc_json
        elif isinstance(ioc_json, dict):
            ioc_data = ioc_json.get("data", []) or ioc_json.get("iocs", []) or []
        else:
            ioc_data = []

        ips, domains, urls, hashes, filenames = [], [], [], [], []

        for item in ioc_data:
            if not isinstance(item, dict):
                continue
            ioc_type = item.get("type", "").lower()
            value    = item.get("value", "")

            if ioc_type == "ip":
                if value not in ips:
                    ips.append(value)
            elif ioc_type in ("domain", "hostname"):
                if value not in domains:
                    domains.append(value)
            elif ioc_type == "url":
                if value not in urls:
                    urls.append(value)
            elif ioc_type in ("md5", "sha1", "sha256"):
                entry = {ioc_type: value}
                if entry not in hashes:
                    hashes.append(entry)
            elif ioc_type in ("filename", "filepath"):
                if value not in filenames:
                    filenames.append(value)

        # Bổ sung từ content nếu IOC endpoint thiếu
        main_obj = content.get("mainObject", {})
        if main_obj:
            h = main_obj.get("hashes", {})
            for algo in ("md5", "sha1", "sha256"):
                val = h.get(algo, "")
                if val:
                    entry = {algo: val}
                    if entry not in hashes:
                        hashes.append(entry)
            filename = main_obj.get("filename", "")
            if filename and filename not in filenames:
                filenames.append(filename)

        # Free-account/manual exports often provide only the JSON summary.
        # Derive IOC candidates from the report content when the IOC endpoint
        # export is missing or unavailable.
        network_data = content.get("network", {}) or {}
        for conn in network_data.get("connections", []) or []:
            ip = conn.get("ip", "")
            if ip and ip not in ips:
                ips.append(ip)

        for req in network_data.get("httpRequests", []) or []:
            url = req.get("url", "")
            domain = req.get("domain", "")
            if url and url not in urls:
                urls.append(url)
            if domain and domain not in domains:
                domains.append(domain)

        for dns in network_data.get("dnsRequests", []) or []:
            domain = dns.get("domain", "")
            if domain and domain not in domains:
                domains.append(domain)

        for dropped in content.get("dropped", []) or []:
            filename = dropped.get("filename", "")
            if filename and filename not in filenames:
                filenames.append(filename)
            dropped_hashes = dropped.get("hashes", {}) or {}
            for algo in ("md5", "sha1", "sha256"):
                val = dropped_hashes.get(algo, "")
                entry = {algo: val}
                if val and entry not in hashes:
                    hashes.append(entry)

        return IOCData(
            ips         = ips,
            domains     = domains,
            urls        = urls,
            file_hashes = hashes,
            filenames   = filenames,
        )
