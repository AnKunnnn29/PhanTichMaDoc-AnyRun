"""
incident_response.py
~~~~~~~~~~~~~~~~~~~~
Sinh quy trình phản ứng sự cố (Incident Response Playbook)
dựa trên kết quả phân tích mã độc từ Any.Run.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict
from analyzer import MalwareAnalysisResult


# ─────────────────────────────────────────────────────────────────────────────
# Data models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class IncidentAction:
    priority: int           # 1 = Critical, 2 = High, 3 = Medium, 4 = Low
    phase: str              # NIST IR phases
    category: str
    title: str
    description: str
    commands: List[str] = field(default_factory=list)
    notes: List[str]   = field(default_factory=list)
    owner: str = ""
    sla: str = ""
    evidence_required: List[str] = field(default_factory=list)
    status: str = "pending"


@dataclass
class IncidentResponsePlaybook:
    """Quy trình phản ứng sự cố đầy đủ."""
    malware_name: str
    severity: str
    threat_level: int
    summary: str
    actions: List[IncidentAction]
    ioc_blocklist: Dict[str, List[str]]   # {"ips": [...], "domains": [...], ...}
    mitigation_summary: str
    affected_os: str
    severity_score: Dict = field(default_factory=dict)
    timeline: List[Dict] = field(default_factory=list)
    scope_hunting: List[Dict] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Playbook generator
# ─────────────────────────────────────────────────────────────────────────────

class IncidentResponseGenerator:
    """
    Phân tích MalwareAnalysisResult và tự động tạo ra
    IncidentResponsePlaybook phù hợp.
    """

    _SEVERITY_MAP = {
        0: ("Thấp",       "LOW"),
        1: ("Trung bình", "MEDIUM"),
        2: ("Cao",        "HIGH"),
        3: ("Nghiêm trọng","CRITICAL"),
        4: ("Nghiêm trọng","CRITICAL"),
    }

    # NIST 800-61 phases
    PHASES = {
        "PREPARE":      "Chuẩn bị (Preparation)",
        "IDENTIFY":     "Xác định (Identification)",
        "CONTAIN":      "Ngăn chặn (Containment)",
        "ERADICATE":    "Loại bỏ (Eradication)",
        "RECOVER":      "Phục hồi (Recovery)",
        "LESSONS":      "Rút kinh nghiệm (Lessons Learned)",
    }

    def generate(self, result: MalwareAnalysisResult) -> IncidentResponsePlaybook:
        threat  = result.threat_info
        network = result.network
        procs   = result.processes
        iocs    = result.iocs
        file    = result.file_info

        severity_vi, severity_en = self._SEVERITY_MAP.get(
            threat.threat_level, ("Không xác định", "UNKNOWN")
        )

        malware_name = threat.threat_name or ", ".join(threat.tags) or "Unknown Malware"
        severity_score = self._build_severity_score(result)
        timeline = self._build_timeline(result)
        scope_hunting = self._build_scope_hunting(result)

        actions: List[IncidentAction] = []

        # ── Phase 1: Identification ──────────────────────────────────────── #
        actions.append(IncidentAction(
            priority=1,
            phase=self.PHASES["IDENTIFY"],
            category="Thu thập bằng chứng",
            title="Xác nhận và ghi lại thông tin mẫu mã độc",
            description=(
                f"Xác nhận đây là mã độc loại '{malware_name}' với mức độ nguy hiểm "
                f"'{severity_vi}' (threat level {threat.threat_level}/4). "
                f"Lưu trữ report đầy đủ từ Any.Run để phục vụ điều tra."
            ),
            notes=[
                f"Any.Run report URL: {result.analysis_url}",
                f"Thời gian phân tích: {result.duration_seconds}s trên {result.os_env}",
                f"MITRE techniques: {len(threat.mitre_techniques)} kỹ thuật được phát hiện",
            ],
        ))

        if file:
            hash_info = f"MD5={file.md5} | SHA256={file.sha256}"
            actions.append(IncidentAction(
                priority=1,
                phase=self.PHASES["IDENTIFY"],
                category="Phân tích mẫu",
                title="Lưu trữ hash và thông tin file mã độc",
                description=(
                    f"File '{file.name}' ({file.file_type}, "
                    f"{self._fmt_size(file.size)}) đã được xác nhận là mã độc."
                ),
                commands=[
                    f'certutil -hashfile "<đường_dẫn_file>" MD5',
                    f'certutil -hashfile "<đường_dẫn_file>" SHA256',
                    f"# Kiểm tra trên VirusTotal: https://www.virustotal.com/gui/file/{file.sha256}",
                ],
                notes=[hash_info],
            ))

        # ── Phase 2: Containment ─────────────────────────────────────────── #
        if network.ip_addresses or network.domains:
            block_rules = []
            for ip in network.ip_addresses[:10]:
                block_rules.append(f'netsh advfirewall firewall add rule name="Block_IR_{ip}" dir=out action=block remoteip={ip}')
            actions.append(IncidentAction(
                priority=1,
                phase=self.PHASES["CONTAIN"],
                category="Cô lập mạng",
                title="Chặn kết nối C2 tại tường lửa",
                description=(
                    f"Phát hiện {len(network.ip_addresses)} địa chỉ IP và "
                    f"{len(network.domains)} domain nghi ngờ C2. "
                    "Chặn ngay các kết nối này tại firewall và DNS."
                ),
                commands=block_rules + [
                    "# Chặn DNS - thêm vào file hosts:",
                    *[f"0.0.0.0 {d}" for d in network.domains[:10]],
                ],
                notes=[
                    "Kiểm tra tất cả thiết bị trong mạng nội bộ xem có kết nối đến các IP/domain trên không.",
                    "Xem xét cô lập hoàn toàn máy bị nhiễm khỏi mạng LAN.",
                ],
            ))

        if procs.injected_processes:
            actions.append(IncidentAction(
                priority=1,
                phase=self.PHASES["CONTAIN"],
                category="Cô lập tiến trình",
                title="Dừng các tiến trình bị inject mã độc",
                description=(
                    f"Phát hiện {len(procs.injected_processes)} tiến trình bị inject: "
                    f"{', '.join(procs.injected_processes[:5])}. "
                    "Cần dừng ngay trước khi tiến hành xóa."
                ),
                commands=[
                    f'taskkill /F /IM "{p}" /T'
                    for p in procs.injected_processes[:5]
                ],
                notes=["Ghi lại process tree trước khi kill bằng Process Hacker/ProcMon."],
            ))

        # Persistence mechanism
        if procs.registry_keys:
            suspicious_keys = [k for k in procs.registry_keys
                               if any(s in k.lower() for s in ["run", "startup", "winlogon", "shell", "appinit"])]
            if suspicious_keys:
                actions.append(IncidentAction(
                    priority=2,
                    phase=self.PHASES["CONTAIN"],
                    category="Persistence",
                    title="Vô hiệu hóa cơ chế duy trì (Persistence)",
                    description=(
                        f"Phát hiện {len(suspicious_keys)} registry key liên quan đến persistence. "
                        "Xóa các key này để ngăn mã độc tự khởi động lại."
                    ),
                    commands=[
                        f'reg delete "{k}" /f' for k in suspicious_keys[:5]
                    ],
                    notes=["Export registry backup trước khi xóa: reg export HKLM\\SOFTWARE backup.reg"],
                ))

        # ── Phase 3: Eradication ─────────────────────────────────────────── #
        eradicate_cmds = [
            "# Quét toàn bộ hệ thống với Windows Defender (đã cập nhật):",
            "Start-MpScan -ScanType FullScan",
            "",
            "# Kiểm tra Scheduled Tasks độc hại:",
            "Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Format-List",
            "",
            "# Kiểm tra dịch vụ độc hại:",
            "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName",
        ]

        if procs.dropped_files:
            eradicate_cmds += [
                "",
                "# Xóa các file mã độc đã drop:",
                *[f'Remove-Item -Force "{f["name"]}" -ErrorAction SilentlyContinue'
                  for f in procs.dropped_files[:5]],
            ]

        actions.append(IncidentAction(
            priority=2,
            phase=self.PHASES["ERADICATE"],
            category="Dọn dẹp hệ thống",
            title="Loại bỏ toàn bộ thành phần mã độc",
            description=(
                f"Xóa {len(procs.dropped_files)} file đã drop, "
                f"dọn dẹp registry và scheduled tasks. "
                "Chạy antivirus quét toàn bộ sau khi xử lý thủ công."
            ),
            commands=eradicate_cmds,
            notes=[
                "Nếu có file được bảo vệ, restart vào Safe Mode để xóa.",
                "Kiểm tra Recycle Bin và %TEMP% folder.",
            ],
        ))

        # ── MITRE ATT&CK specific actions ───────────────────────────────── #
        if threat.mitre_techniques:
            self._add_mitre_actions(actions, threat.mitre_techniques)

        if scope_hunting:
            actions.append(IncidentAction(
                priority=2,
                phase=self.PHASES["IDENTIFY"],
                category="Threat hunting / Scope",
                title="Xác định phạm vi ảnh hưởng trong log nội bộ",
                description=(
                    "Dùng IOC và artifact từ Any.Run để truy vấn DNS/proxy/firewall/EDR, "
                    "tìm host và user khác có dấu hiệu liên quan trước khi kết luận sự cố đã được khoanh vùng."
                ),
                commands=[item["query"] for item in scope_hunting[:6] if item.get("query")],
                notes=[
                    "Truy vấn tối thiểu 7 ngày, ưu tiên 30 ngày nếu có dấu hiệu credential theft/C2.",
                    "Mỗi host match IOC phải được đưa vào danh sách containment hoặc triage riêng.",
                ],
                owner="SOC L2 / Threat Hunter",
                sla="1 giờ",
                evidence_required=["DNS/proxy/firewall query result", "EDR host list", "Affected user list"],
            ))

        # ── Phase 4: Recovery ────────────────────────────────────────────── #
        actions.append(IncidentAction(
            priority=3,
            phase=self.PHASES["RECOVER"],
            category="Phục hồi hệ thống",
            title="Khôi phục hệ thống về trạng thái an toàn",
            description="Sau khi đã loại bỏ mã độc, tiến hành khôi phục và hardening hệ thống.",
            commands=[
                "# Cập nhật Windows:",
                "Install-WindowsUpdate -AcceptAll -AutoReboot",
                "",
                "# Reset mật khẩu tất cả tài khoản (phòng credential theft):",
                "# Thực hiện qua Active Directory hoặc Local Users and Groups",
                "",
                "# Bật lại các dịch vụ bảo mật:",
                'Set-MpPreference -DisableRealtimeMonitoring $false',
                "netsh advfirewall set allprofiles state on",
            ],
            notes=[
                "Không kết nối lại mạng cho đến khi xác nhận hệ thống sạch.",
                "Thực hiện vulnerability scan sau khi phục hồi.",
                "Cân nhắc reinstall OS nếu phát hiện rootkit.",
            ],
        ))

        # ── Phase 5: Lessons Learned ─────────────────────────────────────── #
        actions.append(IncidentAction(
            priority=4,
            phase=self.PHASES["LESSONS"],
            category="Rút kinh nghiệm",
            title="Viết báo cáo sự cố và cải thiện phòng thủ",
            description="Tài liệu hóa sự cố, timeline, và các biện pháp cải thiện.",
            notes=[
                "Xác định điểm xâm nhập ban đầu (phishing? drive-by? USB?).",
                "Cập nhật SIEM rules dựa trên IOC mới phát hiện.",
                f"Thêm {len(iocs.ips)} IP và {len(iocs.domains)} domain vào threat intel feed.",
                "Đào tạo lại nhân viên về nhận biết phishing nếu đây là vector lây nhiễm.",
                "Xem xét triển khai EDR/XDR nếu chưa có.",
            ],
        ))

        # ── IOC Blocklist ─────────────────────────────────────────────────── #
        ioc_blocklist = {
            "ip_addresses": iocs.ips,
            "domains":      iocs.domains,
            "urls":         iocs.urls,
            "file_hashes":  [list(h.values())[0] for h in iocs.file_hashes],
            "filenames":    iocs.filenames,
        }

        # ── Summary ───────────────────────────────────────────────────────── #
        summary = (
            f"Phát hiện mã độc '{malware_name}' với mức độ '{severity_vi}'. "
            f"Mã độc thực hiện {len(threat.mitre_techniques)} kỹ thuật MITRE ATT&CK, "
            f"kết nối {len(network.ip_addresses)} IP/{len(network.domains)} domain C2, "
            f"và tạo {len(procs.dropped_files)} file độc hại trên hệ thống. "
            f"Ma trận rủi ro nội bộ chấm {severity_score['score']}/100 "
            f"({severity_score['recommended_severity']})."
        )

        mitigation = (
            f"Ưu tiên: (1) Cô lập máy bị nhiễm ngay lập tức. "
            f"(2) Chặn {len(ioc_blocklist['ip_addresses'])} IP và "
            f"{len(ioc_blocklist['domains'])} domain tại firewall/DNS. "
            f"(3) Xóa {len(procs.dropped_files)} file độc hại. "
            f"(4) Reset credential toàn bộ user bị ảnh hưởng. "
            f"(5) Patch lỗ hổng bị khai thác nếu xác định được."
        )

        for action in actions:
            self._apply_operational_defaults(action)

        return IncidentResponsePlaybook(
            malware_name       = malware_name,
            severity           = severity_en,
            threat_level       = threat.threat_level,
            summary            = summary,
            actions            = sorted(actions, key=lambda a: a.priority),
            ioc_blocklist      = ioc_blocklist,
            mitigation_summary = mitigation,
            affected_os        = result.os_env,
            severity_score     = severity_score,
            timeline           = timeline,
            scope_hunting      = scope_hunting,
        )

    def _build_severity_score(self, result: MalwareAnalysisResult) -> Dict:
        threat = result.threat_info
        network = result.network
        procs = result.processes
        technique_ids = self._technique_ids(threat.mitre_techniques)

        score = max(0, min(int(threat.threat_level), 4)) * 15
        reasons = [f"Any.Run threat level {threat.threat_level}/4"]

        if network.ip_addresses or network.domains or network.urls:
            score += 15
            reasons.append("Có IOC mạng/C2 cần hunting và block")
        if procs.injected_processes or any(t.startswith("T1055") for t in technique_ids):
            score += 15
            reasons.append("Có process injection/defense evasion")
        if procs.registry_keys or any(t.startswith("T1547") for t in technique_ids):
            score += 10
            reasons.append("Có dấu hiệu persistence")
        if procs.dropped_files:
            score += 10
            reasons.append("Có dropped files cần eradication")
        if any(t.startswith(("T1555", "T1003", "T1056", "T1041")) for t in technique_ids):
            score += 20
            reasons.append("Có khả năng credential theft/exfiltration")
        if any(t.startswith("T1486") for t in technique_ids):
            score += 30
            reasons.append("Có hành vi ransomware/impact")

        score = min(score, 100)
        if score >= 80:
            recommended = "CRITICAL"
        elif score >= 60:
            recommended = "HIGH"
        elif score >= 30:
            recommended = "MEDIUM"
        else:
            recommended = "LOW"

        return {
            "score": score,
            "recommended_severity": recommended,
            "model": "Any.Run level + IOC/TTP operational impact",
            "reasons": reasons,
        }

    def _build_timeline(self, result: MalwareAnalysisResult) -> List[Dict]:
        timeline: List[Dict] = []
        threat = result.threat_info
        file = result.file_info
        procs = result.processes
        network = result.network
        technique_ids = self._technique_ids(threat.mitre_techniques)

        timeline.append({
            "step": 1,
            "stage": "Intake",
            "event": "Nhận file/URL nghi vấn và chạy phân tích động trên Any.Run",
            "evidence": result.analysis_url,
            "mitre": "",
            "ir_action": "Lưu report, hash, task UUID làm bằng chứng ban đầu",
        })
        if file:
            timeline.append({
                "step": len(timeline) + 1,
                "stage": "Execution",
                "event": f"Mẫu chính được thực thi/quan sát: {file.name}",
                "evidence": file.sha256 or file.md5 or file.name,
                "mitre": self._join_matching_ids(technique_ids, ("T1204", "T1059")),
                "ir_action": "Xác định host/user đã khởi chạy file tương tự",
            })
        if procs.injected_processes:
            timeline.append({
                "step": len(timeline) + 1,
                "stage": "Defense Evasion",
                "event": "Process injection vào: " + ", ".join(procs.injected_processes[:5]),
                "evidence": ", ".join(procs.injected_processes[:5]),
                "mitre": self._join_matching_ids(technique_ids, ("T1055",)),
                "ir_action": "Dump memory trước khi kill process, sau đó isolate endpoint",
            })
        if procs.registry_keys:
            timeline.append({
                "step": len(timeline) + 1,
                "stage": "Persistence",
                "event": f"Phát hiện {len(procs.registry_keys)} registry/autostart artifact",
                "evidence": "; ".join(procs.registry_keys[:3]),
                "mitre": self._join_matching_ids(technique_ids, ("T1547",)),
                "ir_action": "Export registry backup và gỡ persistence sau khi thu thập bằng chứng",
            })
        if network.ip_addresses or network.domains or network.urls:
            ioc_preview = ", ".join((network.ip_addresses + network.domains + network.urls)[:5])
            timeline.append({
                "step": len(timeline) + 1,
                "stage": "Command and Control",
                "event": "Liên lạc hạ tầng C2 hoặc tải payload",
                "evidence": ioc_preview,
                "mitre": self._join_matching_ids(technique_ids, ("T1071", "T1105")),
                "ir_action": "Block IOC và hunt trên DNS/proxy/firewall log",
            })
        if procs.dropped_files:
            timeline.append({
                "step": len(timeline) + 1,
                "stage": "Payload / Artifact",
                "event": f"Tạo/drop {len(procs.dropped_files)} file trên hệ thống",
                "evidence": ", ".join(f.get("name", "") for f in procs.dropped_files[:5]),
                "mitre": "",
                "ir_action": "So khớp hash/file path trên EDR và xóa sau containment",
            })
        if any(t.startswith("T1486") for t in technique_ids):
            timeline.append({
                "step": len(timeline) + 1,
                "stage": "Impact",
                "event": "Dấu hiệu mã hóa dữ liệu/ransomware",
                "evidence": "MITRE T1486",
                "mitre": self._join_matching_ids(technique_ids, ("T1486",)),
                "ir_action": "Cô lập khẩn cấp, bảo vệ backup offline, không tắt máy nếu cần memory",
            })
        return timeline

    def _build_scope_hunting(self, result: MalwareAnalysisResult) -> List[Dict]:
        iocs = result.iocs
        procs = result.processes
        technique_ids = self._technique_ids(result.threat_info.mitre_techniques)
        hunts: List[Dict] = []

        if iocs.ips or iocs.domains or iocs.urls:
            terms = iocs.ips + iocs.domains + iocs.urls
            quoted = ", ".join(f'"{item}"' for item in terms[:20])
            hunts.append({
                "priority": "P1",
                "data_source": "DNS / Proxy / Firewall",
                "question": "Host nào đã kết nối tới IOC C2?",
                "query": f"index=* ({quoted}) | stats earliest(_time) latest(_time) values(user) by host src_ip",
                "evidence": "Danh sách host, user, thời gian kết nối IOC",
            })
        hash_values = [list(item.values())[0] for item in iocs.file_hashes if item]
        if hash_values or iocs.filenames:
            values = hash_values + iocs.filenames
            quoted = ", ".join(f'"{item}"' for item in values[:20])
            hunts.append({
                "priority": "P1",
                "data_source": "EDR / AV telemetry",
                "question": "Endpoint nào có file hash/tên file trùng IOC?",
                "query": f"DeviceFileEvents | where SHA256 in ({quoted}) or FileName in ({quoted})",
                "evidence": "Host, file path, SHA256, action taken của EDR",
            })
        process_names = [p.get("name", "") for p in procs.processes if p.get("name")]
        if process_names or procs.injected_processes:
            values = list(dict.fromkeys(procs.injected_processes + process_names))[:20]
            quoted = ", ".join(f'"{item}"' for item in values)
            hunts.append({
                "priority": "P2",
                "data_source": "Process telemetry",
                "question": "Process tree nào chạy giống sandbox?",
                "query": f"DeviceProcessEvents | where FileName in ({quoted}) | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName",
                "evidence": "Process command line, parent process, user thực thi",
            })
        if procs.registry_keys:
            quoted = ", ".join(f'"{item}"' for item in procs.registry_keys[:20])
            hunts.append({
                "priority": "P2",
                "data_source": "Registry telemetry",
                "question": "Máy nào có persistence registry tương tự?",
                "query": f"DeviceRegistryEvents | where RegistryKey in ({quoted})",
                "evidence": "Registry key/value, device, user, timestamp",
            })
        if any(t.startswith("T1566") for t in technique_ids):
            hunts.append({
                "priority": "P2",
                "data_source": "Email gateway / M365",
                "question": "Email nào phát tán file/link ban đầu?",
                "query": "EmailEvents | join EmailAttachmentInfo on NetworkMessageId | where SHA256 has_any (dynamic([\"<sample_sha256>\"]))",
                "evidence": "Sender, recipient, subject, attachment hash, delivery status",
            })
        return hunts

    def _apply_operational_defaults(self, action: IncidentAction) -> None:
        phase = action.phase.lower()
        category = action.category.lower()

        if not action.owner:
            if "containment" in phase or "cô lập" in category or "ransomware" in category:
                action.owner = "IR Lead / Network Admin"
            elif "eradication" in phase or "loại" in phase or "persistence" in category:
                action.owner = "System Admin / SOC L2"
            elif "recovery" in phase or "phục hồi" in phase:
                action.owner = "System Admin"
            elif "lessons" in phase or "rút" in phase:
                action.owner = "IR Lead"
            else:
                action.owner = "SOC L2"

        if not action.sla:
            action.sla = {1: "15 phút", 2: "1 giờ", 3: "4 giờ", 4: "3 ngày"}.get(action.priority, "4 giờ")

        if not action.evidence_required:
            if "containment" in phase:
                action.evidence_required = ["Firewall/EDR block confirmation", "Host isolation timestamp"]
            elif "eradication" in phase or "loại" in phase:
                action.evidence_required = ["Deleted artifact list", "AV/EDR scan result"]
            elif "recovery" in phase or "phục hồi" in phase:
                action.evidence_required = ["Clean scan result", "Business owner approval"]
            elif "lessons" in phase or "rút" in phase:
                action.evidence_required = ["Final incident report", "Updated detection/control record"]
            else:
                action.evidence_required = ["Any.Run report", "IOC list", "Relevant log excerpt"]

    @staticmethod
    def _technique_ids(techniques: List[Dict]) -> set[str]:
        return {str(t.get("id", "")).upper() for t in techniques if t.get("id")}

    @staticmethod
    def _join_matching_ids(technique_ids: set[str], prefixes: tuple[str, ...]) -> str:
        return ", ".join(sorted(t for t in technique_ids if t.startswith(prefixes)))

    # ── MITRE ATT&CK specific responses ────────────────────────────────── #

    def _add_mitre_actions(
        self, actions: List[IncidentAction], techniques: List[Dict]
    ) -> None:
        """Thêm actions đặc biệt dựa trên MITRE ATT&CK techniques."""
        technique_ids = {t.get("id", "").upper() for t in techniques}

        # T1566 - Phishing (match cả base ID lẫn sub-techniques: T1566.001, T1566.002, …)
        if any(t.startswith("T1566") for t in technique_ids):
            actions.append(IncidentAction(
                priority=2,
                phase=self.PHASES["IDENTIFY"],
                category="MITRE ATT&CK - T1566",
                title="[Phishing] Kiểm tra email và quarantine",
                description="Mã độc có dấu hiệu lây nhiễm qua Phishing email.",
                commands=[
                    "# Tìm kiếm email tương tự trong Exchange/M365:",
                    "Search-Mailbox -SearchQuery 'subject:<tên_file>' -TargetMailbox admin",
                    "# Hoặc dùng Microsoft Purview Content Search",
                ],
                notes=["Kiểm tra header email để xác định sender thật.", "Report phishing email cho nhà cung cấp."],
            ))

        # T1055 - Process Injection
        if any(t.startswith("T1055") for t in technique_ids):
            actions.append(IncidentAction(
                priority=1,
                phase=self.PHASES["CONTAIN"],
                category="MITRE ATT&CK - T1055",
                title="[Process Injection] Phân tích bộ nhớ",
                description="Phát hiện kỹ thuật process injection. Dump memory để phân tích chi tiết.",
                commands=[
                    "# Dùng Volatility để dump memory:",
                    "volatility -f memory.dmp --profile=Win10x64 pslist",
                    "volatility -f memory.dmp --profile=Win10x64 malfind",
                    "# Dùng Procdump để dump process:",
                    "procdump.exe -ma <PID> dump.dmp",
                ],
                notes=["Ưu tiên dump memory TRƯỚC khi kill process."],
            ))

        # T1547 - Boot/Logon Autostart
        if any(t.startswith("T1547") for t in technique_ids):
            actions.append(IncidentAction(
                priority=2,
                phase=self.PHASES["ERADICATE"],
                category="MITRE ATT&CK - T1547",
                title="[Persistence] Kiểm tra autostart locations",
                description="Phát hiện persistence thông qua autostart. Kiểm tra toàn bộ autorun locations.",
                commands=[
                    "# Dùng Autoruns (Sysinternals):",
                    "autorunsc.exe -a * -o autoruns_output.csv",
                    "",
                    "# PowerShell - Kiểm tra Run keys:",
                    "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "",
                    "# Scheduled Tasks:",
                    "Get-ScheduledTask | Where {$_.Actions.Execute -like '*.tmp*' -or $_.Actions.Execute -like '%appdata%'}",
                ],
            ))

        # T1082 / T1057 - Discovery
        if any(t.startswith(("T1082", "T1057", "T1083", "T1033")) for t in technique_ids):
            actions.append(IncidentAction(
                priority=3,
                phase=self.PHASES["IDENTIFY"],
                category="MITRE ATT&CK - Discovery",
                title="[Recon] Đánh giá phạm vi xâm phạm",
                description="Mã độc thực hiện system/process discovery. Cần xác định thông tin nào đã bị thu thập.",
                notes=[
                    "Kiểm tra network traffic để xem dữ liệu nào đã được gửi ra ngoài.",
                    "Xem xét DLP (Data Loss Prevention) logs nếu có.",
                    "Kiểm tra xem credential nào đã bị tiếp cận.",
                ],
            ))

        # T1486 - Data Encrypted (Ransomware)
        if any(t.startswith("T1486") for t in technique_ids):
            actions.append(IncidentAction(
                priority=1,
                phase=self.PHASES["CONTAIN"],
                category="MITRE ATT&CK - T1486 (RANSOMWARE)",
                title="[RANSOMWARE] Cô lập khẩn cấp và dừng mã hóa",
                description=(
                    "⚠️ PHÁT HIỆN MÃ ĐỘC RANSOMWARE! "
                    "Cần cô lập ngay lập tức để ngăn lây lan và mã hóa thêm dữ liệu."
                ),
                commands=[
                    "# Dừng Volume Shadow Copy deletion (nếu chưa bị xóa):",
                    "vssadmin list shadows",
                    "",
                    "# Ngắt kết nối mạng NGAY LẬP TỨC:",
                    "netsh interface set interface 'Ethernet' disable",
                    "",
                    "# KHÔNG TẮT MÁY - backup memory trước:",
                    "# Chụp memory dump với Belkasoft RAM Capturer hoặc WinPmem",
                ],
                notes=[
                    "KHÔNG trả tiền chuộc - liên hệ nhà chức trách.",
                    "Kiểm tra nomoreransom.org để tìm decryptor miễn phí.",
                    "Phục hồi từ backup OFFLINE (kiểm tra backup không bị nhiễm).",
                    "Báo cáo ngay cho CERT/VNCERT.",
                ],
            ))

    @staticmethod
    def _fmt_size(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 ** 2:
            return f"{size_bytes / 1024:.1f} KB"
        else:
            return f"{size_bytes / 1024 ** 2:.1f} MB"
