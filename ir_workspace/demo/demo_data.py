"""
demo_data.py
~~~~~~~~~~~~
Dữ liệu giả lập phản hồi từ Any.Run API để chạy demo
mà không cần API key thật.

Mô phỏng mẫu Emotet (trojan/banking malware thực tế).
"""

DEMO_REPORT = {
    "data": {
        "analysis": {
            "uuid": "550e8400-e29b-41d4-a716-446655440000",
            "duration": 120,
            "tags": ["emotet", "trojan", "banking", "spyware"],
            "status": "done",
            "options": {
                "os": {
                    "version": "Windows 10 x64 (Build 19041)"
                }
            }
        },
        "content": {
            "mainObject": {
                "filename": "Invoice_2024_Q4.doc",
                "size": 452608,
                "type": "MS Word Document",
                "mime": "application/msword",
                "hashes": {
                    "md5":    "d41d8cd98f00b204e9800998ecf8427e",
                    "sha1":   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                }
            },
            "scores": {
                "verdict": {
                    "threatLevel": 2,
                    "threat": "Malicious"
                },
                "specs": {
                    "knownThreat": "Emotet"
                }
            },
            "mitre": [
                {"id": "T1566.001", "name": "Spearphishing Attachment",     "tactic": "Initial Access"},
                {"id": "T1059.001", "name": "PowerShell",                   "tactic": "Execution"},
                {"id": "T1059.003", "name": "Windows Command Shell",        "tactic": "Execution"},
                {"id": "T1055.001", "name": "Dynamic-link Library Injection","tactic": "Defense Evasion"},
                {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder","tactic": "Persistence"},
                {"id": "T1082",     "name": "System Information Discovery", "tactic": "Discovery"},
                {"id": "T1057",     "name": "Process Discovery",            "tactic": "Discovery"},
                {"id": "T1083",     "name": "File and Directory Discovery", "tactic": "Discovery"},
                {"id": "T1016",     "name": "System Network Configuration Discovery", "tactic": "Discovery"},
                {"id": "T1041",     "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
                {"id": "T1071.001", "name": "Web Protocols (HTTP/S C2)",    "tactic": "Command and Control"},
                {"id": "T1573.001", "name": "Symmetric Cryptography",       "tactic": "Command and Control"},
            ],
            "network": {
                "connections": [
                    {"ip": "185.220.101.45", "port": 443, "protocol": "TCP"},
                    {"ip": "193.56.255.42",  "port": 80,  "protocol": "TCP"},
                    {"ip": "91.121.88.203",  "port": 8080,"protocol": "TCP"},
                    {"ip": "45.33.32.156",   "port": 443, "protocol": "TCP"},
                ],
                "httpRequests": [
                    {
                        "method": "POST",
                        "url":    "http://malicious-c2.ru/update/check",
                        "domain": "malicious-c2.ru",
                        "status": 200,
                        "userAgent": "Mozilla/5.0 (compatible; MSIE 7.0)",
                    },
                    {
                        "method": "GET",
                        "url":    "http://evil-dropper.net/payload/stage2.bin",
                        "domain": "evil-dropper.net",
                        "status": 200,
                        "userAgent": "Mozilla/5.0",
                    },
                    {
                        "method": "POST",
                        "url":    "https://botnet-panel.top/api/v2/report",
                        "domain": "botnet-panel.top",
                        "status": 200,
                        "userAgent": "",
                    },
                ],
                "dnsRequests": [
                    {"domain": "malicious-c2.ru"},
                    {"domain": "evil-dropper.net"},
                    {"domain": "botnet-panel.top"},
                    {"domain": "update-cdn-service.com"},
                ]
            },
            "processes": [
                {
                    "pid": 1234, "ppid": 984,
                    "name": "winword.exe",
                    "cmd":  "C:\\Program Files\\Microsoft Office\\WINWORD.EXE Invoice_2024_Q4.doc",
                    "isInjected": False,
                    "scores": {"verdict": {"threatLevel": 1}},
                },
                {
                    "pid": 2456, "ppid": 1234,
                    "name": "powershell.exe",
                    "cmd":  "powershell.exe -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0=",
                    "isInjected": False,
                    "scores": {"verdict": {"threatLevel": 3}},
                },
                {
                    "pid": 3678, "ppid": 2456,
                    "name": "rundll32.exe",
                    "cmd":  "rundll32.exe C:\\Users\\ADMINI~1\\AppData\\Local\\Temp\\payload.dll,DllRegisterServer",
                    "isInjected": True,
                    "scores": {"verdict": {"threatLevel": 4}},
                },
                {
                    "pid": 4890, "ppid": 600,
                    "name": "svchost.exe",
                    "cmd":  "C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule",
                    "isInjected": True,
                    "scores": {"verdict": {"threatLevel": 3}},
                },
            ],
            "dropped": [
                {
                    "filename": "C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.dll",
                    "type": "PE32 DLL",
                    "hashes": {"sha256": "abc123def456789012345678901234567890123456789012345678901234abcd"},
                },
                {
                    "filename": "C:\\ProgramData\\WindowsUpdate\\svchost32.exe",
                    "type": "PE32 executable",
                    "hashes": {"sha256": "dead1234beef5678dead1234beef5678dead1234beef5678dead1234beef5678"},
                },
                {
                    "filename": "C:\\Users\\Admin\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.lnk",
                    "type": "Windows shortcut",
                    "hashes": {"sha256": "cafe1234babe5678cafe1234babe5678cafe1234babe5678cafe1234babe5678"},
                },
            ],
            "registry": [
                {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdater"},
                {"key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemService32"},
                {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\TempClean"},
            ],
            "synchronization": [
                {"name": "Global\\EmoteMutex_v2"},
                {"name": "Local\\PayloadMutex_abc123"},
            ],
        }
    }
}

DEMO_IOC = {
    "data": [
        {"type": "ip",     "value": "185.220.101.45"},
        {"type": "ip",     "value": "193.56.255.42"},
        {"type": "ip",     "value": "91.121.88.203"},
        {"type": "ip",     "value": "45.33.32.156"},
        {"type": "domain", "value": "malicious-c2.ru"},
        {"type": "domain", "value": "evil-dropper.net"},
        {"type": "domain", "value": "botnet-panel.top"},
        {"type": "domain", "value": "update-cdn-service.com"},
        {"type": "url",    "value": "http://malicious-c2.ru/update/check"},
        {"type": "url",    "value": "http://evil-dropper.net/payload/stage2.bin"},
        {"type": "url",    "value": "https://botnet-panel.top/api/v2/report"},
        {"type": "md5",    "value": "d41d8cd98f00b204e9800998ecf8427e"},
        {"type": "sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"type": "filename","value": "payload.dll"},
        {"type": "filename","value": "svchost32.exe"},
        {"type": "filename","value": "Invoice_2024_Q4.doc"},
    ]
}
