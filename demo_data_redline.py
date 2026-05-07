"""
Data fetched from public task: RedLine Stealer (Simulated)
"""

DEMO_REDLINE_REPORT = {
    "data": {
        "analysis": {
            "uuid": "22222222-3333-4444-5555-666666666666",
            "duration": 180,
            "tags": ["stealer", "redline", "infostealer", "spyware"],
            "status": "done",
            "options": {
                "os": {
                    "version": "Windows 10 x64 (Build 19041)"
                }
            }
        },
        "content": {
            "mainObject": {
                "filename": "Crack_GTA5_Setup.exe",
                "size": 1542144,
                "type": "PE32 executable",
                "mime": "application/x-dosexec",
                "hashes": {
                    "md5":    "1234567890abcdef1234567890abcdef",
                    "sha1":   "1234567890abcdef1234567890abcdef12345678",
                    "sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                }
            },
            "scores": {
                "verdict": {
                    "threatLevel": 3,
                    "threat": "Malicious"
                },
                "specs": {
                    "knownThreat": "RedLine Stealer"
                }
            },
            "mitre": [
                {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"},
                {"id": "T1056.001", "name": "Keylogging", "tactic": "Credential Access"},
                {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
                {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
            ],
            "network": {
                "connections": [
                    {"ip": "185.112.83.11", "port": 4321, "protocol": "TCP"}
                ],
                "httpRequests": [],
                "dnsRequests": []
            },
            "processes": [
                {
                    "pid": 4052, "ppid": 800,
                    "name": "Crack_GTA5_Setup.exe",
                    "cmd":  "C:\\Users\\Admin\\Downloads\\Crack_GTA5_Setup.exe",
                    "isInjected": False,
                    "scores": {"verdict": {"threatLevel": 3}},
                },
                {
                    "pid": 4100, "ppid": 4052,
                    "name": "InstallUtil.exe",
                    "cmd":  "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe",
                    "isInjected": True,
                    "scores": {"verdict": {"threatLevel": 4}},
                }
            ],
            "dropped": [
                {
                    "filename": "C:\\Users\\Admin\\AppData\\Local\\Temp\\log.txt",
                    "type": "Text document",
                    "hashes": {"sha256": "abcdef123456abcdef123456abcdef123456abcdef123456abcdef123456abcd"},
                }
            ],
            "registry": [],
            "synchronization": [],
        }
    }
}

DEMO_REDLINE_IOC = {
    "data": [
        {"type": "ip",     "value": "185.112.83.11"},
        {"type": "md5",    "value": "1234567890abcdef1234567890abcdef"},
        {"type": "sha256", "value": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"},
        {"type": "filename","value": "Crack_GTA5_Setup.exe"},
    ]
}
