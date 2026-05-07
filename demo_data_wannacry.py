"""
Data fetched from public task: WannaCry Ransomware (Simulated)
"""

DEMO_WANNACRY_REPORT = {
    "data": {
        "analysis": {
            "uuid": "11111111-2222-3333-4444-555555555555",
            "duration": 150,
            "tags": ["ransomware", "wannacry", "crypto", "smb"],
            "status": "done",
            "options": {
                "os": {
                    "version": "Windows 10 x64 (Build 19041)"
                }
            }
        },
        "content": {
            "mainObject": {
                "filename": "WannaCry_Payload.exe",
                "size": 3512320,
                "type": "PE32 executable",
                "mime": "application/x-dosexec",
                "hashes": {
                    "md5":    "84c82835a5d21bbcf75a61706d8ab549",
                    "sha1":   "5ff465afaabcbf0150d1a3ab2c2e74f3a4426467",
                    "sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
                }
            },
            "scores": {
                "verdict": {
                    "threatLevel": 4,
                    "threat": "Malicious"
                },
                "specs": {
                    "knownThreat": "WannaCry"
                }
            },
            "mitre": [
                {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
                {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
                {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution"},
                {"id": "T1543.003", "name": "Windows Service", "tactic": "Persistence"},
                {"id": "T1012", "name": "Query Registry", "tactic": "Discovery"},
            ],
            "network": {
                "connections": [
                    {"ip": "104.17.220.11", "port": 80, "protocol": "TCP"},
                    {"ip": "192.168.1.45",  "port": 445, "protocol": "TCP"}
                ],
                "httpRequests": [
                    {
                        "method": "GET",
                        "url":    "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
                        "domain": "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
                        "status": 200,
                        "userAgent": "Mozilla/5.0",
                    }
                ],
                "dnsRequests": [
                    {"domain": "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"}
                ]
            },
            "processes": [
                {
                    "pid": 3012, "ppid": 800,
                    "name": "WannaCry_Payload.exe",
                    "cmd":  "C:\\Users\\Admin\\Desktop\\WannaCry_Payload.exe",
                    "isInjected": False,
                    "scores": {"verdict": {"threatLevel": 4}},
                },
                {
                    "pid": 3100, "ppid": 3012,
                    "name": "cmd.exe",
                    "cmd":  "cmd.exe /c vssadmin.exe Delete Shadows /All /Quiet",
                    "isInjected": False,
                    "scores": {"verdict": {"threatLevel": 4}},
                },
                {
                    "pid": 3104, "ppid": 3012,
                    "name": "cmd.exe",
                    "cmd":  "cmd.exe /c bcdedit /set {default} recoveryenabled No",
                    "isInjected": False,
                    "scores": {"verdict": {"threatLevel": 4}},
                },
                {
                    "pid": 3200, "ppid": 3012,
                    "name": "tasksche.exe",
                    "cmd":  "C:\\ProgramData\\tasksche.exe",
                    "isInjected": False,
                    "scores": {"verdict": {"threatLevel": 4}},
                }
            ],
            "dropped": [
                {
                    "filename": "C:\\ProgramData\\tasksche.exe",
                    "type": "PE32 executable",
                    "hashes": {"sha256": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"},
                },
                {
                    "filename": "C:\\Users\\Admin\\Desktop\\@Please_Read_Me@.txt",
                    "type": "Text document",
                    "hashes": {"sha256": "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abc1"},
                }
            ],
            "registry": [
                {"key": "HKLM\\SOFTWARE\\WanaCrypt0r"},
            ],
            "synchronization": [
                {"name": "Global\\MsWinZonesCacheCounterMutexA"}
            ],
        }
    }
}

DEMO_WANNACRY_IOC = {
    "data": [
        {"type": "domain", "value": "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"},
        {"type": "ip",     "value": "104.17.220.11"},
        {"type": "md5",    "value": "84c82835a5d21bbcf75a61706d8ab549"},
        {"type": "sha256", "value": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"},
        {"type": "filename","value": "WannaCry_Payload.exe"},
        {"type": "filename","value": "tasksche.exe"},
        {"type": "filename","value": "@Please_Read_Me@.txt"},
    ]
}
