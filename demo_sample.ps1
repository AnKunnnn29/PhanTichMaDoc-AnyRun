# ============================================================
#  DEMO SAMPLE - Muc dich GIAO DUC / HOCLIEU PHAN TICH
#  File nay KHONG chua ma doc. Muc dich: kich hoat sandbox
#  de sinh ra du lieu MITRE ATT&CK cho viec phan tich.
#  Created for: AnyRun IR Tool Demo
# ============================================================

# --- T1082: System Information Discovery ---
Write-Host "[*] Thu thap thong tin he thong..."
$sysInfo = Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, CsProcessors
$sysInfo | Out-String | Write-Host

# --- T1057: Process Discovery ---
Write-Host "[*] Liet ke cac tien trinh dang chay..."
$procs = Get-Process | Select-Object -First 20 Name, Id, CPU
$procs | Format-Table | Out-String | Write-Host

# --- T1083: File and Directory Discovery ---
Write-Host "[*] Kiem tra thu muc nguoi dung..."
$dirs = @(
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Desktop",
    "$env:APPDATA",
    "$env:TEMP"
)
foreach ($dir in $dirs) {
    if (Test-Path $dir) {
        $count = (Get-ChildItem $dir -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Host "  [+] $dir -> $count files"
    }
}

# --- T1012: Query Registry (Doc-only, khong ghi) ---
Write-Host "[*] Kiem tra Registry Run keys..."
$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($path in $regPaths) {
    try {
        $keys = Get-ItemProperty -Path $path -ErrorAction Stop
        Write-Host "  [+] $path : $($keys.PSObject.Properties.Name -join ', ')"
    } catch {
        Write-Host "  [-] Khong the truy cap: $path"
    }
}

# --- T1016: System Network Configuration Discovery ---
Write-Host "[*] Kiem tra cau hinh mang..."
$adapters = Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' } |
            Select-Object InterfaceAlias, IPAddress
$adapters | Format-Table | Out-String | Write-Host

# --- T1071: Network Communication (den domain an toan) ---
Write-Host "[*] Kiem tra ket noi mang (den example.com)..."
try {
    $response = Invoke-WebRequest -Uri "http://example.com" -TimeoutSec 5 -UseBasicParsing
    Write-Host "  [+] Ket noi thanh cong. Status: $($response.StatusCode)"
} catch {
    Write-Host "  [-] Khong ket noi duoc: $_"
}

# --- T1060 (lite): Tao file tam (khong thay doi startup) ---
Write-Host "[*] Ghi file ket qua ra TEMP..."
$outputFile = "$env:TEMP\demo_ir_output.txt"
$report = @"
=== Demo IR Sample Report ===
Thoi gian: $(Get-Date)
Hostname:  $env:COMPUTERNAME
Username:  $env:USERNAME
OS:        $([System.Environment]::OSVersion.VersionString)
Processes: $((Get-Process).Count)
=== END ===
"@
$report | Out-File -FilePath $outputFile -Encoding UTF8
Write-Host "  [+] Da ghi ra: $outputFile"

# --- T1033: System Owner/User Discovery ---
Write-Host "[*] Thong tin tai khoan hien tai..."
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host "  [+] User: $($identity.Name)"
Write-Host "  [+] Token: $($identity.AuthenticationType)"

Write-Host ""
Write-Host "[DONE] Demo hoan tat. File nay duoc tao cho muc dich demo sandbox."
Write-Host "[INFO] Upload file nay len Any.Run de xem ket qua phan tich MITRE ATT&CK."
