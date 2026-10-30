param([switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot
$localState = Join-Path $projectRoot '.local'
New-Item -ItemType Directory -Path $localState -Force | Out-Null
$ollamaExecutable = Join-Path $projectRoot 'tools\ollama\ollama.exe'
if (-not (Test-Path -LiteralPath $ollamaExecutable)) { throw 'Chưa có Ollama trong tools\ollama.' }
$env:OLLAMA_MODELS = Join-Path $projectRoot 'tools\ollama-models'
$env:OLLAMA_HOST = '127.0.0.1:11434'
$env:AI_PROVIDER = 'ollama'
$env:AI_FAST_MODE = '0'
$env:OLLAMA_ENABLED = '1'
$env:OLLAMA_MODEL = 'qwen2.5:3b'
$env:OLLAMA_THINK = '0'
$env:OLLAMA_NUM_CTX = '4096'
$env:OLLAMA_TIMEOUT = '180'
$env:AI_RETRIES = '1'
$env:AI_CONTEXT_LIMIT = '6500'
$env:AGENT_PROVIDER = 'rules'
try { $null = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2 } catch {
    Start-Process -FilePath $ollamaExecutable -ArgumentList 'serve' -WindowStyle Hidden -WorkingDirectory $projectRoot -RedirectStandardOutput (Join-Path $localState 'ollama-stdout.log') -RedirectStandardError (Join-Path $localState 'ollama-stderr.log')
}
$modelReady = $false
for ($attempt = 0; $attempt -lt 10; $attempt++) {
    try { $available = Invoke-RestMethod 'http://127.0.0.1:11434/api/tags' -TimeoutSec 2; $modelReady = $available.models.name -contains $env:OLLAMA_MODEL; break } catch { Start-Sleep -Seconds 1 }
}
if (-not $modelReady) { throw 'Chưa có qwen2.5:3b. Cần tải mô hình trước khi mở chat AI.' }
try { $existing = Invoke-RestMethod 'http://127.0.0.1:5000/api/config' -TimeoutSec 2 } catch { $existing = $null }
if ($existing -and $existing.data.ui_version -ne 'response-v2') { throw 'Cổng 5000 đang chạy bản ứng dụng cũ. Đóng bản đó rồi mở lại.' }
if (-not $existing) {
    $pythonExecutable = Join-Path $projectRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $pythonExecutable)) { $pythonExecutable = (Get-Command python -ErrorAction Stop).Source }
    $serverProcess = Start-Process -FilePath $pythonExecutable -ArgumentList '-X','utf8','app.py' -WindowStyle Hidden -WorkingDirectory $projectRoot -RedirectStandardOutput (Join-Path $localState 'web-stdout.log') -RedirectStandardError (Join-Path $localState 'web-stderr.log') -PassThru
    $serverProcess.Id | Set-Content -LiteralPath (Join-Path $localState 'web.pid')
}
$webReady = $false
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    try { $check = Invoke-RestMethod 'http://127.0.0.1:5000/api/config' -TimeoutSec 2; $webReady = $check.data.ui_version -eq 'response-v2'; if ($webReady) { break } } catch {}
    Start-Sleep -Seconds 1
}
if (-not $webReady) { throw 'Web chua khoi dong xong. Xem .local\web-stderr.log.' }
Write-Output 'IR Workspace: http://127.0.0.1:5000 - Chat AI: qwen2.5:3b tren may'
if (-not $NoBrowser) { Start-Process 'http://127.0.0.1:5000' -WindowStyle Hidden }
