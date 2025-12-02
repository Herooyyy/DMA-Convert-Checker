<#
Start the LeechCore detector with elevated privileges.
在管理员 PowerShell 窗口中运行:
    .\start_detector.ps1
#>
param()

Write-Host "Starting leechcore_detector..." -ForegroundColor Green

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
Push-Location $scriptPath

try {
    # Use the Python from PATH; ensure running as admin for full access
    python .\leechcore_detector.py
} finally {
    Pop-Location
}
