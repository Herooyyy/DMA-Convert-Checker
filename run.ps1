# LeechCore检测系统 - PowerShell启动脚本
# 以管理员身份运行此脚本

param(
    [string]$Action = "menu"
)

# 设置文本编码为UTF-8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# 显示标题
function Show-Banner {
    Write-Host "`n╔════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           LeechCore/MemProcFS 作弊检测系统                          ║" -ForegroundColor Cyan
    Write-Host "║      用于检测通过远程内存读取进行的游戏作弊行为                      ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
}

# 检查权限
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 检查Python
function Test-Python {
    try {
        $pythonVersion = python --version 2>&1
        Write-Host "✓ Python已安装: $pythonVersion" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "✗ 未找到Python" -ForegroundColor Red
        Write-Host "请先安装Python 3.7+ (https://www.python.org/)" -ForegroundColor Yellow
        return $false
    }
}

# 安装依赖
function Install-Dependencies {
    Write-Host "检查依赖..." -ForegroundColor Yellow
    
    try {
        python -c "import psutil" 2>&1 > $null
        Write-Host "✓ 所有依赖已安装" -ForegroundColor Green
    }
    catch {
        Write-Host "首次运行，安装依赖..." -ForegroundColor Yellow
        pip install -r requirements.txt
    }
}

# 快速扫描
function Run-QuickScan {
    Write-Host "`n正在执行快速扫描..." -ForegroundColor Yellow
    Write-Host "═" * 70
    python main.py scan
}

# 持续监控
function Run-Monitor {
    Write-Host "`n启动持续监控 (按 Ctrl+C 停止)..." -ForegroundColor Yellow
    Write-Host "═" * 70
    python main.py monitor
}

# 显示配置
function Show-Config {
    Write-Host "`n显示当前配置..." -ForegroundColor Yellow
    Write-Host "═" * 70
    python main.py config
}

# 运行演示
function Run-Demo {
    Write-Host "`n启动演示程序..." -ForegroundColor Yellow
    python demo.py
}

# 打开文档
function Open-Documentation {
    if (Test-Path "README.md") {
        Write-Host "打开文档..." -ForegroundColor Yellow
        & notepad README.md
    }
    else {
        Write-Host "文档未找到" -ForegroundColor Red
    }
}

# 查看日志
function View-Logs {
    $logPath = "logs"
    if (Test-Path $logPath) {
        Write-Host "日志文件:" -ForegroundColor Yellow
        Get-ChildItem $logPath | ForEach-Object {
            Write-Host "  - $($_.Name)" -ForegroundColor Green
        }
        
        $latest = Get-ChildItem $logPath | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) {
            Write-Host "`n显示最新日志 ($($latest.Name))..." -ForegroundColor Yellow
            Get-Content $latest.FullName | Select-Object -Last 20
        }
    }
    else {
        Write-Host "尚无日志文件" -ForegroundColor Gray
    }
}

# 显示菜单
function Show-Menu {
    Show-Banner
    
    Write-Host "选择操作:" -ForegroundColor Cyan
    Write-Host "  1. 快速扫描" -ForegroundColor White
    Write-Host "  2. 持续监控" -ForegroundColor White
    Write-Host "  3. 显示配置" -ForegroundColor White
    Write-Host "  4. 运行演示" -ForegroundColor White
    Write-Host "  5. 查看日志" -ForegroundColor White
    Write-Host "  6. 打开文档" -ForegroundColor White
    Write-Host "  7. 关于本程序" -ForegroundColor White
    Write-Host "  0. 退出" -ForegroundColor White
    Write-Host ""
    
    $choice = Read-Host "请输入选项 (0-7)"
    
    switch ($choice) {
        "1" { Run-QuickScan }
        "2" { Run-Monitor }
        "3" { Show-Config }
        "4" { Run-Demo }
        "5" { View-Logs }
        "6" { Open-Documentation }
        "7" { 
            Write-Host "`nLeechCore检测系统 v1.0.0" -ForegroundColor Cyan
            Write-Host "用于检测通过LeechCore技术进行的远程内存读取作弊行为"
            Write-Host "更新日期: 2024-12-02" -ForegroundColor Gray
        }
        "0" { exit 0 }
        default { Write-Host "无效选项" -ForegroundColor Red }
    }
}

# 主函数
function Main {
    Show-Banner
    
    # 检查权限
    if (-not (Test-Admin)) {
        Write-Host "⚠️ 警告: 建议以管理员身份运行此脚本以获得最佳效果" -ForegroundColor Yellow
        Write-Host ""
    }
    
    # 检查Python
    if (-not (Test-Python)) {
        exit 1
    }
    
    # 安装依赖
    Install-Dependencies
    
    # 处理参数或显示菜单
    if ($Action -eq "scan") {
        Run-QuickScan
    }
    elseif ($Action -eq "monitor") {
        Run-Monitor
    }
    elseif ($Action -eq "config") {
        Show-Config
    }
    elseif ($Action -eq "demo") {
        Run-Demo
    }
    else {
        # 交互式菜单循环
        while ($true) {
            Show-Menu
            Write-Host "`n按 Enter 继续..."
            Read-Host | Out-Null
            Clear-Host
        }
    }
}

# 运行主函数
Main
