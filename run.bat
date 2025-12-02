@echo off
REM LeechCore检测系统 - Windows启动脚本

echo.
echo ╔════════════════════════════════════════════════════════════════════╗
echo ║           LeechCore/MemProcFS 作弊检测系统                          ║
echo ║      用于检测通过远程内存读取进行的游戏作弊行为                      ║
echo ╚════════════════════════════════════════════════════════════════════╝
echo.

REM 检查Python是否已安装
python --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 未找到Python
    echo 请先安装Python 3.7+ (https://www.python.org/)
    pause
    exit /b 1
)

REM 检查是否需要安装依赖
echo 检查依赖...
python -c "import psutil" >nul 2>&1
if errorlevel 1 (
    echo 首次运行，安装依赖...
    pip install -r requirements.txt
)

REM 显示菜单
echo.
echo 请选择要执行的操作:
echo.
echo 1. 快速扫描
echo 2. 持续监控
echo 3. 显示配置
echo 4. 查看帮助
echo 5. 退出
echo.

set /p choice="请输入选项 (1-5): "

if "%choice%"=="1" (
    echo.
    echo 执行快速扫描...
    echo.
    python main.py scan
) else if "%choice%"=="2" (
    echo.
    echo 启动持续监控 (Ctrl+C 停止)...
    echo.
    python main.py monitor
) else if "%choice%"=="3" (
    echo.
    echo 显示配置...
    echo.
    python main.py config
) else if "%choice%"=="4" (
    echo.
    echo 帮助信息:
    echo.
    echo 快速扫描: 执行一次完整的LeechCore检测
    echo   python main.py scan
    echo.
    echo 持续监控: 启动实时监控服务 (持续1小时)
    echo   python main.py monitor
    echo.
    echo 显示配置: 查看和修改检测参数
    echo   python main.py config
    echo.
) else if "%choice%"=="5" (
    exit /b 0
) else (
    echo 无效选项
    goto :start
)

echo.
pause
