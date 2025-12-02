"""
LeechCore检测系统 - 项目验证和总结
用于快速验证系统完整性
"""

import os
from pathlib import Path
from datetime import datetime

def check_project_completeness():
    """检查项目完整性"""
    
    print("""
╔════════════════════════════════════════════════════════════════════════╗
║        LeechCore检测系统 - 项目验证                                    ║
╚════════════════════════════════════════════════════════════════════════╝
    """)
    
    project_root = Path(__file__).parent
    
    # 定义必要文件
    required_files = {
        '核心模块': [
            'main.py',
            'leechcore_detector.py',
            'advanced_detector.py',
            'monitoring_system.py',
        ],
        '工具脚本': [
            'demo.py',
            'run.bat',
            'run.ps1',
        ],
        '配置文件': [
            'config.json',
            'requirements.txt',
        ],
        '文档': [
            'README.md',
            'QUICK_START.md',
            'PROJECT_STRUCTURE.md',
            'INSTALL_GUIDE.md',
        ]
    }
    
    print("📁 项目文件检查")
    print("=" * 70)
    
    all_exist = True
    for category, files in required_files.items():
        print(f"\n{category}:")
        for filename in files:
            filepath = project_root / filename
            exists = filepath.exists()
            status = "✅" if exists else "❌"
            size = f"({filepath.stat().st_size} bytes)" if exists else ""
            print(f"  {status} {filename} {size}")
            if not exists:
                all_exist = False
    
    print("\n" + "=" * 70)
    if all_exist:
        print("✅ 所有文件完整！")
    else:
        print("❌ 某些文件缺失！")
    
    return all_exist


def check_dependencies():
    """检查依赖"""
    print("\n\n📦 依赖检查")
    print("=" * 70)
    
    dependencies = {
        'psutil': '系统进程和网络监控',
        'numpy': '数值分析',
        'requests': 'HTTP请求（可选）',
    }
    
    for package, description in dependencies.items():
        try:
            __import__(package)
            print(f"✅ {package:15} - {description}")
        except ImportError:
            print(f"⚠️  {package:15} - {description} (未安装)")


def check_file_contents():
    """检查文件内容"""
    print("\n\n🔍 文件内容检查")
    print("=" * 70)
    
    project_root = Path(__file__).parent
    
    # 检查主程序
    main_py = project_root / 'main.py'
    if main_py.exists():
        content = main_py.read_text()
        checks = {
            'LeechCoreDetectionSystem': '系统主类',
            'run_detection': '检测方法',
            'continuous_monitoring': '监控方法',
        }
        
        print(f"\n{main_py.name}:")
        for keyword, description in checks.items():
            found = keyword in content
            status = "✅" if found else "❌"
            print(f"  {status} {keyword:30} - {description}")
    
    # 检查配置文件
    config_json = project_root / 'config.json'
    if config_json.exists():
        import json
        try:
            config = json.load(open(config_json, encoding='utf-8'))
            print(f"\n{config_json.name}:")
            print(f"  ✅ 配置文件有效")
            print(f"     - detection_interval: {config.get('detection_interval')}秒")
            print(f"     - bandwidth_threshold: {config.get('bandwidth_threshold_mbps')}MB/s")
            print(f"     - enable_advanced_detection: {config.get('enable_advanced_detection')}")
        except:
            print(f"  ❌ 配置文件无效")


def print_usage_examples():
    """打印使用示例"""
    print("\n\n📖 使用示例")
    print("=" * 70)
    
    examples = [
        ("快速扫描", "python main.py scan"),
        ("持续监控", "python main.py monitor"),
        ("显示配置", "python main.py config"),
        ("运行演示", "python demo.py"),
        ("GUI启动", "run.bat"),
        ("PowerShell启动", "PowerShell -ExecutionPolicy Bypass -File run.ps1"),
    ]
    
    for description, command in examples:
        print(f"\n{description}:")
        print(f"  > {command}")


def print_module_overview():
    """打印模块概览"""
    print("\n\n📚 模块概览")
    print("=" * 70)
    
    modules = {
        'leechcore_detector.py': {
            'description': '基础检测模块',
            'classes': ['NetworkMonitor', 'ProcessMonitor', 'AnomalyDetector'],
            'features': ['网络监控', '进程扫描', '异常检测']
        },
        'advanced_detector.py': {
            'description': '高级检测模块',
            'classes': ['MemoryAnomalyDetector', 'DriverBehaviorAnalyzer', 
                       'NetworkFingerprinting', 'HistoricalAnalyzer', 'ComprehensiveDetector'],
            'features': ['内存分析', '驱动检查', '指纹识别', '基线对比']
        },
        'monitoring_system.py': {
            'description': '实时监控系统',
            'classes': ['AlertManager', 'LogHandler', 'ArchiveManager', 
                       'RealtimeMonitor', 'MonitoringDashboard', 'NotificationManager'],
            'features': ['警报管理', '事件档案', '实时监控', '邮件通知']
        },
    }
    
    for filename, info in modules.items():
        print(f"\n📄 {filename}")
        print(f"   描述: {info['description']}")
        print(f"   类: {', '.join(info['classes'])}")
        print(f"   功能: {', '.join(info['features'])}")


def print_detection_workflow():
    """打印检测流程"""
    print("\n\n🔄 检测工作流程")
    print("=" * 70)
    
    workflow = """
1️⃣  启动系统
    ↓
2️⃣  加载配置
    ↓
3️⃣  基础检测
    ├─ 网络流量分析
    ├─ 进程扫描
    ├─ 服务检查
    └─ 连接分析
    ↓
4️⃣  高级检测
    ├─ 内存分析
    ├─ 驱动检查
    ├─ 指纹识别
    └─ 基线对比
    ↓
5️⃣  风险计算
    └─ 综合评分 (0-100)
    ↓
6️⃣  结果处理
    ├─ 警报触发
    ├─ 事件档案
    ├─ 日志记录
    └─ 报告生成
    ↓
7️⃣  输出结果
    ├─ 控制台显示
    ├─ 日志文件
    ├─ 事件档案
    └─ 邮件通知
"""
    print(workflow)


def print_quick_reference():
    """打印快速参考"""
    print("\n\n⚡ 快速参考")
    print("=" * 70)
    
    reference = """
【风险等级】
  ✓ LOW (0-29)       系统正常
  ⚠ MEDIUM (30-49)   加强监控
  🔴 HIGH (50-69)    立即调查
  🚨 CRITICAL (70+)  紧急处理

【检测特征】
  🔴 网络异常      带宽 > 100 MB/s
  🔴 可疑进程      包含 leechcore/memprocfs 等
  🔴 异常服务      Windows服务异常
  🔴 异常连接      高位端口 + LAN通讯
  🔴 驱动问题      kmddriver 等可疑驱动
  🔴 内存异常      内存访问模式异常

【输出位置】
  📁 logs/           检测日志
  📁 detection_archive/  事件档案
  📄 alerts.log      警报日志

【配置调优】
  提高阈值 → 减少误报
  降低阈值 → 增加灵敏度
  增加间隔 → 性能提升
  减少间隔 → 更快检测
"""
    print(reference)


def main():
    """主函数"""
    
    # 检查项目完整性
    complete = check_project_completeness()
    
    # 检查依赖
    check_dependencies()
    
    # 检查文件内容
    check_file_contents()
    
    # 打印各种信息
    print_usage_examples()
    print_module_overview()
    print_detection_workflow()
    print_quick_reference()
    
    # 最终总结
    print("\n" + "=" * 70)
    print("✅ 项目验证完成！")
    print("\n后续步骤:")
    print("1. 安装依赖: pip install -r requirements.txt")
    print("2. 运行扫描: python main.py scan")
    print("3. 查看文档: 打开 README.md 或 QUICK_START.md")
    print("=" * 70 + "\n")
    
    return complete


if __name__ == '__main__':
    import sys
    
    try:
        result = main()
        sys.exit(0 if result else 1)
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
