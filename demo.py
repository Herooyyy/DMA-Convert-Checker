"""
LeechCore检测系统 - 测试和演示程序
用于演示各个检测模块的功能
"""

import logging
import json
import sys
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def demo_network_monitoring():
    """演示网络监控"""
    print("\n" + "=" * 70)
    print("演示1: 网络监控")
    print("=" * 70)
    
    from leechcore_detector import NetworkMonitor
    import time
    
    monitor = NetworkMonitor(threshold_mbps=100)
    
    print("\n监控当前网络流量...")
    print("持续10秒，每秒采样一次\n")
    
    for i in range(10):
        is_anomaly, bandwidth = monitor.analyze_bandwidth()
        status = "🚨 异常!" if is_anomaly else "✓ 正常"
        print(f"[{i+1}] 带宽: {bandwidth:.2f} MB/s {status}")
        time.sleep(1)
    
    print("\n检测可疑连接...")
    suspicious = monitor.detect_suspicious_communication()
    print(f"发现 {len(suspicious)} 个可疑连接")
    if suspicious:
        for conn in suspicious[:3]:
            print(f"  - {conn['remote_addr']} (进程: {conn['pid']})")


def demo_process_monitoring():
    """演示进程监控"""
    print("\n" + "=" * 70)
    print("演示2: 进程监控")
    print("=" * 70)
    
    from leechcore_detector import ProcessMonitor
    
    monitor = ProcessMonitor()
    
    print("\n扫描所有运行的进程...")
    suspicious = monitor.scan_all_processes()
    
    print(f"\n发现 {len(suspicious)} 个可疑进程")
    if suspicious:
        for proc in suspicious[:3]:
            print(f"\n  进程名: {proc['name']}")
            print(f"  PID: {proc['pid']}")
            print(f"  状态: {proc['status']}")
            if proc['cmdline']:
                print(f"  命令: {' '.join(proc['cmdline'])}")
    else:
        print("  (未发现可疑进程)")
    
    print("\n检查Windows服务...")
    services = monitor.check_windows_services()
    print(f"发现 {len(services)} 个可疑服务")
    if services:
        for svc in services[:3]:
            print(f"  - {svc}")


def demo_memory_monitoring():
    """演示内存监控"""
    print("\n" + "=" * 70)
    print("演示3: 内存异常检测")
    print("=" * 70)
    
    from advanced_detector import MemoryAnomalyDetector
    import psutil
    
    detector = MemoryAnomalyDetector()
    
    print("\n分析系统内存状态...\n")
    
    # 获取内存最高的进程
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
        try:
            processes.append((proc.info['pid'], proc.info['name'], proc.info['memory_percent']))
        except:
            pass
    
    # 排序并显示前5个
    processes.sort(key=lambda x: x[2], reverse=True)
    
    print("内存占用TOP 5:")
    for i, (pid, name, mem_percent) in enumerate(processes[:5], 1):
        print(f"  {i}. {name:30} {mem_percent:6.2f}% (PID: {pid})")
    
    # 检测异常
    anomalies = detector.detect_memory_access_anomalies()
    print(f"\n内存异常检测: 发现 {len(anomalies)} 个异常")
    if anomalies:
        for anomaly in anomalies:
            print(f"  - {anomaly['type']}: {anomaly['process']['name']}")


def demo_driver_analysis():
    """演示驱动程序分析"""
    print("\n" + "=" * 70)
    print("演示4: 驱动程序分析")
    print("=" * 70)
    
    from advanced_detector import DriverBehaviorAnalyzer
    
    print("\n扫描系统驱动程序...")
    drivers = DriverBehaviorAnalyzer.scan_loaded_drivers()
    
    print(f"发现 {len(drivers)} 个可疑驱动程序")
    if drivers:
        for driver in drivers:
            print(f"  ⚠️ {driver['name']} (状态: {driver['status']}, 严重: {driver['severity']})")
    else:
        print("  ✓ 未发现可疑驱动程序")


def demo_comprehensive_scan():
    """演示综合扫描"""
    print("\n" + "=" * 70)
    print("演示5: 综合检测")
    print("=" * 70)
    
    from advanced_detector import ComprehensiveDetector
    
    detector = ComprehensiveDetector()
    results = detector.comprehensive_scan()
    
    print("\n" + "=" * 70)
    print("检测结果摘要")
    print("=" * 70)
    print(json.dumps(results, indent=2, ensure_ascii=False, default=str))


def demo_monitoring_system():
    """演示监控系统"""
    print("\n" + "=" * 70)
    print("演示6: 监控系统")
    print("=" * 70)
    
    from monitoring_system import AlertManager, LogHandler, ArchiveManager
    
    print("\n初始化监控系统组件...")
    
    # 创建警报管理器
    alert_mgr = AlertManager()
    log_handler = LogHandler('demo_alerts.log')
    archive_mgr = ArchiveManager('demo_archive')
    
    alert_mgr.register_handler(log_handler)
    
    print("\n创建测试警报...")
    
    # 创建不同级别的警报
    alerts = [
        ('INFO', '系统启动', '监控系统已启动'),
        ('WARNING', '检测到可疑活动', '网络带宽异常'),
        ('CRITICAL', '严重威胁检测', 'LeechCore相关进程被发现')
    ]
    
    for severity, title, desc in alerts:
        alert = alert_mgr.create_alert(severity, title, desc)
        print(f"  [{severity}] {title}")
    
    # 显示最近的警报
    print("\n最近的警报:")
    recent = alert_mgr.get_recent_alerts(limit=3)
    for alert in recent:
        print(f"  - {alert['title']}: {alert['description']}")
    
    # 存档统计
    stats = archive_mgr.get_statistics()
    print(f"\n存档统计:")
    print(f"  总事件数: {stats['total_events']}")


def demo_full_system():
    """演示完整系统"""
    print("\n" + "=" * 70)
    print("演示7: 完整系统运行")
    print("=" * 70)
    
    from main import LeechCoreDetectionSystem
    
    print("\n初始化LeechCore检测系统...")
    system = LeechCoreDetectionSystem()
    
    print("\n执行快速扫描...")
    results = system.run_quick_scan()
    
    print("\n生成检测报告...")
    report = system.generate_report(results)
    
    print("\n" + "=" * 70)
    print("检测报告")
    print("=" * 70)
    system.print_report(report)


def run_all_demos():
    """运行所有演示"""
    demos = [
        ("网络监控", demo_network_monitoring),
        ("进程监控", demo_process_monitoring),
        ("内存异常检测", demo_memory_monitoring),
        ("驱动程序分析", demo_driver_analysis),
        ("综合检测", demo_comprehensive_scan),
        ("监控系统", demo_monitoring_system),
        ("完整系统", demo_full_system),
    ]
    
    print("""
╔════════════════════════════════════════════════════════════════════╗
║        LeechCore检测系统 - 演示和测试程序                          ║
╚════════════════════════════════════════════════════════════════════╝
    """)
    
    print("可用的演示:")
    for i, (name, _) in enumerate(demos, 1):
        print(f"  {i}. {name}")
    print(f"  {len(demos)+1}. 运行所有演示")
    print(f"  {len(demos)+2}. 退出")
    print()
    
    try:
        choice = input("请选择演示 (1-{}): ".format(len(demos)+2))
        choice = int(choice)
        
        if choice == len(demos) + 1:
            # 运行所有
            for name, demo_func in demos:
                try:
                    demo_func()
                except Exception as e:
                    logger.error(f"演示失败: {e}")
                    input("\n按Enter继续...")
        
        elif 1 <= choice <= len(demos):
            # 运行选中的演示
            name, demo_func = demos[choice - 1]
            demo_func()
        
        elif choice == len(demos) + 2:
            print("退出")
            return
        
        else:
            print("无效选项")
    
    except Exception as e:
        logger.error(f"错误: {e}")


def main():
    """主函数"""
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        demos_map = {
            'network': demo_network_monitoring,
            'process': demo_process_monitoring,
            'memory': demo_memory_monitoring,
            'driver': demo_driver_analysis,
            'comprehensive': demo_comprehensive_scan,
            'monitoring': demo_monitoring_system,
            'full': demo_full_system,
            'all': run_all_demos,
        }
        
        if command in demos_map:
            demos_map[command]()
        else:
            print("未知的演示命令")
            print("可用命令: " + ", ".join(demos_map.keys()))
    else:
        # 交互式菜单
        run_all_demos()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n演示已停止")
    except Exception as e:
        logger.error(f"错误: {e}")
        import traceback
        traceback.print_exc()
