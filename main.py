"""
LeechCore检测系统 - 主程序
集成所有检测模块和监控系统
"""

import logging
import json
import sys
from pathlib import Path
from datetime import datetime

# 导入各个模块
from leechcore_detector import AnomalyDetector
from advanced_detector import ComprehensiveDetector
from monitoring_system import RealtimeMonitor, MonitoringDashboard, AlertManager, ArchiveManager


class LeechCoreDetectionSystem:
    """LeechCore检测系统 - 主系统类"""
    
    def __init__(self, config_file='config.json'):
        self.config = self._load_config(config_file)
        self._setup_logging()
        self.basic_detector = AnomalyDetector()
        self.advanced_detector = ComprehensiveDetector()
        self.monitor = RealtimeMonitor(
            detection_interval=self.config['detection_interval']
        )
        self.dashboard = MonitoringDashboard(self.monitor)
    
    def _load_config(self, config_file):
        """加载配置文件"""
        default_config = {
            'detection_interval': 5,
            'bandwidth_threshold_mbps': 100,
            'risk_threshold': 30,
            'enable_advanced_detection': True,
            'enable_real_time_monitoring': False,
            'monitoring_duration': 3600,
            'archive_enabled': True,
            'email_alerts_enabled': False,
            'email_config': {
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'from_addr': 'your_email@gmail.com',
                'username': 'your_email@gmail.com',
                'password': 'your_password',
                'to_addr': 'alert@example.com'
            }
        }
        
        try:
            if Path(config_file).exists():
                with open(config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
                logging.getLogger(__name__).info(f"已加载配置: {config_file}")
        except Exception as e:
            logging.getLogger(__name__).warning(f"配置加载失败: {e}，使用默认配置")
        
        return default_config
    
    def _setup_logging(self):
        """设置日志"""
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        logging.getLogger(__name__).info(f"日志文件: {log_file}")
    
    def run_quick_scan(self):
        """运行快速扫描"""
        logger = logging.getLogger(__name__)
        logger.info("=" * 70)
        logger.info("执行快速扫描")
        logger.info("=" * 70)
        
        # 运行基础检测
        results = self.basic_detector.run_detection()
        
        # 运行高级检测（如果启用）
        if self.config['enable_advanced_detection']:
            advanced_results = self.advanced_detector.comprehensive_scan()
            results['advanced_detection'] = advanced_results
        
        # 存档结果
        if self.config['archive_enabled']:
            archive = ArchiveManager()
            archive.save_detection_event(results)
        
        return results
    
    def start_continuous_monitoring(self):
        """启动持续监控"""
        logger = logging.getLogger(__name__)
        logger.info("启动持续监控服务")
        
        self.monitor.start_monitoring(
            self.basic_detector,
            duration=self.config['monitoring_duration']
        )
        
        try:
            # 显示仪表板
            while self.monitor.is_running:
                import time
                time.sleep(30)
                self.dashboard.print_dashboard()
        
        except KeyboardInterrupt:
            logger.info("用户中断监控")
        finally:
            self.monitor.stop_monitoring()
    
    def generate_report(self, scan_results):
        """生成检测报告"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'system_info': self._get_system_info(),
            'scan_results': scan_results,
            'recommendations': self._get_recommendations(scan_results)
        }
        
        return report
    
    def _get_system_info(self):
        """获取系统信息"""
        import psutil
        import platform
        
        return {
            'platform': platform.system(),
            'platform_release': platform.release(),
            'processor': platform.processor(),
            'cpu_count': psutil.cpu_count(),
            'total_memory_gb': psutil.virtual_memory().total / (1024**3)
        }
    
    def _get_recommendations(self, scan_results):
        """获取建议"""
        recommendations = []
        
        risk_level = scan_results.get('risk_level', 0)
        
        if risk_level > 70:
            recommendations.append("🚨 风险等级严重 - 建议立即采取行动:")
            recommendations.append("  1. 立即隔离受影响的系统")
            recommendations.append("  2. 检查Windows事件日志")
            recommendations.append("  3. 扫描系统驱动程序")
            recommendations.append("  4. 进行内存转储分析")
        
        elif risk_level > 50:
            recommendations.append("⚠️ 风险等级中等 - 建议:")
            recommendations.append("  1. 加强监控")
            recommendations.append("  2. 检查可疑进程")
            recommendations.append("  3. 分析网络流量")
        
        else:
            recommendations.append("✓ 系统正常 - 继续定期监控")
        
        return recommendations
    
    def print_report(self, report):
        """打印报告"""
        print("\n" + "=" * 70)
        print("              LeechCore检测系统 - 检测报告")
        print("=" * 70)
        
        print(f"\n时间: {report['timestamp']}")
        print("\n系统信息:")
        for key, value in report['system_info'].items():
            print(f"  {key}: {value}")
        
        print("\n检测结果:")
        print(json.dumps(report['scan_results'], indent=2, ensure_ascii=False, default=str))
        
        print("\n建议:")
        for rec in report['recommendations']:
            print(f"  {rec}")
        
        print("\n" + "=" * 70)


def main():
    """主函数"""
    print("""
╔════════════════════════════════════════════════════════════════════╗
║           LeechCore/MemProcFS 作弊检测系统                          ║
║      用于检测通过远程内存读取进行的游戏作弊行为                      ║
╚════════════════════════════════════════════════════════════════════╝
    """)
    
    # 初始化系统
    system = LeechCoreDetectionSystem()
    
    # 命令行参数处理
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == 'scan':
            # 快速扫描
            print("\n执行快速扫描...")
            results = system.run_quick_scan()
            report = system.generate_report(results)
            system.print_report(report)
        
        elif command == 'monitor':
            # 持续监控
            print("\n启动持续监控...")
            system.start_continuous_monitoring()
        
        elif command == 'config':
            # 显示配置
            print("\n当前配置:")
            print(json.dumps(system.config, indent=2, ensure_ascii=False))
        
        else:
            print_help()
    
    else:
        # 默认运行快速扫描
        print("\n默认模式: 快速扫描")
        print("提示: 使用 'python main.py [命令]' 指定其他模式")
        print("  scan    - 快速扫描")
        print("  monitor - 持续监控")
        print("  config  - 显示配置")
        print()
        
        results = system.run_quick_scan()
        report = system.generate_report(results)
        system.print_report(report)


def print_help():
    """打印帮助信息"""
    help_text = """
使用方法:
  python main.py [命令]

命令:
  scan      - 执行快速扫描，检测LeechCore相关活动
  monitor   - 启动持续监控服务
  config    - 显示当前配置

示例:
  python main.py scan
  python main.py monitor

配置文件:
  编辑 config.json 来自定义检测参数

输出文件:
  - logs/         - 日志文件
  - detection_archive/ - 检测事件档案
  - alerts.log    - 警报日志
    """
    print(help_text)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序已终止")
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
