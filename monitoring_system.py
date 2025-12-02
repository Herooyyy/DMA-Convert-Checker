"""
LeechCore实时监控和报警系统
- 实时监控异常事件
- 自动生成警报
- 邮件/日志通知
- 事件档案记录
"""

import json
import time
from datetime import datetime, timedelta
from collections import deque
import logging
import threading
from pathlib import Path
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


class AlertManager:
    """警报管理器"""
    
    # 警报级别
    SEVERITY_LEVELS = {
        'INFO': 0,
        'WARNING': 1,
        'CRITICAL': 2
    }
    
    def __init__(self, max_alerts=1000):
        self.alerts = deque(maxlen=max_alerts)
        self.alert_handlers = []
        self.lock = threading.Lock()
    
    def register_handler(self, handler):
        """注册警报处理器"""
        self.alert_handlers.append(handler)
    
    def create_alert(self, severity, title, description, data=None):
        """创建警报"""
        alert = {
            'id': len(self.alerts),
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'title': title,
            'description': description,
            'data': data or {}
        }
        
        with self.lock:
            self.alerts.append(alert)
        
        # 触发所有处理器
        for handler in self.alert_handlers:
            try:
                handler.handle_alert(alert)
            except Exception as e:
                logger.error(f"警报处理失败: {e}")
        
        return alert
    
    def get_recent_alerts(self, limit=10, severity=None):
        """获取最近的警报"""
        alerts = list(self.alerts)
        
        if severity:
            alerts = [a for a in alerts if a['severity'] == severity]
        
        return alerts[-limit:]


class LogHandler:
    """日志处理器"""
    
    def __init__(self, log_file='alerts.log'):
        self.log_file = log_file
        self.logger = logging.getLogger('alerts')
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
    
    def handle_alert(self, alert):
        """处理警报"""
        msg = f"[{alert['severity']}] {alert['title']}: {alert['description']}"
        
        if alert['severity'] == 'CRITICAL':
            self.logger.critical(msg)
        elif alert['severity'] == 'WARNING':
            self.logger.warning(msg)
        else:
            self.logger.info(msg)


class ArchiveManager:
    """事件档案管理器"""
    
    def __init__(self, archive_dir='./detection_archive'):
        self.archive_dir = Path(archive_dir)
        self.archive_dir.mkdir(exist_ok=True)
    
    def save_detection_event(self, event_data):
        """保存检测事件"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        filename = self.archive_dir / f"event_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(event_data, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"事件已存档: {filename}")
            return filename
        except Exception as e:
            logger.error(f"存档失败: {e}")
            return None
    
    def get_statistics(self):
        """获取存档统计"""
        events = list(self.archive_dir.glob('event_*.json'))
        
        stats = {
            'total_events': len(events),
            'latest_event': events[-1] if events else None,
            'event_files': [str(e) for e in events[-10:]]  # 最近10个
        }
        
        return stats


class RealtimeMonitor:
    """实时监控器"""
    
    def __init__(self, detection_interval=5):
        self.detection_interval = detection_interval
        self.alert_manager = AlertManager()
        self.archive_manager = ArchiveManager()
        self.log_handler = LogHandler()
        self.is_running = False
        self.detection_thread = None
        
        # 注册处理器
        self.alert_manager.register_handler(self.log_handler)
    
    def start_monitoring(self, detector, duration=None):
        """启动实时监控"""
        logger.info("启动实时监控服务...")
        
        self.is_running = True
        self.detection_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(detector, duration),
            daemon=True
        )
        self.detection_thread.start()
    
    def stop_monitoring(self):
        """停止监控"""
        self.is_running = False
        if self.detection_thread:
            self.detection_thread.join(timeout=5)
        logger.info("实时监控已停止")
    
    def _monitoring_loop(self, detector, duration):
        """监控循环"""
        start_time = time.time()
        last_high_risk_alert = 0  # 防止重复警报
        alert_cooldown = 30  # 30秒冷却期
        
        try:
            while self.is_running:
                if duration and (time.time() - start_time) > duration:
                    break
                
                try:
                    # 执行检测
                    results = detector.run_detection()
                    
                    # 处理结果
                    self._process_detection_results(results, last_high_risk_alert, alert_cooldown)
                    
                    # 更新上次高风险警报时间
                    if results.get('alert'):
                        last_high_risk_alert = time.time()
                    
                    # 存档重要事件
                    if results.get('risk_level', 0) > 50:
                        self.archive_manager.save_detection_event(results)
                    
                except Exception as e:
                    logger.error(f"检测循环出错: {e}")
                    self.alert_manager.create_alert(
                        'WARNING',
                        '检测系统错误',
                        str(e)
                    )
                
                time.sleep(self.detection_interval)
        
        except Exception as e:
            logger.error(f"监控线程出错: {e}")
    
    def _process_detection_results(self, results, last_alert_time, cooldown):
        """处理检测结果"""
        risk_level = results.get('risk_level', 0)
        
        if risk_level > 70:
            # 严重威胁
            if time.time() - last_alert_time > cooldown:
                self.alert_manager.create_alert(
                    'CRITICAL',
                    '检测到高风险LeechCore作弊行为',
                    f'风险等级: {risk_level}',
                    results
                )
        
        elif risk_level > 50:
            # 中等威胁
            self.alert_manager.create_alert(
                'WARNING',
                '检测到可疑活动',
                f'风险等级: {risk_level}',
                results
            )
    
    def get_monitoring_status(self):
        """获取监控状态"""
        return {
            'running': self.is_running,
            'recent_alerts': self.alert_manager.get_recent_alerts(limit=5),
            'archive_stats': self.archive_manager.get_statistics()
        }


class NotificationManager:
    """通知管理器 - 支持多种通知方式"""
    
    @staticmethod
    def send_email_alert(alert_data, email_config):
        """发送邮件警报"""
        try:
            msg = MIMEMultipart()
            msg['From'] = email_config['from_addr']
            msg['To'] = email_config['to_addr']
            msg['Subject'] = f"[LeechCore检测警报] {alert_data['title']}"
            
            body = f"""
检测到潜在的LeechCore/MemProcFS作弊行为
时间: {alert_data['timestamp']}
严重级别: {alert_data['severity']}
标题: {alert_data['title']}
描述: {alert_data['description']}

详细数据:
{json.dumps(alert_data['data'], indent=2, ensure_ascii=False)}
            """
            
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # 发送邮件
            with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
                server.starttls()
                server.login(email_config['username'], email_config['password'])
                server.send_message(msg)
            
            logger.info(f"邮件警报已发送到: {email_config['to_addr']}")
        
        except Exception as e:
            logger.error(f"发送邮件失败: {e}")
    
    @staticmethod
    def send_webhook_alert(alert_data, webhook_url):
        """发送Webhook通知"""
        import requests
        
        try:
            payload = {
                'timestamp': alert_data['timestamp'],
                'severity': alert_data['severity'],
                'title': alert_data['title'],
                'description': alert_data['description']
            }
            
            response = requests.post(webhook_url, json=payload, timeout=5)
            if response.status_code == 200:
                logger.info(f"Webhook通知已发送")
            else:
                logger.warning(f"Webhook返回状态码: {response.status_code}")
        
        except Exception as e:
            logger.error(f"Webhook通知失败: {e}")


class MonitoringDashboard:
    """监控仪表板 - 提供实时监控统计"""
    
    def __init__(self, monitor):
        self.monitor = monitor
    
    def get_dashboard_data(self):
        """获取仪表板数据"""
        status = self.monitor.get_monitoring_status()
        
        dashboard = {
            'monitoring_active': status['running'],
            'recent_alerts': status['recent_alerts'],
            'archive_statistics': status['archive_stats'],
            'critical_alerts_count': sum(1 for a in status['recent_alerts'] 
                                        if a['severity'] == 'CRITICAL'),
            'timestamp': datetime.now().isoformat()
        }
        
        return dashboard
    
    def print_dashboard(self):
        """打印仪表板"""
        data = self.get_dashboard_data()
        
        print("\n" + "=" * 70)
        print("                    LeechCore检测监控仪表板")
        print("=" * 70)
        print(f"监控状态: {'🟢 运行中' if data['monitoring_active'] else '🔴 已停止'}")
        print(f"严重警报: {data['critical_alerts_count']}")
        print(f"最近警报数: {len(data['recent_alerts'])}")
        print(f"存档事件: {data['archive_statistics'].get('total_events', 0)}")
        print("=" * 70)
        
        if data['recent_alerts']:
            print("\n最近警报:")
            for alert in data['recent_alerts'][-5:]:
                severity_icon = {
                    'CRITICAL': '🚨',
                    'WARNING': '⚠️',
                    'INFO': 'ℹ️'
                }.get(alert['severity'], '•')
                
                print(f"{severity_icon} [{alert['severity']}] {alert['title']}")
                print(f"   {alert['description']}")
                print(f"   时间: {alert['timestamp']}\n")


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # 演示
    monitor = RealtimeMonitor(detection_interval=10)
    dashboard = MonitoringDashboard(monitor)
    
    print("监控系统已初始化")
    dashboard.print_dashboard()
