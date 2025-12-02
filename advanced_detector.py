"""
LeechCore高级检测模块
- 内存异常检测
- 驱动程序行为分析
- 网络指纹识别
- 历史对比分析
"""

import psutil
import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timedelta
import logging
import subprocess
import re

logger = logging.getLogger(__name__)


class MemoryAnomalyDetector:
    """内存异常检测 - 检测可能的内存读取操作"""
    
    def __init__(self):
        self.memory_access_patterns = defaultdict(deque)
        self.baseline_memory = {}
    
    def get_process_memory_info(self, pid):
        """获取进程内存信息"""
        try:
            proc = psutil.Process(pid)
            return {
                'pid': pid,
                'name': proc.name(),
                'rss': proc.memory_info().rss,  # 物理内存
                'vms': proc.memory_info().vms,  # 虚拟内存
                'memory_percent': proc.memory_percent(),
                'page_faults': proc.memory_info().pfn if hasattr(proc.memory_info(), 'pfn') else None
            }
        except Exception as e:
            logger.error(f"获取进程 {pid} 内存信息失败: {e}")
            return None
    
    def detect_memory_access_anomalies(self):
        """检测异常的内存访问行为"""
        anomalies = []
        
        try:
            # 检查具有高内存占用的进程
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
                try:
                    if proc.info['memory_percent'] > 30:  # 占用超过30%
                        # 获取详细信息
                        mem_info = self.get_process_memory_info(proc.info['pid'])
                        if mem_info:
                            # 检查是否是可疑进程
                            if self._is_suspicious_memory_usage(mem_info):
                                anomalies.append({
                                    'type': 'high_memory_usage',
                                    'process': mem_info,
                                    'severity': 'medium'
                                })
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        
        except Exception as e:
            logger.error(f"检测内存异常失败: {e}")
        
        return anomalies
    
    def _is_suspicious_memory_usage(self, mem_info):
        """判断内存使用是否可疑"""
        # 可疑特征：
        # 1. 内存占用异常高但不是常见应用
        # 2. 虚拟内存远大于物理内存
        
        if mem_info['vms'] > mem_info['rss'] * 3:
            return True
        
        return False


class DriverBehaviorAnalyzer:
    """驱动程序行为分析"""
    
    # 可疑驱动程序特征
    SUSPICIOUS_DRIVERS = [
        'leechcore',
        'kmddriver',
        'kvmdriver',
        'dmadriver',
        'memproc',
        'directio',
        'physmem',
        'pciebar',
    ]
    
    @staticmethod
    def scan_loaded_drivers():
        """扫描已加载的驱动程序"""
        suspicious_drivers = []
        
        try:
            # Windows特定的驱动扫描
            result = subprocess.run(
                ['wmic', 'sysdriver', 'list', 'brief'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:
                    if line.strip():
                        # 提取驱动程序名称
                        parts = line.split()
                        if parts:
                            driver_name = parts[0].lower()
                            for suspicious in DriverBehaviorAnalyzer.SUSPICIOUS_DRIVERS:
                                if suspicious in driver_name:
                                    suspicious_drivers.append({
                                        'name': parts[0],
                                        'status': 'loaded',
                                        'severity': 'critical'
                                    })
                                    logger.warning(f"🚨 检测到可疑驱动程序: {parts[0]}")
        
        except Exception as e:
            logger.warning(f"扫描驱动程序失败: {e}")
        
        return suspicious_drivers
    
    @staticmethod
    def check_kernel_mode_execution():
        """检查是否有内核模式执行"""
        try:
            # 检查是否有异常的内核模式进程
            result = subprocess.run(
                ['tasklist', '/v'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # 分析进程列表中的异常
                return result.stdout
        
        except Exception as e:
            logger.error(f"检查内核模式执行失败: {e}")
        
        return None


class NetworkFingerprinting:
    """网络指纹识别 - 识别LeechCore的通讯模式"""
    
    # LeechCore已知的通讯特征
    LEECHCORE_SIGNATURES = {
        'port_ranges': [(30000, 65535), (10000, 20000)],
        'protocols': ['TCP', 'UDP'],
        'patterns': [
            'LEECH_CMD',
            'MEM_READ',
            'MEM_WRITE',
            'PAGE_REQUEST',
        ]
    }
    
    @staticmethod
    def analyze_connection_fingerprint(connection):
        """分析连接的指纹特征"""
        fingerprint = {
            'local_port': connection.laddr[1],
            'remote_port': connection.raddr[1] if connection.raddr else None,
            'protocol': 'TCP' if connection.type == 1 else 'UDP',
            'status': connection.status,
            'indicators': []
        }
        
        # 检查可疑的端口范围
        remote_port = fingerprint['remote_port']
        if remote_port:
            for start, end in NetworkFingerprinting.LEECHCORE_SIGNATURES['port_ranges']:
                if start <= remote_port <= end:
                    fingerprint['indicators'].append('suspicious_port_range')
        
        # 检查状态
        if connection.status == 'ESTABLISHED':
            fingerprint['indicators'].append('established_connection')
        
        return fingerprint


class HistoricalAnalyzer:
    """历史对比分析 - 与基线数据对比"""
    
    def __init__(self, history_limit=100):
        self.history = deque(maxlen=history_limit)
        self.baseline = None
    
    def establish_baseline(self, current_state):
        """建立基线数据"""
        self.baseline = {
            'timestamp': datetime.now(),
            'network_connections': len(psutil.net_connections()),
            'process_count': len(psutil.pids()),
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().percent
        }
        logger.info("基线数据已建立")
    
    def compare_with_baseline(self, current_state):
        """与基线数据对比"""
        if not self.baseline:
            return {'deviation': 'no_baseline'}
        
        deviations = {}
        
        # 网络连接数变化
        if 'network_connections' in current_state:
            delta = current_state['network_connections'] - self.baseline['network_connections']
            if abs(delta) > 10:  # 阈值：连接数增加/减少超过10个
                deviations['network_connection_change'] = delta
        
        # 进程数变化
        if 'process_count' in current_state:
            delta = current_state['process_count'] - self.baseline['process_count']
            if abs(delta) > 5:
                deviations['process_count_change'] = delta
        
        # 内存使用变化
        if 'memory_usage' in current_state:
            delta = current_state['memory_usage'] - self.baseline['memory_usage']
            if delta > 20:  # 内存使用增加超过20%
                deviations['memory_usage_spike'] = delta
        
        return deviations


class ComprehensiveDetector:
    """综合检测器 - 整合所有检测模块"""
    
    def __init__(self):
        self.memory_detector = MemoryAnomalyDetector()
        self.driver_analyzer = DriverBehaviorAnalyzer()
        self.network_fingerprinter = NetworkFingerprinting()
        self.historical_analyzer = HistoricalAnalyzer()
        self.detection_log = deque(maxlen=1000)
    
    def comprehensive_scan(self):
        """执行综合扫描"""
        logger.info("\n" + "=" * 60)
        logger.info("执行高级综合检测")
        logger.info("=" * 60)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'memory_anomalies': [],
            'driver_issues': [],
            'network_fingerprints': [],
            'baseline_deviations': [],
            'overall_threat_level': 'LOW'
        }
        
        # 1. 内存异常检测
        logger.info("\n[高级-1] 检测内存异常...")
        mem_anomalies = self.memory_detector.detect_memory_access_anomalies()
        if mem_anomalies:
            results['memory_anomalies'] = mem_anomalies
            logger.warning(f"   发现 {len(mem_anomalies)} 个内存异常")
        
        # 2. 驱动程序分析
        logger.info("[高级-2] 分析驱动程序...")
        suspicious_drivers = self.driver_analyzer.scan_loaded_drivers()
        if suspicious_drivers:
            results['driver_issues'] = suspicious_drivers
            logger.warning(f"   发现 {len(suspicious_drivers)} 个可疑驱动程序")
        
        # 3. 网络指纹识别
        logger.info("[高级-3] 分析网络指纹...")
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.raddr:
                    fingerprint = self.network_fingerprinter.analyze_connection_fingerprint(conn)
                    if fingerprint['indicators']:
                        results['network_fingerprints'].append({
                            'connection': {
                                'local': str(conn.laddr),
                                'remote': str(conn.raddr)
                            },
                            'fingerprint': fingerprint,
                            'pid': conn.pid
                        })
        except Exception as e:
            logger.error(f"网络指纹分析失败: {e}")
        
        # 4. 历史对比分析
        logger.info("[高级-4] 历史对比分析...")
        current_state = {
            'network_connections': len(psutil.net_connections()),
            'process_count': len(psutil.pids()),
            'memory_usage': psutil.virtual_memory().percent
        }
        
        if self.historical_analyzer.baseline is None:
            self.historical_analyzer.establish_baseline(current_state)
        else:
            deviations = self.historical_analyzer.compare_with_baseline(current_state)
            if deviations and 'deviation' not in deviations:
                results['baseline_deviations'] = deviations
                logger.warning(f"   检测到 {len(deviations)} 个基线偏差")
        
        # 5. 计算威胁等级
        threat_score = self._calculate_threat_score(results)
        if threat_score >= 70:
            results['overall_threat_level'] = 'CRITICAL'
        elif threat_score >= 50:
            results['overall_threat_level'] = 'HIGH'
        elif threat_score >= 30:
            results['overall_threat_level'] = 'MEDIUM'
        else:
            results['overall_threat_level'] = 'LOW'
        
        logger.info(f"\n威胁等级: {results['overall_threat_level']} (得分: {threat_score})")
        
        return results
    
    def _calculate_threat_score(self, results):
        """计算威胁得分"""
        score = 0
        
        if results['memory_anomalies']:
            score += len(results['memory_anomalies']) * 10
        
        if results['driver_issues']:
            score += len(results['driver_issues']) * 30  # 驱动程序问题权重较高
        
        if results['network_fingerprints']:
            score += len(results['network_fingerprints']) * 15
        
        if results['baseline_deviations']:
            score += len(results['baseline_deviations']) * 10
        
        return min(100, score)


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    detector = ComprehensiveDetector()
    results = detector.comprehensive_scan()
    
    import json
    print("\n" + "=" * 60)
    print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
    print("=" * 60)
