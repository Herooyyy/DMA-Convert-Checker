#!/usr/bin/env python3
"""
LeechCore 检测器（基于局域网带宽与可疑服务进程连接模式的启发式检测）

工作方式：
- 定期采样系统网卡的字节计数（发送+接收），计算带宽（Mbps）。
- 当带宽超过配置阈值时，枚举运行中的 Windows 服务并检查其关联进程的网络连接。
- 基于连接数、远端地址数量和是否使用可疑端口范围计算风险评分。

依赖：`psutil`（已在 `requirements.txt` 中）。

注意：此工具采用启发式方法来发现异常服务/进程，不能保证捕获所有变种。请在具有管理员权限的环境下运行以获得更完整的进程/服务信息。
"""
import argparse
import json
import logging
import os
import sys
import time
from collections import defaultdict

import psutil

ROOT = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(ROOT, "config.json")


def load_config(path=CONFIG_PATH):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def nic_total_bytes(pernic):
    # pernic: dict from psutil.net_io_counters(pernic=True)
    total = 0
    for name, stats in pernic.items():
        try:
            total += stats.bytes_sent + stats.bytes_recv
        except Exception:
            continue
    return total


def in_suspicious_port_ranges(port, ranges):
    for a, b in ranges:
        if a <= port <= b:
            return True
    return False


def analyze_services(cfg, delta_mbps, connections_snapshot=None):
    suspicious = []
    risk_threshold = cfg.get("risk_threshold", 30)
    suspicious_ranges = cfg.get("network_monitoring", {}).get("suspicious_port_ranges", [])

    for svc in psutil.win_service_iter():
        try:
            info = svc.as_dict()
        except Exception:
            continue

        pid = info.get("pid") or 0
        if not pid:
            continue

        try:
            p = psutil.Process(pid)
        except psutil.NoSuchProcess:
            continue

        try:
            conns = p.connections(kind="inet")
        except Exception:
            conns = []

        est_count = 0
        remote_addrs = set()
        suspicious_ports = 0
        for c in conns:
            if c.raddr:
                remote_addrs.add(c.raddr.ip)
                try:
                    port = c.raddr.port
                    if in_suspicious_port_ranges(port, suspicious_ranges):
                        suspicious_ports += 1
                except Exception:
                    pass
            if getattr(c, "status", None) == "ESTABLISHED":
                est_count += 1

        # 基于启发式规则计算风险分数
        score = est_count * 5 + len(remote_addrs) * 3 + suspicious_ports * 10
        # 当系统带宽非常高时，稍微提升分数
        if delta_mbps > cfg.get("network_monitoring", {}).get("high_bandwidth_threshold", 100):
            score += 10

        if score >= risk_threshold:
            exe = None
            try:
                exe = p.exe()
            except Exception:
                exe = None

            suspicious.append({
                "service_name": info.get("name"),
                "display_name": info.get("display_name"),
                "pid": pid,
                "exe": exe,
                "established_connections": est_count,
                "unique_remote_hosts": len(remote_addrs),
                "suspicious_remote_ports": suspicious_ports,
                "risk_score": score,
            })

    return suspicious


def run_monitor(cfg):
    interval = cfg.get("detection_interval", 5)
    bw_threshold = cfg.get("bandwidth_threshold_mbps", 100)

    print("Starting LeechCore heuristic detector. Press Ctrl-C to stop.")
    prev = psutil.net_io_counters(pernic=True)
    prev_total = nic_total_bytes(prev)

    try:
        while True:
            time.sleep(interval)
            curr = psutil.net_io_counters(pernic=True)
            curr_total = nic_total_bytes(curr)
            delta_bytes = max(0, curr_total - prev_total)
            mbps = (delta_bytes * 8) / (interval * 1024 * 1024)

            logging.info("Network delta: %.2f Mbps", mbps)

            if cfg.get("network_monitoring", {}).get("check_lan_traffic", True) and mbps >= bw_threshold:
                logging.warning("High LAN bandwidth detected: %.2f Mbps (threshold %.2f)", mbps, bw_threshold)
                suspicious = analyze_services(cfg, mbps)
                if suspicious:
                    for s in suspicious:
                        msg = (
                            f"Suspicious service detected: {s['service_name']} (PID {s['pid']})",
                            f"Exe: {s['exe']}",
                            f"Established connections: {s['established_connections']}",
                            f"Unique remote hosts: {s['unique_remote_hosts']}",
                            f"Suspicious remote ports: {s['suspicious_remote_ports']}",
                            f"Risk score: {s['risk_score']}",
                        )
                        logging.warning("%s", " | ".join(msg))
                        print("ALERT:")
                        print(" | ".join(msg))
                else:
                    logging.info("No suspicious services found in this interval.")

            prev_total = curr_total

    except KeyboardInterrupt:
        print("Detector stopped by user.")


def run_once(cfg):
    # 单次检测，便于调试
    interval = cfg.get("detection_interval", 5)
    prev = psutil.net_io_counters(pernic=True)
    prev_total = nic_total_bytes(prev)
    time.sleep(interval)
    curr = psutil.net_io_counters(pernic=True)
    curr_total = nic_total_bytes(curr)
    delta_bytes = max(0, curr_total - prev_total)
    mbps = (delta_bytes * 8) / (interval * 1024 * 1024)
    print(f"Measured bandwidth: {mbps:.2f} Mbps")
    suspicious = analyze_services(cfg, mbps)
    if suspicious:
        print("Suspicious services:")
        for s in suspicious:
            print(json.dumps(s, ensure_ascii=False, indent=2))
    else:
        print("No suspicious services found.")


def setup_logging(cfg):
    level = cfg.get("logging", {}).get("log_level", "INFO")
    numeric = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(level=numeric, format="%(asctime)s [%(levelname)s] %(message)s")


def main():
    parser = argparse.ArgumentParser(description="LeechCore heuristic detector")
    parser.add_argument("--config", "-c", default=CONFIG_PATH, help="配置文件路径")
    parser.add_argument("--once", action="store_true", help="只运行一次检测并退出（便于调试）")
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"配置文件未找到: {args.config}")
        sys.exit(2)

    cfg = load_config(args.config)
    setup_logging(cfg)

    if args.once:
        run_once(cfg)
    else:
        run_monitor(cfg)


if __name__ == "__main__":
    main()
"""
LeechCore/MemProcFS 作弊检测程序
用于检测通过LeechCore技术进行远程内存读取的作弊行为
关键检测点：网络带宽异常 + 可疑服务进程 + 异常通讯模式
"""

import psutil
import socket
import subprocess
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict, deque
from threading import Thread, Lock
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('leechcore_detection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class NetworkMonitor:
    """网络监控器 - 检测异常带宽使用"""
    
    def __init__(self, threshold_mbps=100, window_size=60):
        """
        初始化网络监控器
        
        Args:
            threshold_mbps: 带宽异常阈值(MB/s)
            window_size: 检测窗口大小(秒)
        """
        self.threshold_mbps = threshold_mbps
        self.window_size = window_size
        self.bandwidth_history = deque(maxlen=window_size)
        self.last_stats = None
        self.lock = Lock()
        self.suspicious_ips = defaultdict(int)
        
    def get_network_stats(self):
        """获取当前网络统计信息"""
        try:
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'timestamp': time.time()
            }
        except Exception as e:
            logger.error(f"获取网络统计失败: {e}")
            return None
    
    def calculate_bandwidth(self):
        """计算当前带宽使用率 (MB/s)"""
        current_stats = self.get_network_stats()
        if not current_stats or not self.last_stats:
            self.last_stats = current_stats
            return 0
        
        time_delta = current_stats['timestamp'] - self.last_stats['timestamp']
        if time_delta == 0:
            return 0
        
        bytes_delta = (current_stats['bytes_sent'] - self.last_stats['bytes_sent'] + 
                      current_stats['bytes_recv'] - self.last_stats['bytes_recv'])
        
        bandwidth_mbps = (bytes_delta / time_delta) / (1024 * 1024)
        self.last_stats = current_stats
        
        return bandwidth_mbps
    
    def analyze_bandwidth(self):
        """分析带宽异常"""
        bandwidth = self.calculate_bandwidth()
        
        with self.lock:
            self.bandwidth_history.append(bandwidth)
        
        avg_bandwidth = sum(self.bandwidth_history) / len(self.bandwidth_history) if self.bandwidth_history else 0
        
        if bandwidth > self.threshold_mbps:
            logger.warning(f"🚨 检测到异常带宽: {bandwidth:.2f} MB/s (阈值: {self.threshold_mbps} MB/s)")
            return True, bandwidth
        
        return False, bandwidth
    
    def get_active_connections(self):
        """获取所有活跃的网络连接"""
        try:
            connections = psutil.net_connections(kind='inet')
            return connections
        except Exception as e:
            logger.error(f"获取连接信息失败: {e}")
            return []
    
    def detect_suspicious_communication(self):
        """检测可疑的网络通讯"""
        connections = self.get_active_connections()
        suspicious = []
        
        for conn in connections:
            if conn.raddr:  # 有远程地址
                remote_ip = conn.raddr[0]
                remote_port = conn.raddr[1]
                
                # 检测特定的通讯特征
                # LeechCore通常使用特定端口或非标准通讯模式
                if self._is_suspicious_connection(conn):
                    suspicious.append({
                        'local_addr': conn.laddr,
                        'remote_addr': conn.raddr,
                        'status': conn.status,
                        'pid': conn.pid,
                        'type': conn.type
                    })
                    
                    with self.lock:
                        self.suspicious_ips[remote_ip] += 1
        
        return suspicious
    
    def _is_suspicious_connection(self, conn):
        """判断连接是否可疑"""
        # 检测非标准端口（常见作弊工具使用高位端口）
        if conn.raddr:
            remote_port = conn.raddr[1]
            # LeechCore可能使用的典型端口范围
            if 30000 <= remote_port <= 65535:
                return True
            
            # 检测到副机的连接（通常局域网IP）
            remote_ip = conn.raddr[0]
            if self._is_lan_ip(remote_ip) and conn.status == 'ESTABLISHED':
                # 本地网络连接且建立状态 - 需要进一步确认
                if self._is_high_bandwidth_connection(conn):
                    return True
        
        return False
    
    def _is_lan_ip(self, ip):
        """检测是否为局域网IP"""
        lan_ranges = [
            ('10.', '10.255.'),
            ('172.16.', '172.31.'),
            ('192.168.', '192.168.'),
            ('127.', '127.')
        ]
        
        for start, end in lan_ranges:
            if ip.startswith(start[:ip.rfind('.')]):
                return True
        
        return False
    
    def _is_high_bandwidth_connection(self, conn):
        """检测连接是否为高带宽连接"""
        try:
            if conn.pid:
                proc = psutil.Process(conn.pid)
                # 后续可通过进程统计信息判断
                return True
        except:
            pass
        return False


class ProcessMonitor:
    """进程监控器 - 检测可疑的服务进程"""
    
    # 已知的作弊工具和可疑服务特征
    SUSPICIOUS_PATTERNS = [
        'leechcore',
        'pcileech',
        'memprocfs',
        'memproc',
        'kmddriver',
        'kvmdriver',
        'umd_dispatcher',
        'dma',
        'memory_reader',
        'remote_memory',
        'kernel_access',
        'direct_access',
    ]
    
    # 可疑的命令行参数
    SUSPICIOUS_CMDLINE_PATTERNS = [
        'leechcore',
        'memprocfs',
        '-device',
        'rpc://',
        'fpga://',
        'usbmicro://',
    ]
    
    def __init__(self):
        self.known_services = set()
        self.suspicious_processes = []
        self.lock = Lock()
        self._load_known_services()
    
    def _load_known_services(self):
        """加载已知的系统服务（用于排除误报）"""
        # 常见的系统服务不应标记为可疑
        known_safe_services = {
            'svchost', 'lsass', 'csrss', 'services', 'explorer',
            'dwm', 'winlogon', 'taskhost', 'userinit', 'spoolsv',
            'java', 'python', 'node', 'chrome', 'firefox'
        }
        self.known_services = known_safe_services
    
    def scan_all_processes(self):
        """扫描所有运行的进程"""
        suspicious = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'status']):
                try:
                    proc_info = proc.as_dict(attrs=['pid', 'name', 'cmdline', 'status'])
                    
                    # 检查进程名称
                    if self._check_process_name(proc_info['name']):
                        suspicious.append(proc_info)
                        logger.warning(f"🚨 检测到可疑进程（名称）: {proc_info['name']} (PID: {proc_info['pid']})")
                    
                    # 检查命令行参数
                    if proc_info['cmdline'] and self._check_cmdline(proc_info['cmdline']):
                        suspicious.append(proc_info)
                        logger.warning(f"🚨 检测到可疑进程（命令行）: {proc_info['name']} (PID: {proc_info['pid']})")
                        logger.info(f"   命令行: {' '.join(proc_info['cmdline'])}")
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        
        except Exception as e:
            logger.error(f"扫描进程失败: {e}")
        
        with self.lock:
            self.suspicious_processes = suspicious
        
        return suspicious
    
    def _check_process_name(self, name):
        """检查进程名称是否可疑"""
        name_lower = name.lower()
        
        # 检查黑名单
        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern in name_lower:
                return True
        
        # 检查是否为已知安全的进程
        if name_lower.split('.')[0] in self.known_services:
            return False
        
        return False
    
    def _check_cmdline(self, cmdline):
        """检查命令行参数是否可疑"""
        cmdline_str = ' '.join(cmdline).lower()
        
        for pattern in self.SUSPICIOUS_CMDLINE_PATTERNS:
            if pattern in cmdline_str:
                return True
        
        return False
    
    def get_process_network_usage(self, pid):
        """获取特定进程的网络使用情况"""
        try:
            proc = psutil.Process(pid)
            connections = proc.net_connections()
            
            network_info = {
                'pid': pid,
                'name': proc.name(),
                'connection_count': len(connections),
                'connections': []
            }
            
            for conn in connections:
                if conn.raddr:
                    network_info['connections'].append({
                        'local_addr': conn.laddr,
                        'remote_addr': conn.raddr,
                        'status': conn.status,
                        'type': conn.type
                    })
            
            return network_info
        except Exception as e:
            logger.error(f"获取进程网络信息失败: {e}")
            return None
    
    def check_windows_services(self):
        """检查Windows服务中是否有可疑服务"""
        suspicious_services = []
        
        try:
            # 在Windows上使用wmic获取服务信息
            result = subprocess.run(
                ['wmic', 'service', 'list', 'brief'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # 跳过标题行
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            service_name = parts[0]
                            if self._check_process_name(service_name):
                                suspicious_services.append(service_name)
                                logger.warning(f"🚨 检测到可疑Windows服务: {service_name}")
        
        except Exception as e:
            logger.error(f"检查Windows服务失败: {e}")
        
        return suspicious_services


class AnomalyDetector:
    """异常检测器 - 综合分析检测结果"""
    
    def __init__(self):
        self.network_monitor = NetworkMonitor(threshold_mbps=100)
        self.process_monitor = ProcessMonitor()
        self.risk_level = 0  # 0-100
        self.detection_events = deque(maxlen=1000)
        self.lock = Lock()
    
    def run_detection(self):
        """运行完整的检测流程"""
        logger.info("=" * 60)
        logger.info("开始LeechCore/MemProcFS作弊检测")
        logger.info("=" * 60)
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'network_anomalies': [],
            'suspicious_processes': [],
            'suspicious_services': [],
            'suspicious_connections': [],
            'risk_level': 0,
            'alert': False
        }
        
        # 1. 检查网络异常
        logger.info("\n[1] 检查网络带宽异常...")
        is_anomaly, bandwidth = self.network_monitor.analyze_bandwidth()
        if is_anomaly:
            results['network_anomalies'].append({
                'type': 'bandwidth_spike',
                'bandwidth_mbps': bandwidth,
                'threshold_mbps': self.network_monitor.threshold_mbps
            })
        
        # 2. 检查可疑通讯
        logger.info("[2] 检查可疑网络通讯...")
        suspicious_conns = self.network_monitor.detect_suspicious_communication()
        if suspicious_conns:
            results['suspicious_connections'] = suspicious_conns
            logger.warning(f"   发现 {len(suspicious_conns)} 个可疑连接")
        
        # 3. 扫描可疑进程
        logger.info("[3] 扫描可疑进程...")
        suspicious_procs = self.process_monitor.scan_all_processes()
        if suspicious_procs:
            results['suspicious_processes'] = suspicious_procs
            logger.warning(f"   发现 {len(suspicious_procs)} 个可疑进程")
            
            # 获取可疑进程的网络信息
            for proc in suspicious_procs:
                net_info = self.process_monitor.get_process_network_usage(proc['pid'])
                if net_info and net_info['connection_count'] > 0:
                    results['suspicious_processes'].append(net_info)
        
        # 4. 检查Windows服务
        logger.info("[4] 检查Windows服务...")
        suspicious_services = self.process_monitor.check_windows_services()
        if suspicious_services:
            results['suspicious_services'] = suspicious_services
        
        # 5. 计算风险等级
        self._calculate_risk_level(results)
        results['risk_level'] = self.risk_level
        
        # 6. 生成警报
        if self.risk_level > 30:
            results['alert'] = True
            logger.critical(f"⚠️ 检测到潜在的LeechCore作弊行为! 风险等级: {self.risk_level}")
        else:
            logger.info(f"✓ 未检测到异常。风险等级: {self.risk_level}")
        
        # 记录事件
        with self.lock:
            self.detection_events.append(results)
        
        return results
    
    def _calculate_risk_level(self, results):
        """计算风险等级 (0-100)"""
        self.risk_level = 0
        
        # 网络异常
        if results['network_anomalies']:
            self.risk_level += 30
        
        # 可疑连接
        if len(results['suspicious_connections']) > 0:
            self.risk_level += min(20, len(results['suspicious_connections']) * 5)
        
        # 可疑进程
        if len(results['suspicious_processes']) > 0:
            self.risk_level += min(30, len(results['suspicious_processes']) * 10)
        
        # 可疑服务
        if len(results['suspicious_services']) > 0:
            self.risk_level += min(20, len(results['suspicious_services']) * 10)
        
        self.risk_level = min(100, self.risk_level)
    
    def continuous_monitoring(self, interval=5, duration=None):
        """持续监控"""
        logger.info(f"启动持续监控 (间隔: {interval}秒)")
        
        start_time = time.time()
        
        try:
            while True:
                if duration and (time.time() - start_time) > duration:
                    break
                
                results = self.run_detection()
                
                # 如果检测到高风险，立即记录
                if results['alert']:
                    self._save_alert(results)
                
                logger.info(f"下次检测倒计时: {interval}秒\n")
                time.sleep(interval)
        
        except KeyboardInterrupt:
            logger.info("\n监控已停止")
    
    def _save_alert(self, results):
        """保存警报信息"""
        try:
            filename = f"alert_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            logger.info(f"警报已保存到: {filename}")
        except Exception as e:
            logger.error(f"保存警报失败: {e}")


def main():
    """主函数"""
    detector = AnomalyDetector()
    
    # 运行一次完整检测
    results = detector.run_detection()
    
    # 输出结果
    print("\n" + "=" * 60)
    print("检测结果摘要")
    print("=" * 60)
    print(json.dumps(results, indent=2, ensure_ascii=False, default=str))
    print("=" * 60)
    
    # 可选：启动持续监控
    # detector.continuous_monitoring(interval=5, duration=300)


if __name__ == '__main__':
    main()
