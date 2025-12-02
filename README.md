# LeechCore/MemProcFS 作弊检测系统

## 项目概述

这是一个专门设计用于检测通过**LeechCore技术**进行远程内存读取的游戏作弊行为的检测系统。该技术通过在主机上安装Windows服务，允许副机读取主机内存，实现游戏内的透视等作弊功能。

### 作弊原理
1. **主机端**: 安装LeechCore服务进程作为中介
2. **副机端**: 通过RPC/Network通讯与服务通讯
3. **数据传输**: 大量局域网带宽用于传输内存数据
4. **坐标分析**: 副机分析游戏数据获得透视坐标

---

## 核心检测技术

### 1. **网络流量异常检测** (Network Anomaly Detection)
- **检测对象**: 局域网带宽异常
- **检测原理**: LeechCore的主副机通讯会产生大量LAN流量
- **阈值**: 默认100MB/s（可配置）
- **特征**: 持续高带宽、非标准端口通讯

### 2. **可疑进程识别** (Suspicious Process Detection)
- **扫描范围**: 所有运行进程的名称、命令行参数
- **检测特征**:
  - 进程名包含: `leechcore`, `memprocfs`, `kmddriver`, `dmadriver` 等
  - 命令行参数包含: `memprocfs`, `-device`, `rpc://` 等
  - 异常的网络连接

### 3. **Windows服务检查** (Windows Service Detection)
- **检查方式**: 扫描Windows系统服务
- **识别方式**: 黑名单匹配
- **风险等级**: 高（内核级别的威胁）

### 4. **网络指纹识别** (Network Fingerprinting)
- **连接分析**: 检测异常的网络通讯模式
- **特征提取**:
  - 高位端口 (30000-65535)
  - 局域网目标IP
  - ESTABLISHED状态的长连接
  - 非标准通讯协议

### 5. **内存异常检测** (Memory Anomaly Detection)
- **监控指标**:
  - 进程内存占用异常高
  - 虚拟内存远大于物理内存比例
  - 进程页面错误异常

### 6. **驱动程序分析** (Driver Behavior Analysis)
- **检查范围**: 已加载的系统驱动程序
- **可疑驱动**: `leechcore.sys`, `kmddriver.sys` 等
- **威胁等级**: 严重（内核级别访问）

### 7. **历史基线对比** (Historical Baseline Comparison)
- **建立基线**: 系统启动时记录网络连接数、进程数等
- **动态分析**: 与基线对比，检测异常变化
- **敏感指标**: 连接数突增、内存使用激增等

---

## 文件结构

```
Converter_Detecter/
├── main.py                      # 主程序入口
├── leechcore_detector.py        # 基础检测模块
├── advanced_detector.py         # 高级检测模块
├── monitoring_system.py         # 实时监控系统
├── config.json                  # 配置文件
├── requirements.txt             # 依赖列表
├── logs/                        # 日志目录
├── detection_archive/           # 事件档案
└── README.md                    # 说明文档
```

---

## 安装与依赖

### 系统要求
- **操作系统**: Windows 7 或更高版本
- **Python版本**: 3.7+
- **权限**: 需要管理员权限

### 安装依赖

```powershell
# 方法1: 使用pip
pip install -r requirements.txt

# 方法2: 手动安装
pip install psutil numpy
```

### 依赖说明

| 包名 | 版本 | 用途 |
|-----|------|------|
| psutil | >=5.0.0 | 系统进程和网络监控 |
| numpy | >=1.15.0 | 数值分析和异常检测 |

---

## 使用方法

### 快速扫描

```powershell
# 执行一次快速检测
python main.py scan

# 输出结果示例:
# [2024-12-02 10:30:45] 检测到异常带宽: 150.25 MB/s (阈值: 100 MB/s)
# [2024-12-02 10:30:45] 检测到可疑进程（名称）: LeechCore (PID: 1234)
# [2024-12-02 10:30:45] 风险等级: CRITICAL
```

### 持续监控

```powershell
# 启动实时监控服务（默认持续1小时）
python main.py monitor

# 服务会在以下情况触发警报:
# - 风险等级 > 70: 严重警报
# - 风险等级 > 50: 中等警报
# - 其他异常: 信息警报
```

### 显示配置

```powershell
python main.py config

# 输出当前所有配置参数
```

---

## 配置说明

编辑 `config.json` 来自定义检测参数：

```json
{
  "detection_interval": 5,                    // 检测间隔(秒)
  "bandwidth_threshold_mbps": 100,            // 带宽异常阈值(MB/s)
  "risk_threshold": 30,                       // 风险等级阈值(0-100)
  "enable_advanced_detection": true,          // 启用高级检测
  "enable_real_time_monitoring": false,       // 启用实时监控
  "monitoring_duration": 3600,                // 监控持续时间(秒)
  "archive_enabled": true,                    // 启用事件档案
  "email_alerts_enabled": false,              // 启用邮件警报
  "email_config": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "from_addr": "your_email@gmail.com",
    "to_addr": "alert@example.com"
  }
}
```

### 关键参数说明

| 参数 | 默认值 | 说明 |
|-----|-------|------|
| `bandwidth_threshold_mbps` | 100 | 网络带宽异常阈值，调高可减少误报 |
| `detection_interval` | 5 | 检测频率，调低可更快检测异常 |
| `risk_threshold` | 30 | 触发警报的风险等级，范围0-100 |
| `monitoring_duration` | 3600 | 持续监控时间（秒），设置为0表示无限 |

---

## 输出文件

### 日志文件 (logs/)
```
detection_20241202_103045.log     # 检测日志
alerts.log                         # 警报日志
```

### 事件档案 (detection_archive/)
```
event_20241202_103045_123456.json  # 检测事件记录
event_20241202_103050_789012.json  # 高风险事件记录
```

---

## 风险等级计算

系统根据以下因素计算风险等级 (0-100):

| 检测项 | 权重 | 说明 |
|-------|------|------|
| 网络异常 | +30 | 带宽异常检测 |
| 可疑连接 | +5~20 | 异常网络通讯 |
| 可疑进程 | +10~30 | 可疑进程发现 |
| 可疑服务 | +10~20 | Windows服务异常 |
| 内存异常 | +10 | 内存访问模式异常 |
| 驱动程序 | +30 | 可疑驱动程序加载 |

### 威胁等级划分

| 风险等级 | 范围 | 建议操作 |
|---------|------|---------|
| LOW | 0-29 | 继续监控 |
| MEDIUM | 30-49 | 加强监控，检查可疑进程 |
| HIGH | 50-69 | 立即调查，准备隔离 |
| CRITICAL | 70-100 | 立即采取行动，隔离系统 |

---

## 检测原理详解

### LeechCore通讯流程

```
副机 (Cheater PC) ──RPC/Network──> 主机 (Game PC)
                                     │
                              LeechCore Service
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
            内存读取操作      网络传输(HQ Bandwidth)   坐标分析
                    │                │                │
                    └────────────────┼────────────────┘
                                     │
                  返回透视数据给副机 ──┘
```

### 检测特征

1. **网络侧**: 副机→主机的大量LAN流量（100+ MB/s）
2. **进程侧**: LeechCore服务进程的异常网络连接
3. **系统侧**: 可疑驱动程序的加载
4. **内存侧**: 异常的内存访问模式

---

## 常见问题

### Q: 为什么检测到高风险但系统正常运行?
A: 可能是误报，建议：
- 调高 `bandwidth_threshold_mbps` 参数
- 检查是否有大文件下载/上传
- 排除已知的应用程序

### Q: 如何只检测LeechCore而不是其他应用?
A: 系统默认已内置过滤器，排除常见应用。可编辑 `SUSPICIOUS_PATTERNS` 列表来优化。

### Q: 系统对性能有什么影响?
A: 非常轻量级，CPU占用 < 1%, 内存占用 < 50MB。

### Q: 能否在游戏运行时进行检测?
A: 可以，但建议在后台运行，不影响游戏帧率。

---

## 高级用法

### 编程使用

```python
from leechcore_detector import AnomalyDetector
from monitoring_system import RealtimeMonitor

# 创建检测器
detector = AnomalyDetector()

# 单次检测
results = detector.run_detection()

# 或启动持续监控
detector.continuous_monitoring(interval=5, duration=300)
```

### 集成到反作弊系统

```python
from main import LeechCoreDetectionSystem

system = LeechCoreDetectionSystem()
report = system.generate_report(system.run_quick_scan())

# 根据风险等级采取行动
if report['scan_results']['risk_level'] > 70:
    # 触发禁号流程
    ban_player()
```

---

## 安全建议

1. **定期运行**: 建议每日定期运行全面扫描
2. **持续监控**: 在关键游戏服务器上启用实时监控
3. **日志审查**: 定期审查检测日志和事件档案
4. **更新维护**: 定期更新黑名单和检测规则
5. **多层防御**: 配合其他反作弊手段使用

---

## 许可证

MIT License

---

## 支持与反馈

如有问题或建议，请提交Issue或Contact。

