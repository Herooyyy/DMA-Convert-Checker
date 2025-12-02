## LeechCore检测系统 - 项目文件说明

### 📁 文件结构

```
Converter_Detecter/
├── 📄 main.py                      # [核心] 系统入口和集成程序
├── 📄 leechcore_detector.py        # [核心] 基础检测模块
├── 📄 advanced_detector.py         # [核心] 高级检测模块  
├── 📄 monitoring_system.py         # [核心] 实时监控和报警系统
├── 📄 demo.py                      # [工具] 演示和测试程序
├── 📄 config.json                  # [配置] 检测参数配置
├── 📄 requirements.txt             # [配置] Python依赖列表
├── 📄 run.bat                      # [启动] Windows快速启动脚本
├── 📄 README.md                    # [文档] 完整使用说明
└── 📄 PROJECT_STRUCTURE.md         # [文档] 本文件
```

---

## 📖 核心模块详解

### 1️⃣ **main.py** - 系统入口
**功能**: 集成所有检测模块，提供统一的用户界面

**主要类**:
- `LeechCoreDetectionSystem` - 系统主类

**使用方法**:
```powershell
python main.py scan                 # 快速扫描
python main.py monitor              # 持续监控
python main.py config               # 显示配置
```

---

### 2️⃣ **leechcore_detector.py** - 基础检测
**功能**: 实现基础的异常检测逻辑

**主要类**:
```
NetworkMonitor          # 网络异常监控
├─ get_network_stats()           # 获取网络统计
├─ calculate_bandwidth()         # 计算带宽使用
├─ analyze_bandwidth()           # 分析带宽异常
├─ get_active_connections()      # 获取活跃连接
└─ detect_suspicious_communication()  # 检测可疑通讯

ProcessMonitor          # 进程监控
├─ scan_all_processes()         # 扫描所有进程
├─ check_windows_services()     # 检查Windows服务
├─ get_process_network_usage()  # 获取进程网络信息
└─ _check_process_name()        # 检查进程名是否可疑

AnomalyDetector         # 异常检测器（集成器）
├─ run_detection()               # 执行完整检测
├─ _calculate_risk_level()       # 计算风险等级
├─ continuous_monitoring()       # 持续监控
└─ _save_alert()                # 保存警报
```

**关键检测特征**:
- 🚨 **网络特征**: 局域网带宽异常（>100MB/s）
- 🚨 **进程特征**: 进程名/命令行包含 `leechcore`, `memprocfs`, 等
- 🚨 **服务特征**: Windows服务中的可疑程序
- 🚨 **连接特征**: 高位端口(30000-65535)的LAN通讯

---

### 3️⃣ **advanced_detector.py** - 高级检测
**功能**: 实现深层次的系统分析

**主要类**:
```
MemoryAnomalyDetector   # 内存异常检测
├─ get_process_memory_info()        # 获取进程内存信息
├─ detect_memory_access_anomalies() # 检测异常
└─ _is_suspicious_memory_usage()    # 判断内存使用是否可疑

DriverBehaviorAnalyzer  # 驱动行为分析
├─ scan_loaded_drivers()           # 扫描加载的驱动
└─ check_kernel_mode_execution()   # 检查内核模式执行

NetworkFingerprinting   # 网络指纹识别
└─ analyze_connection_fingerprint() # 分析连接特征

HistoricalAnalyzer      # 历史基线对比
├─ establish_baseline()            # 建立基线
└─ compare_with_baseline()         # 与基线对比

ComprehensiveDetector   # 综合检测器
├─ comprehensive_scan()            # 执行综合扫描
└─ _calculate_threat_score()       # 计算威胁得分
```

**高级检测技术**:
- 📊 **内存分析**: 异常的内存访问模式
- 🔧 **驱动分析**: 可疑驱动程序检测（严重威胁）
- 📡 **网络指纹**: 通讯模式特征识别
- 📈 **基线对比**: 系统状态变化监控

---

### 4️⃣ **monitoring_system.py** - 实时监控
**功能**: 实现持续监控、警报和事件档案

**主要类**:
```
AlertManager            # 警报管理
├─ create_alert()                  # 创建警报
├─ register_handler()              # 注册处理器
└─ get_recent_alerts()             # 获取最近警报

LogHandler              # 日志处理
└─ handle_alert()                  # 处理警报

ArchiveManager          # 事件档案管理
├─ save_detection_event()          # 保存检测事件
└─ get_statistics()                # 获取统计信息

RealtimeMonitor         # 实时监控
├─ start_monitoring()              # 启动监控
├─ stop_monitoring()               # 停止监控
├─ get_monitoring_status()         # 获取监控状态
└─ _monitoring_loop()              # 监控循环

MonitoringDashboard     # 监控仪表板
├─ get_dashboard_data()            # 获取仪表板数据
└─ print_dashboard()               # 打印仪表板

NotificationManager     # 通知管理
├─ send_email_alert()              # 发送邮件警报
└─ send_webhook_alert()            # 发送Webhook通知
```

**监控功能**:
- ⚠️ **警报等级**: INFO / WARNING / CRITICAL
- 📋 **事件档案**: 自动保存所有高风险事件
- 📊 **实时仪表板**: 显示监控统计
- 📧 **多渠道通知**: 邮件、Webhook等

---

### 5️⃣ **demo.py** - 演示程序
**功能**: 演示各个模块的功能

**演示项目**:
1. 网络监控演示
2. 进程监控演示
3. 内存异常检测演示
4. 驱动程序分析演示
5. 综合检测演示
6. 监控系统演示
7. 完整系统演示

**使用方法**:
```powershell
python demo.py                      # 交互式菜单
python demo.py network             # 演示网络监控
python demo.py full                # 演示完整系统
python demo.py all                 # 运行所有演示
```

---

## ⚙️ 配置文件说明

### **config.json** - 检测参数

```json
{
  "detection_interval": 5,          // 检测间隔(秒)
  "bandwidth_threshold_mbps": 100,  // 带宽异常阈值
  "risk_threshold": 30,             // 风险等级阈值
  "enable_advanced_detection": true,// 启用高级检测
  "enable_real_time_monitoring": false,  // 启用实时监控
  "monitoring_duration": 3600,      // 监控持续时间(秒)
  "archive_enabled": true           // 启用事件档案
}
```

### **requirements.txt** - Python依赖
```
psutil>=5.0.0          # 系统进程和网络监控
numpy>=1.15.0          # 数值分析
requests>=2.25.0       # HTTP请求（Webhook支持）
```

---

## 🚀 快速开始

### 第一步：安装依赖
```powershell
pip install -r requirements.txt
```

### 第二步：运行快速扫描
```powershell
python main.py scan
```

### 第三步：查看结果
```
- logs/              # 检测日志
- detection_archive/ # 事件档案
- alerts.log         # 警报日志
```

---

## 📊 检测流程图

```
┌─────────────────────────────┐
│    LeechCore检测系统启动      │
└──────────────┬──────────────┘
               │
        ┌──────▼──────┐
        │  加载配置   │
        └──────┬──────┘
               │
    ┌──────────▼──────────┐
    │   基础检测阶段      │
    │ ├─ 网络流量检测     │
    │ ├─ 进程扫描        │
    │ ├─ 服务检查        │
    │ └─ 连接分析        │
    └──────────┬──────────┘
               │
    ┌──────────▼──────────┐
    │   高级检测阶段      │
    │ ├─ 内存异常检测     │
    │ ├─ 驱动分析        │
    │ ├─ 指纹识别        │
    │ └─ 基线对比        │
    └──────────┬──────────┘
               │
    ┌──────────▼──────────┐
    │   风险等级计算      │
    └──────────┬──────────┘
               │
        ┌──────▼──────┐
        │ 威胁等级    │
        ├─ LOW (0-29) │
        ├─ MEDIUM ... │
        ├─ HIGH ...   │
        └─ CRITICAL..
```

---

## 🎯 检测精度优化

### 误报处理
1. **调整带宽阈值**: 增加 `bandwidth_threshold_mbps`
2. **进程白名单**: 编辑 `SUSPICIOUS_PATTERNS` 列表
3. **基线建立**: 让系统在正常运行时建立准确的基线

### 漏检预防
1. **定期更新**: 更新可疑进程/驱动程序特征库
2. **多角度分析**: 综合网络、进程、内存多个维度
3. **持续监控**: 启用实时监控，不放过临时行为

---

## 📈 性能指标

| 指标 | 值 |
|-----|-----|
| CPU占用 | < 1% |
| 内存占用 | < 50 MB |
| 网络检测延迟 | < 1秒 |
| 进程扫描时间 | < 5秒 |
| 系统影响 | 极小 |

---

## 🔒 安全建议

1. ✅ **定期扫描**: 每日定时执行快速扫描
2. ✅ **持续监控**: 在游戏服务器上启用实时监控
3. ✅ **日志审查**: 每周审查检测日志
4. ✅ **规则更新**: 定期更新检测规则
5. ✅ **多层防御**: 配合其他反作弊手段

---

## 📞 故障排除

| 问题 | 解决方案 |
|-----|--------|
| 导入错误 | 运行 `pip install -r requirements.txt` |
| 权限不足 | 以管理员身份运行 |
| 误报过多 | 调整config.json中的阈值 |
| 性能问题 | 增加 `detection_interval` 参数 |

---

**版本**: 1.0.0  
**最后更新**: 2024-12-02  
**作者**: AntiCheat Development Team
