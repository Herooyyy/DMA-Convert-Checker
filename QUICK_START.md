# LeechCore检测系统 - 快速安装和使用指南

## 🚀 5分钟快速开始

### 步骤1: 安装Python
- 下载Python 3.7+: https://www.python.org/
- 安装时勾选 "Add Python to PATH"

### 步骤2: 安装依赖
```powershell
cd C:\Users\Administrator\Desktop\Converter_Detecter
pip install -r requirements.txt
```

### 步骤3: 运行系统
**方法A - 使用GUI菜单（推荐）**
```powershell
# Windows批处理脚本
run.bat

# 或PowerShell脚本
PowerShell -ExecutionPolicy Bypass -File run.ps1
```

**方法B - 命令行**
```powershell
# 快速扫描
python main.py scan

# 持续监控
python main.py monitor
```

---

## 📋 常见操作

### 1. 快速扫描（推荐用于日常检测）
```powershell
python main.py scan
```
- 执行一次完整的LeechCore检测
- 输出风险等级和详细报告
- 自动存档高风险事件
- 执行时间: 10-30秒

### 2. 持续监控（推荐用于游戏服务器）
```powershell
python main.py monitor
```
- 持续监控系统（默认1小时）
- 自动触发警报
- 保存所有事件档案
- 显示实时仪表板

### 3. 运行演示
```powershell
python demo.py
```
- 演示各个检测模块
- 了解系统工作原理
- 测试环境配置

### 4. 查看配置
```powershell
python main.py config
```
- 显示当前所有参数
- 可编辑config.json来修改

---

## ⚙️ 配置调优

编辑 `config.json` 来优化检测参数：

### 减少误报
```json
{
  "bandwidth_threshold_mbps": 150,  // 增加带宽阈值
  "detection_interval": 10          // 增加检测间隔
}
```

### 增加检测灵敏度
```json
{
  "bandwidth_threshold_mbps": 50,   // 降低带宽阈值
  "detection_interval": 2           // 减少检测间隔
}
```

### 启用邮件警报
```json
{
  "email_alerts_enabled": true,
  "email_config": {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "from_addr": "your_email@gmail.com",
    "username": "your_email@gmail.com",
    "password": "your_app_password",
    "to_addr": "admin@example.com"
  }
}
```

---

## 📊 理解检测结果

### 风险等级
```
✓ LOW (0-29)       → 系统正常，继续监控
⚠ MEDIUM (30-49)   → 可疑活动，加强监控
🔴 HIGH (50-69)    → 高风险活动，立即调查
🚨 CRITICAL (70+)  → 严重威胁，立即采取行动
```

### 输出示例
```
[2024-12-02 10:30:45] 检测到异常带宽: 150.25 MB/s (阈值: 100 MB/s)   ← 网络异常
[2024-12-02 10:30:45] 检测到可疑进程（名称）: LeechCore (PID: 1234)  ← 进程异常
[2024-12-02 10:30:45] 发现 1 个可疑连接                               ← 连接异常
[2024-12-02 10:30:45] 风险等级: CRITICAL                             ← 最终判断
```

---

## 📁 输出文件位置

### 日志文件 (`logs/`)
```
detection_20241202_103045.log  # 系统日志
```

### 警报日志 (`alerts.log`)
```
[CRITICAL] 检测到高风险LeechCore作弊行为: 风险等级: 85
[WARNING] 检测到可疑活动: 风险等级: 55
```

### 事件档案 (`detection_archive/`)
```
event_20241202_103045_123456.json  # JSON格式的完整检测数据
event_20241202_103050_789012.json  # 可用于分析和回溯
```

---

## 🔍 故障排除

### Q: 运行报错 "No module named 'psutil'"
**A:** 重新安装依赖
```powershell
pip install --upgrade psutil
```

### Q: 权限不足
**A:** 以管理员身份运行
```powershell
# 右键点击cmd.exe，选择"以管理员身份运行"
# 然后运行脚本
```

### Q: 检测到太多警报
**A:** 调整config.json中的阈值
```json
{
  "bandwidth_threshold_mbps": 150,  // 提高带宽阈值
  "risk_threshold": 50              // 提高风险等级阈值
}
```

### Q: 性能问题
**A:** 减少检测频率
```json
{
  "detection_interval": 30,         // 每30秒检测一次
  "enable_advanced_detection": false // 禁用高级检测
}
```

---

## 🎓 工作原理简述

```
LeechCore作弊流程:
  副机(Cheater) ──RPC/Network──> 主机(Game PC)
                                    ↓
                            LeechCore Service
                                    ↓
                    ┌──────────────┬──────────────┐
                    ↓              ↓              ↓
                 内存读取        网络传输      坐标解析
                    ↓              ↓              ↓
                    └──────────────┬──────────────┘
                                    ↓
                          返回坐标给副机
                                    ↑
                    LeechCore检测系统 ↙ ← 我们在这里检测

检测点:
1. 网络流量: 副机↔主机的大量LAN流量 (100+ MB/s)
2. 进程: LeechCore服务进程和异常网络连接
3. 驱动: 可疑驱动程序（kmddriver等）
4. 内存: 异常的内存访问模式
```

---

## 📈 部署建议

### 单机游戏
```
运行频率: 每天1次
命令: python main.py scan
时间: 每天凌晨2点
```

### 游戏服务器
```
运行模式: 持续监控
命令: python main.py monitor
设置: 配合Windows计划任务自启
```

### 蜜罐系统
```
运行模式: 实时监控 + 邮件警报
设置: 启用email_alerts_enabled
用途: 捕获作弊者试图入侵
```

---

## 🛡️ 安全建议

1. **定期更新**: 检查是否有新的可疑特征库更新
2. **日志备份**: 每周备份检测日志
3. **多层防御**: 配合其他反作弊手段
4. **权限管理**: 限制对检测系统日志的访问
5. **隔离环境**: 在独立的监控机器上运行

---

## 📞 技术支持

### 常见问题
参考 `README.md` 中的"常见问题"部分

### 查看日志
所有日志保存在 `logs/` 和 `detection_archive/` 目录

### 联系开发者
(添加您的联系方式)

---

## 📌 版本信息

- **版本**: 1.0.0
- **发布日期**: 2024-12-02
- **Python**: 3.7+
- **支持平台**: Windows 7+

---

**祝您使用愉快！有任何问题欢迎反馈。**
