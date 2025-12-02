# LeechCore 检测器（启发式）

简述：本检测器通过监测局域网带宽峰值并扫描运行的 Windows 服务进程的网络连接模式，来识别可能利用 LeechCore 或类似技术进行内存转发的可疑服务。

主要特性：
- 基于系统网卡的带宽采样（Mbps）
- 枚举 Windows 服务并检查其关联进程的网络连接（已连接数、远端主机数、疑似端口）
- 启发式风险评分与告警输出

依赖：
- Python 3.8+
- 在 `requirements.txt` 中已声明：`psutil`、`numpy`、`requests`（仅 `psutil` 为运行必需）

快速开始：
1. 安装依赖：
```powershell
python -m pip install -r requirements.txt
```
2. 以管理员身份打开 PowerShell（检测需要读取服务与进程信息）
3. 运行：
```powershell
.\start_detector.ps1
```
或直接运行（调试模式，单次检测）：
```powershell
python .\leechcore_detector.py --once
```

配置：
- 使用仓库根目录下的 `config.json` 来调整阈值，例如 `detection_interval`、`bandwidth_threshold_mbps` 和 `risk_threshold`。

建议与限制：
- 该工具为启发式检测，可用于快速排查高带宽 + 可疑服务场景，但无法替代深度包检测或主机入侵检测系统（HIDS）。
- 若需要更精确的按进程字节统计，可使用 Windows 专有接口（ETW/PDH）或抓包工具（WinPcap/NPcap）来做流量归属，此类改进可作为后续增强点。

后续工作建议：
- 将可疑样本（service name, exe path, PID, 连接列表）自动上报到集中检测服务器
- 集成基线学习，建立正常游戏/应用的带宽行为模型，减少误报
- 使用 ETW/Windows Perfmon 或 npcap + pcap 分析实现按进程字节级流量归属
