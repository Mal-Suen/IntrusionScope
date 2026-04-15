# IntrusionScope - 需求文档

## 项目概述

**IntrusionScope** 是一个跨平台的快速主机取证与威胁狩猎工具,专为入侵事件应急响应场景设计。融合业界顶级 DFIR 工具的最佳实践,支持 Linux 和 Windows 操作系统,能够在受入侵主机上快速执行、收集关键取证数据,帮助安全分析师快速评估入侵范围、确定攻击路径、提取关键证据。

### 设计理念

> **取各家之所长,构建统一的取证范式**

| 参考工具 | 借鉴核心理念 | IntrusionScope 实现方式 |
|----------|-------------|------------------------|
| **Velociraptor** | 查询驱动 + Artifact 生态 | 内置 IFQL(IntrusionScope Forensic Query Language),按需采集、高度可编程 |
| **GRR** | 远程编排 + 批量 Hunt | 支持本地单机与远程批量执行两种模式 |
| **PEASS-ng** | 智能规则匹配 + 彩色输出 | 内置风险评分引擎,终端实时高亮可疑发现 |
| **UAC** | 易失性优先 + YAML 驱动 | 严格按数据易失性顺序采集,YAML 定义可插拔 Artifact |
| **ir-rescue** | 第三方工具集成 + 配置驱动 | 模块化集成外部取证子工具,`.conf` 控制采集范围 |
| **Chainsaw** | Rust 高性能解析 + Sigma 规则 | 核心解析引擎采用 Rust 构建,原生支持 Sigma 规则 |
| **Hayabusa** | 时间线生成 + 威胁评分 | 自动生成取证时间线,五级威胁评分体系 |
| **Loki** | 多维 IOC 检测 | 文件名/哈希/YARA/C2 四维 IOC 匹配引擎 |
| **Dissect** | 统一抽象层 + 多格式解析 | 统一 Windows/Linux 数据模型,直接解析底层结构 |
| **Volatility 3** | 内存取证深度 | 可选集成内存转储与进程/网络/密钥提取 |

### 项目目标

- **快速部署**:单一静态二进制文件,零依赖运行,可在受感染主机上立即执行
- **查询驱动**:采用 IFQL 查询语言,按需精确采集,避免"全量扫描"的性能浪费
- **全面采集**:覆盖系统、网络、进程、文件系统、日志、内存等关键取证维度
- **最小侵入**:严格遵循数据易失性原则,采集过程对主机状态影响最小化
- **跨平台支持**:统一数据模型覆盖 Linux 和 Windows 两大主流操作系统
- **智能检测**:内置 Sigma 规则引擎、YARA 扫描、IOC 匹配与自动威胁评分
- **证据保全**:自动哈希校验、时间戳保护、结构化输出,确保证据可追溯

---

## 核心功能需求

### 1. 查询驱动采集引擎(IFQL)

> **借鉴 Velociraptor VQL 理念,实现按需精准采集**

#### 1.1 IFQL(IntrusionScope Forensic Query Language)
- 声明式查询语言,用于定义"采集什么"和"如何采集"
- 支持对文件系统、注册表、进程、日志、网络状态等结构化查询
- 内置 Artifact 模板库,每个 Artifact 封装一组 IFQL 查询逻辑
- 支持参数化 Artifact,允许运行时自定义采集范围
- 查询结果自动序列化为 JSON/CSV

#### 1.2 Artifact 生态
- 预置标准取证 Artifact(系统信息、进程、网络、文件、日志等)
- 社区可扩展 Artifact,用户可编写自定义 IFQL 查询
- Artifact 支持依赖声明,自动处理采集顺序
- 支持 Artifact 组合执行,形成取证 Playbook

### 2. 系统信息采集

#### 2.1 基础系统信息
- **Linux**: 主机名、内核版本、操作系统发行版、系统架构、运行时间、容器/虚拟化环境检测
- **Windows**: 主机名、OS 版本、构建号、系统架构、补丁级别、启动时间、域/工作组信息
- 系统时区与当前时间(用于时间线对齐)
- 硬件信息(CPU、内存、磁盘概览)

#### 2.2 系统配置
- **Linux**: `/etc/passwd`, `/etc/shadow` (权限允许时), `/etc/sudoers`, `/etc/hosts`, 环境变量
- **Windows**: 注册表关键配置(SAM、SYSTEM、SOFTWARE)、本地用户/组、环境变量
- 已安装的软件/包列表(APT/YUM/RPM vs Windows Installer/Program Files)
- 系统服务与守护进程状态

> **借鉴 Dissect 统一抽象层理念,Linux/Windows 输出采用统一数据模型**

### 3. 进程与线程取证

#### 3.1 进程快照
- 完整进程列表(PID、PPID、用户、启动时间、命令行、工作目录、会话 ID)
- 进程树结构(父子关系可视化,支持深度控制)
- 线程级信息(线程 ID、状态、CPU 时间)

#### 3.2 进程深度分析
- 进程打开的文件/句柄(`/proc/[pid]/fd` vs Windows Handle Table)
- 进程网络连接(关联 `/proc/[pid]/net` vs Windows TCP 表)
- 进程加载的模块/DLL/SO
- 进程内存映射概览(VAD 树 / `/proc/[pid]/maps`)
- 进程命令行参数与环境变量

#### 3.3 异常进程检测
> **借鉴 PEASS-ng 智能检测理念**
- 无文件进程(已删除可执行文件但仍运行)
- 进程注入特征(非正常 DLL/SO 加载、内存执行权限页)
- 隐藏进程(交叉验证 ps/proc/WMI 发现不一致)
- 异常父进程(非常规父子关系,如 Office 生成 PowerShell)
- 风险评分与彩色终端高亮输出

### 4. 网络状态取证

#### 4.1 网络连接
- 所有活跃网络连接(TCP/UDP/RAW)
- 监听端口与关联服务/进程
- 连接状态(ESTABLISHED/TIME_WAIT/CLOSE_WAIT 等)
- ARP 表与邻居缓存
- 路由表(主路由与策略路由)

#### 4.2 网络配置
- 网卡信息与 IP 配置(IPv4/IPv6、DHCP/静态)
- DNS 配置与缓存(`systemd-resolve` vs `Get-DnsClientCache`)
- **Linux**: `iptables`/`nftables`/`firewalld` 规则、`/etc/resolv.conf`、网络命名空间
- **Windows**: Windows 防火墙规则(入站/出站)、网络适配器配置、网络共享

#### 4.3 异常网络行为
> **借鉴 Loki C2 检测理念**
- 可疑外联检测(非常用端口、非常用协议、已知恶意 IP/域名)
- DNS 隧道特征识别(异常查询频率、超长域名、TXT 记录滥用)
- 隐藏端口/后门检测(非标准监听、Rootkit 隐藏端口)
- 代理/隧道检测(SOCKS、HTTP 隧道、ICMP 隧道)

### 5. 文件系统取证

#### 5.1 关键文件采集
- 系统日志文件
  - **Linux**: `/var/log/` 下的 auth.log、syslog、secure、cron、journal 等
  - **Windows**: 事件日志(Security、System、Application、PowerShell、Sysmon),支持 `.evtx` 解析
- 计划任务/定时任务
  - **Linux**: crontab(系统级和用户级)、`/etc/cron.*`、systemd timers、at 任务
  - **Windows**: 计划任务、WMI 事件订阅、COM 处理器自动化
- 启动项
  - **Linux**: systemd 服务、init.d、rc.local、bashrc/profile、XDG 自启动
  - **Windows**: 注册表 Run/RunOnce 键、启动文件夹、服务、AppInit_DLLs

> **借鉴 ir-rescue 配置驱动理念,通过 `.conf` 文件控制采集范围与深度**

#### 5.2 文件时间线
> **借鉴 Hayabusa/Chainsaw 时间线生成理念**
- 最近修改的系统文件(mtime/atime/ctime/btime)
- 临时目录异常文件(`/tmp`, `/var/tmp`, `%TEMP%`, `%APPDATA%`)
- Web shell 特征检测(Web 根目录异常文件、可疑 PHP/JSP/ASPX)
- Prefetch/Shimcache/Amcache 执行痕迹
- LNK 文件与 Jump Lists(Windows 用户活动痕迹)
- 已知恶意文件哈希比对(内置 + 可自定义 IOC)

#### 5.3 文件完整性
- 关键系统文件哈希计算(SHA256/MD5)
- 文件权限/所有权异常检测(SUID/SGID/World-writable vs Windows ACL)
- 隐藏文件/目录发现(`.` 前缀、NTFS ADS、扩展属性)
- USN 日志提取(Windows 文件系统变更日志)

#### 5.4 MFT 与文件系统元数据
> **借鉴 Chainsaw/Dissect 高性能解析理念**
- **Windows**: MFT 条目解析(文件名、时间戳、数据流、父目录)
- **Linux**: inode 元数据批量提取
- 备用数据流(ADS)检测
- 已删除文件痕迹(MFT 未覆盖条目)

### 6. 内存取证(可选深度模式)

> **借鉴 Volatility 3 内存分析理念**

#### 6.1 内存快照
- 可选的完整内存转储功能
- **Linux**: LiME 集成或 `/proc/kcore` 提取
- **Windows**: WinPMEM 集成或 hiberfil.sys/pagefile.sys 提取
- 增量转储支持(仅捕获自上次快照变更区域)

#### 6.2 内存特征提取
- 内存中的进程列表与隐藏进程
- 内存中的网络连接
- 内存中的加密密钥/凭证(SSH 私钥、浏览器密码、Kerberos TGT)
- 无文件恶意软件痕迹(内存注入、Shellcode、反射式 DLL)
- 内核模块与 Rootkit 检测(SSDT 钩子、IRP 钩子)

### 7. 用户活动取证

#### 7.1 登录历史
- **Linux**: `last`, `lastb`, `wtmp`, `utmp`, `btmp`, `journalctl` 登录事件
- **Windows**: 登录事件(Event ID 4624, 4625, 4634, 4647),远程登录(RDP 4778/4779)

#### 7.2 命令历史
- **Linux**: Bash history、Zsh history、Python history、Vim/NeoVim 撤销树
- **Windows**: PowerShell 执行历史(Script Block Logging 4104)、RunMRU、PSReadline 历史、DOSKey 缓冲区

#### 7.3 用户行为痕迹
- 剪贴板内容(如可获取)
- 浏览器历史(Chrome/Edge/Firefox)
- 最近访问的文件/文档(Recent 文件夹、X Recent Files)
- USB 设备连接历史(Windows Registry + Linux dmesg)
- 回收站文件

### 8. 安全软件与防护状态

#### 8.1 安全工具检测
- 已安装的杀毒软件/EDR/HIDS(Defender、CrowdStrike、SentinelOne 等)
- 安全软件运行状态(启用/禁用/旁路)
- 安全软件配置与日志

#### 8.2 防护措施状态
- **Linux**: SELinux/AppArmor 状态、auditd 配置、内核模块签名验证
- **Windows**: Windows Defender 状态、AMSI 配置、LSA 保护、Credential Guard

#### 8.3 安全日志完整性
- 日志清除检测(Event Log 服务重启、日志文件时间断档)
- 审计策略变更痕迹(Event ID 4719/4902/4906)
- 安全软件禁用/卸载痕迹

### 9. 自动化威胁检测

> **融合 Loki + Chainsaw + Hayabusa 检测理念**

#### 9.1 IOC 匹配引擎(四维检测)
- **文件名 IOC**: 正则匹配可疑文件路径/名称
- **哈希 IOC**: MD5/SHA1/SHA256 恶意文件哈希比对
- **C2 IOC**: 进程网络连接与已知 C2 IP/域名匹配
- **YARA 规则**: 文件内容与进程内存 YARA 模式匹配
- 支持自定义 IOC 文件导入(JSON/YAML 格式)

#### 9.2 Sigma 规则引擎
> **借鉴 Chainsaw/Hayabusa Sigma 集成理念**
- 原生支持 Sigma 规范(含 v2 关联规则)
- 内置 Sigma 规则集,支持自动更新
- 规则字段映射(自动适配不同日志源字段命名)
- 按严重级别/状态/类型动态过滤规则
- 匹配结果关联 MITRE ATT&CK 战术与技术

#### 9.3 异常行为标记
- 异常进程名/路径(系统目录外的 svchost、临时文件执行)
- 异常网络连接(反向 Shell、非常用端口、Tor 节点)
- 异常文件权限(World-writable 配置文件、SUID 异常)
- 已知 Rootkit/后门特征(DKOM 隐藏、服务劫持)
- 横向移动痕迹(PsExec、WMI 远程执行、RDP 爆破)

#### 9.4 威胁评分与风险评估
> **借鉴 Hayabusa 五级评分体系**
- **informational**: 普通事件,无需关注
- **low**: 低危告警,可能为误报
- **medium**: 中危告警,需进一步调查
- **high**: 高危告警,高度可疑
- **critical**: 严重告警,确认为恶意行为(可自动升级至 emergency)
- 自动生成入侵严重性评分
- 关键发现摘要报告
- MITRE ATT&CK 覆盖热力图

### 10. 日志解析与时间线分析

> **借鉴 Chainsaw/Hayabusa 高性能日志解析理念**

#### 10.1 Windows 事件日志解析
- 原生支持 `.evtx` 文件解析(Rust 高性能解析引擎)
- 支持 EVTX 空闲空间记录恢复(record carving)
- 字段标准化与统一命名规范
- 支持 Sysmon、PowerShell、安全日志等主流事件类型

#### 10.2 Linux 日志解析
- journalctl 日志结构化解析
-  syslog/auth.log/cron.log 等关键日志解析
- 审计日志(auditd)解析
- 应用日志(Web 服务器、数据库)可选采集

#### 10.3 时间线生成
- 多源日志整合为单一取证时间线
- 支持按时间排序、事件频率可视化
- Shimcache + Amcache 近时间戳对检测
- 输出格式:CSV、JSON、JSONL、HTML 摘要
- 兼容 Timesketch、Elastic Stack 等下游分析工具

---

## 非功能需求

### 1. 性能要求

#### 1.1 时间性能

| 指标 | 目标值 | 说明 |
|------|--------|------|
| 工具启动时间 | < 3 秒 | 从执行到开始采集 |
| 规则库加载时间 | < 10 秒 | 标准模式规则加载 |
| 快速模式采集 | < 1 分钟 | 仅易失性数据 + 核心系统信息 |
| 标准模式采集 | < 5 分钟 | 完整系统信息 + 日志 + 文件时间线 |
| 深度模式采集 | < 15 分钟 | 全量数据 + 内存转储 + 深度检测 |
| 日志解析性能 | 3GB EVTX + 4000 规则 < 10 分钟 | 参考 Hayabusa 性能 |

#### 1.2 资源占用

| 指标 | 目标值 | 说明 |
|------|--------|------|
| 基础内存占用 | < 128MB | 不含规则库加载 |
| 规则库内存占用 | < 256MB | 含 Bloom Filter 索引 |
| 内存转储除外 | 内存转储文件不计入限制 | 单独存储 |
| CPU 使用率 | 单核峰值 < 50% | 多核环境下总体 < 30% |
| 磁盘 I/O | 不超过 50MB/s | 避免影响生产系统 |

#### 1.3 输出体积

| 模式 | 目标体积 | 说明 |
|------|---------|------|
| 快速模式 | < 10MB | 压缩前 |
| 标准模式 | < 50MB | 压缩前,不含日志原文 |
| 深度模式 | < 500MB | 压缩前,不含内存转储 |
| 单文件上限 | 100MB | 超过时自动分割 |

#### 1.4 并发控制

| 参数 | 默认值 | 可配置范围 |
|------|--------|-----------|
| 采集并发线程 | 4 | 1-16 |
| 规则下载并发 | 4 | 1-8 |
| 文件扫描并发 | CPU 核心数 | 1-32 |
| 网络请求超时 | 30 秒 | 5-300 秒 |

### 2. 可靠性要求

#### 2.1 数据完整性
- 采集过程中不修改主机状态(只读操作优先)
- 严格遵循数据易失性顺序(RAM → 网络连接 → 进程 → 文件)
- 输出数据自动校验(SHA256 哈希验证)
- 可选数字签名(工具私钥签名,公钥验证)

#### 2.2 容错能力
- 单个采集项失败不影响整体流程
- 异常中断后可恢复或标记不完整
- 权限不足时优雅降级,记录受限项
- 磁盘空间不足时提前警告并停止

#### 2.3 离线能力
- 零依赖外部网络(离线环境可运行)
- 内置规则库保证基础检测能力
- 所有核心功能无需网络即可运行
- 支持离线规则更新导入

### 3. 兼容性要求

#### 3.1 Linux 支持

| 项目 | 要求 |
|------|------|
| 发行版 | Ubuntu 18.04+, CentOS/RHEL 7+, Debian 10+, Alpine 3.12+ |
| 内核版本 | 4.x+ (推荐 5.x+) |
| 架构 | x86_64, ARM64 |
| 最小构建 | 支持 musl libc (Alpine) |

#### 3.2 Windows 支持

| 项目 | 要求 |
|------|------|
| 版本 | Windows 10/11, Windows Server 2016/2019/2022 |
| 架构 | x86_64, ARM64 |
| 依赖 | 无外部运行时依赖 |

#### 3.3 特殊环境

| 环境 | 支持级别 |
|------|---------|
| Docker 容器 | 完全支持 |
| Kubernetes Pod | 完全支持 |
| 嵌入式 Linux | 精简版支持 |
| Windows PE | 基础支持 |

### 4. 安全性要求

#### 4.1 工具安全
- 代码签名(可验证来源)
- 发布包哈希校验
- 无后门/恶意代码(开源审计)

#### 4.2 数据安全
- 输出数据加密选项(AES-256-GCM)
- 采集凭证信息脱敏或加密存储
- 敏感信息不记录到日志
- 代理认证信息不持久化存储

#### 4.3 运行安全
- 工具执行后不留痕迹(可选自清理模式)
- 不修改系统配置
- 不安装任何服务或驱动

### 5. 可用性要求

#### 5.1 交互模式
- **交互式模式**: 引导式采集,逐步确认
- **无人值守模式**: 一键全自动执行
- **实时进度反馈**: 终端彩色输出 + 进度条
- **JSON 日志**: 可选结构化日志输出

#### 5.2 输出友好性
- 结构化输出(JSON + 人类可读报告)
- 多格式报告(Markdown + HTML)
- 彩色终端输出(可配置关闭)
- 国际化支持(中/英文)

#### 5.3 配置管理
- 配置驱动采集(`.conf` 文件控制范围)
- YAML 格式配置文件
- 支持配置文件模板
- 配置项验证与错误提示

### 6. 可维护性要求

#### 6.1 日志与诊断
- 详细日志级别控制 (debug/info/warn/error)
- 日志文件轮转支持
- 问题诊断模式 (--verbose --log-file)

#### 6.2 更新与升级
- 规则库自动更新
- 版本检查(可选)
- 更新包签名验证

#### 6.3 扩展性
- Artifact 可插拔扩展
- 自定义 YARA/Sigma 规则
- 自定义 IOC 导入
- 插件系统预留接口

---

## 输出规范

### 1. 输出结构

> **借鉴 ir-rescue 分类归档理念 + UAC 易失性顺序**

```
intrusionscope_<hostname>_<timestamp>/
├── metadata.json              # 采集元数据(时间、主机信息、工具版本)
├── collection.log             # 采集过程日志
├── 01_volatile/               # 易失性数据(最先采集)
│   ├── network_connections.json
│   ├── arp_cache.json
│   ├── running_processes.json
│   ├── process_tree.json
│   ├── open_files.json        # 打开的文件/句柄
│   └── memory_dump.raw        # 可选
├── 02_system/
│   ├── system_info.json
│   ├── users.json
│   ├── groups.json
│   ├── services.json
│   ├── installed_packages.json
│   ├── environment.json
│   └── container_info.json    # 容器环境信息(如适用)
├── 03_filesystem/
│   ├── timeline.json
│   ├── startup_items.json
│   ├── scheduled_tasks.json
│   ├── mft_entries.json       # Windows only
│   ├── prefetch/              # Windows Prefetch 文件
│   ├── logs/                  # 采集的日志文件
│   │   ├── sysmon/
│   │   ├── security/
│   │   └── application/
│   └── hashes.json
├── 04_user_activity/
│   ├── login_history.json
│   ├── command_history.json
│   ├── browser_history.json
│   ├── usb_history.json
│   ├── recent_files.json      # 最近访问文件
│   └── clipboard.txt
├── 05_security/
│   ├── av_status.json
│   ├── firewall_rules.json
│   ├── config_audit.json
│   └── patch_level.json       # 补丁级别
├── 06_analysis/
│   ├── ioc_matches.json       # IOC 匹配结果
│   ├── sigma_matches.json     # Sigma 规则匹配
│   ├── yara_matches.json      # YARA 规则匹配
│   ├── c2_matches.json        # C2 IOC 匹配
│   ├── findings.json          # 自动化发现摘要
│   ├── threat_score.json      # 威胁评分
│   ├── mitre_attack.json      # MITRE ATT&CK 映射
│   └── timeline.csv           # 取证时间线
├── 07_rules_snapshot/         # 规则库快照(新增)
│   ├── index.json             # 规则版本信息
│   ├── sources.json           # 数据源列表
│   └── rule_counts.json       # 各类规则统计
├── report.md                  # 人类可读报告
├── report.html                # HTML 摘要报告
├── report_summary.txt         # 纯文本摘要(快速预览)
└── checksums.sha256           # 完整性校验
```

### 2. 元数据格式

```json
{
  "tool": {
    "name": "IntrusionScope",
    "version": "1.0.0",
    "build": "20260415",
    "rules_version": "2026041500"
  },
  "collection": {
    "start_time": "2026-04-15T10:30:00Z",
    "end_time": "2026-04-15T10:35:00Z",
    "duration_seconds": 300,
    "mode": "standard",
    "hostname": "compromised-host",
    "platform": "windows",
    "os_version": "Windows Server 2019",
    "architecture": "x86_64",
    "timezone": "UTC+8",
    "privileges": "Administrator"
  },
  "rules": {
    "hash_count": 100000,
    "yara_count": 300,
    "sigma_count": 2000,
    "c2_count": 5000,
    "last_sync": "2026-04-15T00:00:00Z"
  }
}
```

### 3. 数据格式

#### 3.1 通用格式规范
- **JSON**: 所有结构化数据采用 UTF-8 编码 JSON
- **时间戳**: ISO 8601 格式(YYYY-MM-DDTHH:MM:SS.sssZ)
- **哈希**: SHA256(默认),可选 MD5
- **报告**: Markdown + HTML 双格式,可转换为 PDF

#### 3.2 时间线 CSV 格式

```csv
timestamp,event_type,source,severity,description,mitre_tactic,mitre_technique
2026-04-15T09:15:00Z,process_create,sysmon,high,Suspicious PowerShell execution,Execution,T1059.001
2026-04-15T09:16:00Z,network_connection,netstat,critical,C2 connection to 10.0.0.99:4444,Command and Control,T1071
```

#### 3.3 威胁评分格式

```json
{
  "overall_score": 75,
  "risk_level": "high",
  "summary": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8,
    "informational": 45
  },
  "top_findings": [
    {
      "type": "c2_connection",
      "severity": "critical",
      "description": "Connection to known C2 server",
      "mitre_attack": ["T1071", "TA0011"]
    }
  ]
}
```

### 4. 完整性校验

#### 4.1 校验文件格式

```
# SHA256 checksums generated by IntrusionScope v1.0.0
# Generated: 2026-04-15T10:35:00Z

a1b2c3d4e5f6...  metadata.json
f6e5d4c3b2a1...  01_volatile/network_connections.json
...
```

#### 4.2 数字签名(可选)

```bash
# 生成签名
gpg --detach-sign --armor checksums.sha256

# 验证签名
gpg --verify checksums.sha256.sig
```

### 5. 加密输出

#### 5.1 加密格式
- 算法: AES-256-GCM
- 密钥派生: PBKDF2 (100,000 iterations)
- 输出格式: `.enc` 后缀加密文件

#### 5.2 解密命令

```bash
# 解密输出包
intrusionscope decrypt --input output.enc --password
```
- 可选数字签名(工具私钥签名,公钥验证)

---

## 技术架构

### 1. 开发语言

- **核心引擎**: Rust (高性能解析:EVTX/MFT/YARA/Sigma)
- **主程序**: Go (跨平台编译、单一二进制、无运行时依赖)
- **优势**: 结合 Rust 的安全性与性能 + Go 的开发效率与跨平台能力

### 2. 架构设计

```
┌─────────────────────────────────────────────────────────┐
│                  IntrusionScope CLI                     │
├─────────────────────────────────────────────────────────┤
│                    Core Engine                          │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐           │
│  │  IFQL     │  │ Collector │  │ Analyzer  │           │
│  │  Parser   │  │ Executor  │  │ Reporter  │           │
│  └───────────┘  └───────────┘  └───────────┘           │
├─────────────────────────────────────────────────────────┤
│                 Artifact Layer                          │
│  ┌──────────────────────────────────────────┐           │
│  │  YAML-defined Artifacts (可插拔)          │           │
│  │  - System / Process / Network / File ... │           │
│  └──────────────────────────────────────────┘           │
├─────────────────────────────────────────────────────────┤
│              Platform Abstraction Layer                 │
│  ┌──────────────┐              ┌──────────────┐         │
│  │   Linux      │              │   Windows    │         │
│  │   Plugin     │              │   Plugin     │         │
│  └──────────────┘              └──────────────┘         │
├─────────────────────────────────────────────────────────┤
│              Detection Engine (Rust)                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │   IOC    │  │  Sigma   │  │  YARA    │              │
│  │  Matcher │  │  Engine  │  │  Scanner │              │
│  └──────────┘  └──────────┘  └──────────┘              │
└─────────────────────────────────────────────────────────┘
```

### 3. 核心模块

- **IFQL Parser**: 解析查询语言,生成执行计划
- **Collector Executor**: 按 Artifact 定义执行采集,遵循易失性顺序
- **Analyzer Reporter**: IOC/Sigma/YARA 检测,威胁评分,报告生成
- **Artifact Registry**: 管理 Artifact 加载、依赖、版本
- **Platform Plugin**: Linux/Windows 平台差异抽象
- **Detection Engine**: Rust 构建的高性能检测引擎(IOC/Sigma/YARA)

### 4. 外部依赖

- **最小化原则**: 优先使用标准库
- 可选集成:
  - YARA 规则引擎(恶意软件检测)
  - Sigma 规则解析(日志分析)
  - LiME/WinPMEM(内存转储)
  - VirusTotal API(哈希查询,需网络)

---

## 11. 威胁特征库管理

> **核心原则**: 内置基础库保证离线可用, 云端同步保证时效性, 用户自定义保证灵活性

### 11.1 特征库同步机制

#### 11.1.1 首次启动同步
- 检测规则库目录是否存在 (`rules/index.json`)
- 不存在时自动从免费数据源下载内置规则
- 显示下载进度条,支持并发下载
- 下载失败时警告用户检测引擎功能受限
- 构建规则索引与 Bloom Filter 加速结构

#### 11.1.2 增量更新机制
- 每次启动检查 `last_sync` 时间戳
- 超过更新间隔(默认 24 小时)触发后台异步同步
- 同步过程不阻塞取证主流程
- 原子替换规则文件,保证运行中不受影响
- 支持按数据源配置不同更新频率

#### 11.1.3 离线环境支持
- `--no-sync` 参数跳过规则同步
- `--offline` 参数完全禁用网络请求
- 支持通过 USB 介质导入规则更新包
- 离线环境可使用内置规则库正常工作

### 11.2 免费数据源清单

以下数据源均**无需 API Key**, 可通过 HTTPS 直接下载:

| 数据源 | 类型 | 更新频率 | 数据量级 | 说明 |
|--------|------|---------|---------|------|
| **MalwareBazaar** | 恶意哈希 (SHA256/MD5/SHA1) | 实时 | 100 万+ | abuse.ch 运营,推荐核心数据源 |
| **URLhaus** | 恶意 URL/域名 | 每日 | 50 万+ | 与 MalwareBazaar 互补 |
| **ThreatFox** | IOC (IP/域名/URL/哈希) | 每日 | 20 万+ | abuse.ch IOC 数据库 |
| **DShield Blocklist** | 恶意 IP 段 | 每日 | 5 千+ | SANS ISC 运营 |
| **Spamhaus DROP** | 恶意 IP 段 | 每日 | 2 万+ | 僵尸网络/垃圾邮件 IP |
| **SigmaHQ Rules** | Sigma 检测规则 | 持续 | 5000+ 条 | 日志检测规则标准 |
| **Neo23x0 signature-base** | YARA 规则 + 文件名 IOC | 持续 | 300+ 条 | LOKI 项目维护 |
| **YARAHQ yara-rules** | YARA 规则 | 持续 | 200+ 条 | 社区维护 |
| **NSRL RDS** | 良性文件哈希 (白名单) | 定期 | 10 亿+ | NIST 标准,用于白名单过滤 |

### 11.3 三层特征库模型

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: 内置库 (Built-in)                             │
│  - 随工具发布, 离线可用                                  │
│  - 包含高频恶意哈希 + 核心 YARA + 基础 Sigma            │
│  - 大小: ~50MB                                          │
├─────────────────────────────────────────────────────────┤
│  Layer 2: 用户库 (Custom)                               │
│  - 用户自定义/企业情报导入                               │
│  - 格式: JSON/YAML                                      │
│  - 支持私有 IOC、自定义 YARA、企业 Sigma 规则           │
├─────────────────────────────────────────────────────────┤
│  Layer 3: 云端库 (Cloud/Sync)                           │
│  - 在线同步最新威胁情报                                  │
│  - 接入免费公开数据源                                    │
│  - 离线环境不使用                                        │
└─────────────────────────────────────────────────────────┘
```

### 11.4 自定义规则导入

#### 11.4.1 IOC 导入格式
```json
{
  "version": "1.0",
  "updated": "2026-04-15T00:00:00Z",
  "source": "internal-threat-intel",
  "hashes": [
    {
      "sha256": "abc123...",
      "threat": "APT-XX Malware",
      "confidence": "high",
      "tags": ["apt", "malware", "custom"]
    }
  ],
  "c2_indicators": [
    {
      "type": "ip",
      "value": "10.0.0.99",
      "port": 8443,
      "threat": "Known C2 Server",
      "tags": ["c2", "apt"]
    }
  ]
}
```

#### 11.4.2 规则导入命令
```bash
# 导入自定义 IOC
intrusionscope rules import --file custom_iocs.json

# 导入自定义 YARA 规则
intrusionscope rules import --yara ./custom_yara/

# 导入自定义 Sigma 规则
intrusionscope rules import --sigma ./custom_sigma/

# 导出规则库(用于离线更新其他机器)
intrusionscope rules export --output rules_backup.tar.gz
```

### 11.5 规则库管理命令

```bash
intrusionscope rules <subcommand>

子命令:
  sync          手动触发规则同步
  status        查看规则库状态(版本、来源、更新时间)
  stats         查看规则统计信息(各类规则数量)
  import        导入自定义规则
  export        导出规则库
  update        强制更新所有规则源
  clean         清理规则缓存
```

### 11.6 性能优化要求

| 优化项 | 方法 | 目标效果 |
|--------|------|---------|
| 白名单优先 | NSRL 已知良性哈希直接跳过 | 减少 80%+ 无效扫描 |
| Bloom Filter | 哈希库使用布隆过滤器预过滤 | 查询速度提升 100 倍 |
| Trie Tree | C2 IP/域名使用前缀树存储 | O(k) 查询复杂度 |
| 规则预编译 | YARA 规则预编译为字节码 | 扫描速度提升 5~10 倍 |
| 按需加载 | 按采集模式加载不同量级规则 | quick 模式仅核心规则 |

---

## 12. 环境适配

### 12.1 代理环境支持

#### 12.1.1 代理配置方式
```bash
# 环境变量方式
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080

# 命令行参数方式
intrusionscope --proxy http://proxy:8080 --mode standard

# 配置文件方式 (.intrusionscope.conf)
[network]
proxy = http://proxy.company.com:8080
proxy_auth = basic:user:pass
```

#### 12.1.2 代理认证
- 支持 Basic/Digest/NTLM 认证
- 支持从环境变量读取认证信息
- 敏感信息不记录到日志

### 12.2 离线环境支持

#### 12.2.1 完全离线模式
```bash
# 离线模式(禁用所有网络请求)
intrusionscope --offline --mode standard --output ./case_001

# 跳过规则同步(使用本地缓存)
intrusionscope --no-sync --mode quick --output ./case_001
```

#### 12.2.2 离线规则更新
```bash
# 在联网机器上导出规则
intrusionscope rules export --output rules_latest.tar.gz

# 通过 USB 传输到离线机器
# 在离线机器上导入
intrusionscope rules import --file rules_latest.tar.gz
```

#### 12.2.3 离线环境要求
- 内置规则库保证基础检测能力
- 所有核心功能无需网络即可运行
- 文档提供离线部署指南

### 12.3 受限环境适配

#### 12.3.1 低权限环境
- 非 root/Administrator 权限时优雅降级
- 记录权限不足的采集项
- 终端彩色提示受限功能
- 输出报告中标注权限限制

```bash
# 权限不足时的输出示例
[!] Running without root privileges
[!] Limited collection capabilities:
    - Memory dump: SKIPPED (requires root)
    - /etc/shadow: SKIPPED (permission denied)
    - Process memory: LIMITED
```

#### 12.3.2 资源受限环境
- 内存限制: 可配置最大内存使用量
- CPU 限制: 可配置并发线程数上限
- 磁盘限制: 可配置输出文件大小上限
- 时间限制: 可配置采集超时时间

```bash
# 资源限制参数
intrusionscope --max-memory 128M --max-threads 2 --timeout 300 --mode quick
```

#### 12.3.3 容器化环境
- 检测是否运行在容器中 (Docker/Kubernetes)
- 适配容器特有的日志位置
- 识别容器逃逸风险特征
- 支持采集容器元数据

### 12.4 特殊系统环境

#### 12.4.1 嵌入式/物联网设备
- 支持资源极度受限的嵌入式 Linux
- 提供 minimal 构建版本 (< 10MB)
- 精简采集项,仅保留核心功能

#### 12.4.2 云环境
- 检测云平台类型 (AWS/Azure/GCP/阿里云)
- 采集云实例元数据
- 识别云安全组/网络配置
- 支持输出推送至云存储 (S3/Blob)

---

## 使用场景

### 场景 1: 实时应急响应

```bash
# 在受感染主机上直接运行
sudo ./intrusionscope --mode full --output /tmp/forensics_output

# 通过 SSH 远程执行
ssh admin@compromised-host "sudo ./intrusionscope --mode quick --output -" | tar xzf -

# 使用自定义 Artifact 组合
./intrusionscope --mode custom --config playbook_lateral_movement.yaml --output ./case_001
```

### 场景 2: 离线取证

```bash
# 通过 USB 介质在隔离网络运行
./intrusionscope --mode full --encrypt --output /media/usb/output

# 生成完整报告用于后续分析
./intrusionscope --mode full --output ./case_001 --report all

# 内存深度取证
./intrusionscope --mode deep --memory-dump --output ./memory_case_001
```

### 场景 3: 批量采集

> **借鉴 GRR Hunt 理念**

```bash
# 通过配置管理工具批量部署执行
ansible compromised_hosts -m shell -a "./intrusionscope --mode quick --output /tmp/"

# 使用 GRR/Velociraptor 远程下发
grr_client_exec --hosts host1,host2,host3 --command "intrusionscope --mode quick"
```

### 场景 4: 威胁狩猎

```bash
# 仅运行检测引擎(不采集数据)
./intrusionscope --scan-only --ioc-file custom_iocs.json --sigma-rules ./sigma --yara-rules ./yara

# 日志离线分析
./intrusionscope --analyze-evtx /path/to/logs.evtx --sigma-rules ./sigma --output results.json
```

---

## 命令行接口设计

### 主命令

```bash
intrusionscope [OPTIONS]
intrusionscope <subcommand> [OPTIONS]

子命令:
  rules         规则库管理 (sync/status/stats/import/export/update/clean)
  version       显示详细版本信息
  help          显示帮助信息
```

### 全局选项

```bash
模式选择:
  --mode <quick|standard|deep|custom>  采集模式 (默认: standard)
    quick      快速采集(< 1 分钟),仅易失性数据 + 核心系统信息
    standard   标准采集(< 5 分钟),完整系统信息 + 日志 + 文件时间线
    deep       深度采集(< 15 分钟),全量数据 + 内存转储 + 深度检测
    custom     自定义采集(通过 Artifact 配置文件)

输出控制:
  --output <path>                      输出目录
  --format <json|csv|markdown|html|all>  输出格式 (默认: all)
  --compress                           打包为 tar.gz
  --encrypt                            加密输出包
  --password <password>                加密密码(交互输入更安全)

采集范围:
  --include <artifact,...>             仅采集指定 Artifact
  --exclude <artifact,...>             排除指定 Artifact
  --config <path>                      Artifact 配置文件(YAML)
  --ioc-file <path>                    自定义 IOC 文件
  --sigma-rules <path>                 Sigma 规则目录
  --yara-rules <path>                  YARA 规则目录

规则库控制:
  --no-sync                            跳过规则库同步(使用本地缓存)
  --rules-dir <path>                   自定义规则库目录
  --rules-mode <minimal|standard|full> 规则加载模式 (默认: standard)

网络环境:
  --offline                            完全离线模式(禁用所有网络请求)
  --proxy <url>                        HTTP/HTTPS 代理地址
  --proxy-auth <user:pass>             代理认证信息
  --timeout <seconds>                  网络请求超时 (默认: 30)

资源限制:
  --max-memory <size>                  最大内存使用量 (如: 128M, 1G)
  --max-threads <n>                    最大并发线程数 (默认: 4)
  --max-output <size>                  单个输出文件大小上限 (默认: 100M)
  --collection-timeout <seconds>       采集超时时间 (默认: 600)

高级选项:
  --memory-dump                        包含完整内存转储
  --scan-only                          仅扫描检测,不采集数据
  --analyze-evtx <path>                离线分析 EVTX 文件
  --cleanup                            执行后清理工具痕迹
  --verbose                            详细输出
  --quiet                              静默模式
  --color <auto|always|never>          彩色输出控制
  --log-file <path>                    日志输出文件

通用:
  --version                            显示版本
  --help                               显示帮助
```

### rules 子命令

```bash
intrusionscope rules <subcommand> [OPTIONS]

子命令:
  sync                                手动触发规则同步
    --force                             强制同步所有规则源
    --source <name>                     仅同步指定数据源

  status                              查看规则库状态
    --json                              JSON 格式输出

  stats                               查看规则统计信息
    --detail                            详细统计(按数据源分类)

  import                              导入自定义规则
    --file <path>                       导入 IOC 文件 (JSON/YAML)
    --yara <path>                       导入 YARA 规则目录
    --sigma <path>                      导入 Sigma 规则目录
    --overwrite                         覆盖已存在的规则

  export                              导出规则库
    --output <path>                     输出文件路径 (默认: rules_export.tar.gz)
    --include-custom                    包含用户自定义规则

  update                              强制更新所有规则源
    --parallel <n>                      并发下载数 (默认: 4)

  clean                               清理规则缓存
    --all                               清理所有规则(恢复到初始状态)
```

### 使用示例

```bash
# 标准采集
sudo ./intrusionscope --mode standard --output /tmp/forensics_output

# 离线环境快速采集
./intrusionscope --offline --mode quick --output ./case_001

# 通过代理同步规则
./intrusionscope rules sync --proxy http://proxy:8080

# 导入企业自定义 IOC
./intrusionscope rules import --file company_iocs.json

# 资源受限环境采集
./intrusionscope --max-memory 128M --max-threads 2 --mode quick

# 仅运行检测引擎
./intrusionscope --scan-only --ioc-file custom_iocs.json --output results.json
```

---

## 开发里程碑

### Phase 1: 基础框架(MVP) - 3 个月

#### 1.1 项目基础设施
- [ ] 项目结构搭建(Go + Rust 混合项目)
- [ ] 跨平台编译配置(Linux/Windows, x86_64/ARM64)
- [ ] CI/CD 流水线配置
- [ ] 代码规范与 Linter 配置

#### 1.2 CLI 框架
- [ ] CLI 框架与参数解析(cobra/pflag)
- [ ] 子命令结构设计
- [ ] 彩色输出支持
- [ ] 进度条显示

#### 1.3 核心解析器
- [ ] IFQL 基础语法解析器
- [ ] Artifact YAML 加载器
- [ ] 配置文件解析器(.conf)

#### 1.4 基础采集
- [ ] Linux 基础采集(系统信息、进程、网络)
- [ ] Windows 基础采集(系统信息、进程、网络)
- [ ] 权限检查与优雅降级

#### 1.5 输出系统
- [ ] JSON 输出与校验
- [ ] 输出目录结构生成
- [ ] 哈希校验文件生成

### Phase 2: 核心功能完善 - 3 个月

#### 2.1 Linux 完整采集
- [ ] 文件系统采集(时间线、启动项、计划任务)
- [ ] 日志采集(syslog、journal、auditd)
- [ ] 用户活动采集(登录历史、命令历史)
- [ ] 安全配置采集(SELinux、防火墙)

#### 2.2 Windows 完整采集
- [ ] 注册表采集
- [ ] 事件日志采集(EVTX)
- [ ] 用户活动采集(登录事件、PowerShell 历史)
- [ ] 安全配置采集(Defender、防火墙)

#### 2.3 关联分析
- [ ] 进程树构建与可视化
- [ ] 网络连接与进程关联
- [ ] 文件时间线生成

#### 2.4 报告生成
- [ ] 自动化报告生成(Markdown + HTML)
- [ ] 威胁发现摘要
- [ ] MITRE ATT&CK 映射

### Phase 3: 威胁检测引擎 - 3 个月

#### 3.1 Rust 检测引擎框架
- [ ] FFI 接口设计(Go ↔ Rust)
- [ ] 检测引擎核心架构
- [ ] 规则加载与编译

#### 3.2 威胁特征库系统
- [ ] 特征库同步框架
- [ ] 免费数据源下载器(MalwareBazaar、URLhaus 等)
- [ ] 规则索引构建与 Bloom Filter 加速
- [ ] 规则库管理命令(sync/status/import/export)
- [ ] 离线规则更新支持

#### 3.3 IOC 检测
- [ ] 文件名 IOC 匹配(正则)
- [ ] 哈希 IOC 匹配(SHA256/MD5)
- [ ] C2 IOC 匹配(IP/域名)
- [ ] 白名单过滤(NSRL)

#### 3.4 规则引擎
- [ ] YARA 扫描器集成
- [ ] Sigma 规则引擎
- [ ] 规则预编译与缓存

#### 3.5 威胁评估
- [ ] 威胁评分模型(五级评分)
- [ ] 时间线生成器
- [ ] MITRE ATT&CK 自动映射

### Phase 4: 高级功能 - 2 个月

#### 4.1 内存取证
- [ ] 内存转储集成(LiME/WinPMEM)
- [ ] 内存基础分析(进程、网络连接)

#### 4.2 高性能解析
- [ ] MFT 高性能解析(Rust)
- [ ] EVTX 高性能解析(Rust)
- [ ] 空闲空间记录恢复

#### 4.3 安全特性
- [ ] 加密输出(AES-256-GCM)
- [ ] 代码签名
- [ ] 自清理模式

#### 4.4 环境适配
- [ ] 代理环境支持
- [ ] 离线模式完善
- [ ] 容器环境检测
- [ ] 云环境元数据采集

#### 4.5 扩展功能
- [ ] 远程批量执行模式
- [ ] Artifact 社区生态
- [ ] 插件系统接口

### Phase 5: 生产就绪 - 1 个月

#### 5.1 质量保证
- [ ] 代码审计与安全审查
- [ ] 单元测试覆盖率 > 80%
- [ ] 集成测试全覆盖
- [ ] 性能基准测试

#### 5.2 文档完善
- [ ] 用户手册
- [ ] 部署指南
- [ ] API 文档
- [ ] 故障排查指南

#### 5.3 发布准备
- [ ] 多平台构建验证
- [ ] 发布包签名
- [ ] 版本更新机制
- [ ] 发布 v1.0

---

## 风险与挑战

1. **权限限制**: 部分采集操作需要 root/Administrator 权限
   - 缓解:优雅降级,记录权限不足的采集项,终端彩色提示

2. **抗取证环境**: 攻击者可能部署反取证措施
   - 缓解:多数据源交叉验证,标记异常缺失,内存检测辅助

3. **系统影响**: 采集过程可能影响脆弱系统
   - 缓解:资源使用限制,快速模式优先,易失性顺序采集

4. **误报控制**: 自动化检测可能产生误报
   - 缓解:置信度评分,可自定义规则阈值,误报排除规则

5. **跨平台一致性**: Linux/Windows 差异导致输出不统一
   - 缓解:统一数据模型,平台特定字段标注,IFQL 抽象查询

6. **Rust + Go 混合开发**: 技术栈复杂度高
   - 缓解:清晰模块边界,FFI 接口规范,团队技能储备

---

## 成功标准

- ✅ 支持 Linux 和 Windows 主流发行版
- ✅ 快速模式 < 1 分钟完成核心采集
- ✅ 输出数据 100% 可解析(JSON 校验通过)
- ✅ 零外部依赖运行(离线环境可用)
- ✅ Sigma 规则兼容性 100%
- ✅ YARA 扫描性能优于 Python 实现 10 倍
- ✅ 通过真实入侵场景测试验证
- ✅ 社区/用户反馈正面,实际应急响应中采用

---

## 附录

### A. 参考工具

| 工具 | 仓库 | 借鉴点 |
|------|------|--------|
| Velociraptor | https://github.com/Velocidex/velociraptor | VQL 查询驱动、Artifact 生态 |
| GRR | https://github.com/google/grr | 远程编排、批量 Hunt |
| PEASS-ng | https://github.com/carlospolop/PEASS-ng | 智能检测、彩色输出 |
| UAC | https://github.com/tclahr/uac | 易失性优先、YAML 驱动 |
| ir-rescue | https://github.com/diogo-fernan/ir-rescue | 第三方工具集成、配置驱动 |
| Chainsaw | https://github.com/WithSecureLabs/chainsaw | Rust 高性能解析、Sigma 集成 |
| Hayabusa | https://github.com/Yamato-Security/hayabusa | 时间线生成、威胁评分 |
| Loki | https://github.com/Neo23x0/Loki | 四维 IOC 检测 |
| Dissect | https://github.com/fox-it/dissect | 统一抽象层、多格式解析 |
| Volatility 3 | https://github.com/volatilityfoundation/volatility3 | 内存取证深度 |

### B. 相关标准

- NIST SP 800-86: 数字取证指南
- ISO/IEC 27037: 数字证据识别、收集与保全
- RFC 3227: 电子证据收集指南
- MITRE ATT&CK: 攻击技术分类框架

### C. 术语表

| 术语 | 说明 |
|------|------|
| IOC | Indicators of Compromise,入侵指标 |
| DFIR | Digital Forensics and Incident Response,数字取证与应急响应 |
| Triage | 分级/初筛,快速评估优先级 |
| Volatile Data | 易失性数据,重启后丢失的数据 |
| YARA | 恶意软件模式匹配规则引擎 |
| Sigma | 日志检测规则标准格式 |
| IFQL | IntrusionScope Forensic Query Language,取证查询语言 |
| Artifact | 取证工件,定义采集范围与逻辑的可插拔模块 |
| MFT | Master File Table,Windows 主文件表 |
| EVTX | Windows 事件日志文件格式 |

---

**文档版本**: v0.3  
**创建日期**: 2026-04-15  
**最后更新**: 2026-04-15  
**状态**: 完善版 - 新增威胁特征库管理、环境适配、完善非功能需求与命令行接口
