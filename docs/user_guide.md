# IntrusionScope 用户指南

**版本**: v0.4  
**更新日期**: 2026-05-21  
**作者**: Mal-Suen

---

## 目录

1. [概述](#1-概述)
2. [安装与部署](#2-安装与部署)
3. [快速入门](#3-快速入门)
4. [命令详解](#4-命令详解)
5. [采集器参考](#5-采集器参考)
6. [检测引擎](#6-检测引擎)
7. [IFQL 查询语言](#7-ifql-查询语言)
8. [配置管理](#8-配置管理)
9. [输出格式](#9-输出格式)
10. [实战场景](#10-实战场景)
11. [故障排除](#11-故障排除)

---

## 1. 概述

### 1.1 什么是 IntrusionScope？

IntrusionScope 是一款跨平台主机取证与威胁检测工具，专为以下场景设计：

- **应急响应**: 快速采集主机取证数据，识别入侵痕迹
- **威胁狩猎**: 主动搜索环境中的可疑活动和高级威胁
- **取证分析**: 收集、保存、分析主机证据
- **安全审计**: 定期检查主机安全状态

### 1.2 核心能力

| 能力 | 说明 |
|------|------|
| 数据采集 | 37 个收集器覆盖进程、网络、文件、日志、注册表 |
| 威胁检测 | IOC/Sigma/YARA 三引擎，100+ 内置检测模式 |
| 数据查询 | IFQL 类 SQL 查询语言 |
| 报告生成 | JSON/CSV/HTML 多格式输出 |
| 规则同步 | 25+ 威胁情报源自动更新 |

### 1.3 技术架构

```
┌─────────────────────────────────────────────────────────┐
│                    CLI (Cobra)                          │
│  collect │ detect │ query │ report │ sync │ rules      │
├─────────────────────────────────────────────────────────┤
│                    业务层 (Go)                          │
│  Collector │ Detector │ IFQL │ Output │ Config         │
├─────────────────────────────────────────────────────────┤
│                 高性能引擎 (Rust/CGO)                    │
│     Aho-Corasick │ IOC Matcher │ Sigma │ YARA          │
├─────────────────────────────────────────────────────────┤
│                    操作系统 API                         │
│         Linux (proc/sys/net) │ Windows (API)           │
└─────────────────────────────────────────────────────────┘
```

---

## 2. 安装与部署

### 2.1 环境要求

| 组件 | 最低版本 | 推荐版本 | 说明 |
|------|----------|----------|------|
| Go | 1.21 | 1.22+ | 主程序运行时 |
| Rust | 1.70 | 1.75+ | 高性能检测引擎 (CGO 模式) |
| GCC | - | - | Linux CGO 编译 |
| MinGW-w64 | - | - | Windows CGO 编译 |

### 2.2 编译安装

#### CGO 模式 (推荐，高性能)

```bash
# Linux
git clone https://github.com/Mal-Suen/IntrusionScope.git
cd IntrusionScope
CGO_ENABLED=1 go build -o intrusionscope ./cmd/intrusionscope

# Windows (需要安装 MinGW-w64)
git clone https://github.com/Mal-Suen/IntrusionScope.git
cd IntrusionScope
set CGO_ENABLED=1
go build -o intrusionscope.exe ./cmd/intrusionscope
```

#### NoCGO 模式 (跨平台编译)

```bash
# 编译 Linux 版本
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o intrusionscope-linux-amd64 ./cmd/intrusionscope

# 编译 Windows 版本
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o intrusionscope-windows-amd64.exe ./cmd/intrusionscope

# 编译 macOS 版本
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o intrusionscope-darwin-amd64 ./cmd/intrusionscope
```

### 2.3 验证安装

```bash
# 检查版本
intrusionscope version

# 输出示例
IntrusionScope v0.4
Build: 2026-05-21
Go Version: go1.22.0
Platform: linux/amd64
Engine: Rust (CGO)
```

### 2.4 权限要求

| 功能 | Linux | Windows |
|------|-------|---------|
| 基本采集 | 普通用户 | 普通用户 |
| 进程内存 | root | Administrator |
| 所有日志 | root (adm组) | Administrator |
| 注册表完整访问 | - | Administrator |
| MFT 读取 | root | Administrator |

---

## 3. 快速入门

### 3.1 第一个采集任务

```bash
# 快速采集 (约 1 分钟)
intrusionscope collect --mode quick --output ./quick_scan

# 查看结果
ls ./quick_scan/
# process_list.json
# network_connections.json
# log_auth.json
# ...
```

### 3.2 第一次威胁检测

```bash
# 对采集结果进行检测
intrusionscope detect -i ./quick_scan -o ./detection_report.json

# 查看检测结果
cat ./detection_report.json | jq '.summary'
# {
#   "total_detections": 5,
#   "high_severity": 2,
#   "medium_severity": 3,
#   "low_severity": 0
# }
```

### 3.3 第一次 IFQL 查询

```bash
# 查询可疑 PowerShell 进程
intrusionscope query -i ./quick_scan "SELECT * FROM process.list WHERE name LIKE '%powershell%'"

# 输出示例
# [
#   {
#     "pid": 1234,
#     "name": "powershell.exe",
#     "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
#     "cmdline": "powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0...",
#     "user": "DOMAIN\\user"
#   }
# ]
```

---

## 4. 命令详解

### 4.1 collect - 数据采集

```bash
intrusionscope collect [flags]
```

#### 标志说明

| 标志 | 简写 | 说明 | 示例 |
|------|------|------|------|
| `--mode` | `-m` | 预设模式 (quick/standard/deep) | `--mode quick` |
| `--all` | `-a` | 采集所有数据源 | `--all` |
| `--artifacts` | | 指定采集项 (逗号分隔) | `--artifacts process.list,network.connections` |
| `--output` | `-o` | 输出目录 | `--output ./output` |
| `--format` | `-f` | 输出格式 (json/csv) | `--format json` |
| `--threads` | `-t` | 并发线程数 | `--threads 4` |
| `--timeout` | | 单项超时 (秒) | `--timeout 60` |
| `--offline` | | 离线模式 | `--offline` |
| `--encrypt` | | 加密输出 | `--encrypt` |
| `--quiet` | `-q` | 静默模式 | `--quiet` |

#### 预设模式

| 模式 | 数据源数 | 预计耗时 | 包含内容 |
|------|----------|----------|----------|
| `quick` | 4 | < 1 分钟 | 进程列表、网络连接、认证日志、自启动项 |
| `standard` | 15 | < 5 分钟 | quick + 文件哈希、DNS缓存、计划任务、服务、用户等 |
| `deep` | 28 | < 15 分钟 | standard + MFT、进程内存、完整注册表、审计日志等 |

#### 示例

```bash
# 快速采集
intrusionscope collect --mode quick --output ./case001

# 标准采集，4 线程并发
intrusionscope collect --mode standard --threads 4 --output ./case001

# 深度采集，离线模式
intrusionscope collect --mode deep --offline --output ./case001

# 仅采集进程和网络
intrusionscope collect --artifacts process.list,process.tree,network.connections --output ./case001

# 采集并加密
intrusionscope collect --mode standard --encrypt --output ./secure_output
```

### 4.2 detect - 威胁检测

```bash
intrusionscope detect [flags]
```

#### 标志说明

| 标志 | 简写 | 说明 | 示例 |
|------|------|------|------|
| `--input` | `-i` | 输入目录 (采集结果) | `--input ./output` |
| `--output` | `-o` | 输出文件 | `--output ./report.json` |
| `--ioc-file` | | 自定义 IOC 文件 | `--ioc-file custom_iocs.json` |
| `--sigma-rules` | | Sigma 规则目录 | `--sigma-rules ./sigma/` |
| `--yara-rules` | | YARA 规则目录 | `--yara-rules ./yara/` |
| `--severity` | | 最低严重级别 (high/medium/low) | `--severity high` |
| `--format` | `-f` | 输出格式 (json/csv/html) | `--format html` |

#### 检测引擎

| 引擎 | 检测内容 | 规则格式 |
|------|----------|----------|
| IOC | 哈希、IP、域名、URL、路径 | JSON |
| Sigma | 行为模式、攻击技术 | YAML |
| YARA | 文件特征、内存模式 | YARA |
| 内置 | 可疑进程、LOLBins、攻击模式 | 内置 |

#### 示例

```bash
# 基本检测
intrusionscope detect -i ./output -o ./detection.json

# 使用自定义 IOC
intrusionscope detect -i ./output --ioc-file ./my_iocs.json -o ./detection.json

# 使用自定义规则
intrusionscope detect -i ./output \
  --sigma-rules ./custom_sigma/ \
  --yara-rules ./custom_yara/ \
  -o ./detection.json

# 仅输出高危告警
intrusionscope detect -i ./output --severity high -o ./high_alerts.json

# 生成 HTML 报告
intrusionscope detect -i ./output --format html -o ./report.html
```

### 4.3 query - IFQL 查询

```bash
intrusionscope query [flags] "<IFQL语句>"
```

#### 标志说明

| 标志 | 简写 | 说明 | 示例 |
|------|------|------|------|
| `--input` | `-i` | 输入目录 | `--input ./output` |
| `--format` | `-f` | 输出格式 (json/csv/table) | `--format table` |
| `--limit` | | 结果限制 | `--limit 100` |

#### 示例

```bash
# 查询所有进程
intrusionscope query -i ./output "SELECT * FROM process.list"

# 查询可疑进程
intrusionscope query -i ./output "SELECT * FROM process.list WHERE name LIKE '%powershell%' OR name LIKE '%cmd%'"

# 查询外连
intrusionscope query -i ./output "SELECT * FROM network.connections WHERE state = 'ESTABLISHED' AND remote_ip NOT IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')"

# 查询失败登录
intrusionscope query -i ./output "SELECT * FROM log.auth WHERE type = 'failed_login' ORDER BY timestamp DESC LIMIT 50"

# 表格输出
intrusionscope query -i ./output --format table "SELECT name, pid, user FROM process.list LIMIT 10"
```

### 4.4 report - 报告生成

```bash
intrusionscope report [flags]
```

#### 标志说明

| 标志 | 简写 | 说明 | 示例 |
|------|------|------|------|
| `--input` | `-i` | 输入目录 | `--input ./output` |
| `--output` | `-o` | 输出文件 | `--output ./report.html` |
| `--format` | `-f` | 输出格式 (html/json/markdown) | `--format html` |
| `--title` | | 报告标题 | `--title "应急响应报告"` |
| `--language` | | 语言 (zh/en) | `--language zh` |

#### 示例

```bash
# 生成 HTML 报告
intrusionscope report -i ./output -o ./report.html --format html

# 生成中文报告
intrusionscope report -i ./output -o ./report.html --language zh --title "主机取证报告"

# 生成 Markdown 报告
intrusionscope report -i ./output -o ./report.md --format markdown
```

### 4.5 timeline - 时间线生成

```bash
intrusionscope timeline [flags]
```

#### 标志说明

| 标志 | 简写 | 说明 | 示例 |
|------|------|------|------|
| `--input` | `-i` | 输入目录 | `--input ./output` |
| `--output` | `-o` | 输出文件 | `--output ./timeline.csv` |
| `--start` | | 开始时间 | `--start "2024-01-01 00:00:00"` |
| `--end` | | 结束时间 | `--end "2024-01-02 00:00:00"` |
| `--format` | `-f` | 输出格式 (csv/json) | `--format csv` |

#### 示例

```bash
# 生成完整时间线
intrusionscope timeline -i ./output -o ./timeline.csv

# 生成指定时间范围
intrusionscope timeline -i ./output --start "2024-01-15 08:00:00" --end "2024-01-15 18:00:00" -o ./timeline.csv
```

### 4.6 sync - 规则同步

```bash
intrusionscope sync [flags]
```

#### 标志说明

| 标志 | 简写 | 说明 | 示例 |
|------|------|------|------|
| `--source` | | 指定同步源 | `--source sigma,yara,ioc` |
| `--force` | | 强制更新 | `--force` |
| `--proxy` | | 代理地址 | `--proxy http://127.0.0.1:8080` |

#### 同步源

| 类型 | 来源 | 说明 |
|------|------|------|
| IOC | MalwareBazaar, URLhaus, ThreatFox, Feodo Tracker | 恶意软件哈希、URL、IP |
| Sigma | SigmaHQ | 检测规则 |
| YARA | YARAHQ, BartBlaze, Stratosphere | 文件特征规则 |

#### 示例

```bash
# 同步所有规则
intrusionscope sync

# 仅同步 Sigma 规则
intrusionscope sync --source sigma

# 使用代理同步
intrusionscope sync --proxy http://127.0.0.1:8080

# 强制更新
intrusionscope sync --force
```

### 4.7 rules - 规则管理

```bash
intrusionscope rules <subcommand> [flags]
```

#### 子命令

| 子命令 | 说明 |
|--------|------|
| `status` | 查看规则库状态 |
| `list` | 列出规则 |
| `import` | 导入规则 |
| `export` | 导出规则 |
| `validate` | 验证规则 |

#### 示例

```bash
# 查看状态
intrusionscope rules status

# 列出 Sigma 规则
intrusionscope rules list --type sigma

# 导入 IOC
intrusionscope rules import --file ./custom_iocs.json

# 导入 YARA 规则
intrusionscope rules import --yara ./custom_yara/

# 验证规则
intrusionscope rules validate --file ./suspicious.yml
```

### 4.8 version - 版本信息

```bash
intrusionscope version
```

---

## 5. 采集器参考

### 5.1 进程采集器

#### process.list - 进程列表

采集所有运行进程的详细信息。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| pid | int | 进程 ID |
| ppid | int | 父进程 ID |
| name | string | 进程名 |
| exe | string | 可执行文件路径 |
| cmdline | string | 命令行参数 |
| user | string | 运行用户 |
| start_time | timestamp | 启动时间 |
| memory_mb | float | 内存使用 (MB) |
| cpu_percent | float | CPU 使用率 |
| threads | int | 线程数 |
| handles | int | 句柄数 (Windows) |

**平台**: Linux, Windows

#### process.tree - 进程树

以树形结构展示进程父子关系。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| pid | int | 进程 ID |
| ppid | int | 父进程 ID |
| name | string | 进程名 |
| depth | int | 树深度 |
| children | []int | 子进程 PID 列表 |

**平台**: Linux, Windows

#### process.open_files - 打开文件

采集进程打开的文件和网络连接。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| pid | int | 进程 ID |
| fd | int | 文件描述符 |
| type | string | 类型 (file/pipe/socket) |
| path | string | 文件路径 |
| mode | string | 访问模式 |

**平台**: Linux, Windows

#### process.memory - 进程内存

采集进程内存映射信息。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| pid | int | 进程 ID |
| region | string | 内存区域 |
| start | hex | 起始地址 |
| end | hex | 结束地址 |
| perms | string | 权限 (rwx) |
| size_kb | int | 大小 (KB) |

**平台**: Linux, Windows (需要管理员权限)

#### process.modules - 进程模块

采集进程加载的模块/DLL。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| pid | int | 进程 ID |
| name | string | 模块名 |
| path | string | 模块路径 |
| base_addr | hex | 基址 |
| size | int | 大小 |

**平台**: Linux, Windows

### 5.2 网络采集器

#### network.connections - 网络连接

采集所有 TCP/UDP 连接。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| protocol | string | 协议 (TCP/UDP) |
| local_ip | string | 本地 IP |
| local_port | int | 本地端口 |
| remote_ip | string | 远程 IP |
| remote_port | int | 远程端口 |
| state | string | 连接状态 |
| pid | int | 关联进程 ID |
| process_name | string | 进程名 |

**平台**: Linux, Windows

#### network.listening_ports - 监听端口

采集所有监听端口。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| protocol | string | 协议 |
| port | int | 端口号 |
| address | string | 绑定地址 |
| pid | int | 进程 ID |
| process_name | string | 进程名 |

**平台**: Linux, Windows

#### network.dns_cache - DNS 缓存

采集 DNS 缓存条目。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| domain | string | 域名 |
| ip | string | 解析 IP |
| ttl | int | TTL |
| type | string | 记录类型 |

**平台**: Linux, Windows

#### network.arp_cache - ARP 缓存

采集 ARP 缓存条目。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| ip | string | IP 地址 |
| mac | string | MAC 地址 |
| interface | string | 网络接口 |
| type | string | 类型 (dynamic/static) |

**平台**: Linux, Windows

#### network.hosts - Hosts 文件

解析 hosts 文件内容。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| ip | string | IP 地址 |
| hostname | string | 主机名 |
| line | int | 行号 |

**平台**: Linux, Windows

### 5.3 文件系统采集器

#### filesystem.recent_files - 最近文件

采集最近修改/访问的文件。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| path | string | 文件路径 |
| size | int | 文件大小 |
| mtime | timestamp | 修改时间 |
| atime | timestamp | 访问时间 |
| ctime | timestamp | 创建时间 |
| mode | string | 文件权限 |

**平台**: Linux, Windows

#### filesystem.file_hash - 文件哈希

计算指定文件的哈希值。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| path | string | 文件路径 |
| md5 | string | MD5 哈希 |
| sha1 | string | SHA1 哈希 |
| sha256 | string | SHA256 哈希 |
| size | int | 文件大小 |

**平台**: Linux, Windows

#### filesystem.mft - MFT 记录

解析 NTFS MFT (需要管理员权限)。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| record_num | int | MFT 记录号 |
| filename | string | 文件名 |
| parent_ref | int | 父目录引用 |
| size | int | 文件大小 |
| created | timestamp | 创建时间 |
| modified | timestamp | 修改时间 |
| accessed | timestamp | 访问时间 |
| flags | string | 文件标志 |

**平台**: Windows

#### filesystem.bash_history - Bash 历史

解析 Bash 历史文件。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| line | int | 行号 |
| command | string | 命令 |
| timestamp | timestamp | 执行时间 |

**平台**: Linux

#### filesystem.cron_jobs - Cron 任务

列出所有 Cron 任务。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| schedule | string | 调度表达式 |
| command | string | 命令 |
| user | string | 用户 |

**平台**: Linux

#### filesystem.systemd_services - Systemd 服务

列出 Systemd 服务状态。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| name | string | 服务名 |
| status | string | 状态 |
| enabled | bool | 是否开机启动 |
| description | string | 描述 |

**平台**: Linux

#### filesystem.scheduled_tasks - 计划任务

列出 Windows 计划任务。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| name | string | 任务名 |
| path | string | 任务路径 |
| status | string | 状态 |
| last_run | timestamp | 上次运行 |
| next_run | timestamp | 下次运行 |
| command | string | 执行命令 |

**平台**: Windows

#### filesystem.autoruns - 自启动项

列出所有自启动项。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| location | string | 位置 |
| name | string | 名称 |
| path | string | 可执行文件路径 |
| args | string | 参数 |
| user | string | 用户 |

**平台**: Linux, Windows

#### filesystem.suid_files - SUID 文件

查找 SUID/SGID 文件。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| path | string | 文件路径 |
| mode | string | 权限 |
| owner | string | 所有者 |
| group | string | 组 |

**平台**: Linux

### 5.4 日志采集器

#### log.auth - 认证日志

解析认证日志 (auth.log/secure/Windows Security)。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| timestamp | timestamp | 时间戳 |
| type | string | 事件类型 (login/failed_login/logout/sudo) |
| user | string | 用户 |
| source_ip | string | 来源 IP |
| method | string | 认证方式 |
| service | string | 服务 |
| success | bool | 是否成功 |

**平台**: Linux, Windows

#### log.syslog - 系统日志

解析 Syslog。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| timestamp | timestamp | 时间戳 |
| facility | string | 设施 |
| severity | string | 严重级别 |
| host | string | 主机 |
| program | string | 程序 |
| message | string | 消息 |

**平台**: Linux

#### log.wtmp - 登录记录

解析 wtmp/btmp 登录记录。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| timestamp | timestamp | 时间戳 |
| type | string | 类型 (login/logout/boot) |
| user | string | 用户 |
| tty | string | 终端 |
| host | string | 来源主机 |
| ip | string | 来源 IP |

**平台**: Linux

#### log.audit - 审计日志

解析 Auditd 日志。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| timestamp | timestamp | 时间戳 |
| type | string | 事件类型 |
| pid | int | 进程 ID |
| uid | int | 用户 ID |
| exe | string | 可执行文件 |
| success | bool | 是否成功 |
| message | string | 消息 |

**平台**: Linux

#### log.journal - Journal 日志

解析 Systemd Journal。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| timestamp | timestamp | 时间戳 |
| unit | string | 单元 |
| priority | int | 优先级 |
| message | string | 消息 |
| pid | int | 进程 ID |

**平台**: Linux

#### log.windows_events - Windows 事件日志

解析 Windows 事件日志。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| timestamp | timestamp | 时间戳 |
| event_id | int | 事件 ID |
| channel | string | 日志通道 |
| provider | string | 提供者 |
| level | string | 级别 |
| computer | string | 计算机 |
| user | string | 用户 |
| message | string | 消息 |

**平台**: Windows

#### log.web_server - Web 服务器日志

解析 Apache/Nginx/IIS 日志。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| timestamp | timestamp | 时间戳 |
| client_ip | string | 客户端 IP |
| method | string | HTTP 方法 |
| path | string | 请求路径 |
| status | int | 状态码 |
| size | int | 响应大小 |
| referer | string | 来源 |
| user_agent | string | User-Agent |

**平台**: Linux, Windows

### 5.5 注册表采集器 (Windows)

#### registry.run_keys - Run 键

采集 Run/RunOnce 注册表键。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| key | string | 注册表键路径 |
| name | string | 值名称 |
| value | string | 值数据 |
| hive | string | 注册表配置单元 |

**平台**: Windows

#### registry.services - 服务注册表

采集服务注册表项。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| name | string | 服务名 |
| display_name | string | 显示名称 |
| image_path | string | 可执行文件路径 |
| start_type | string | 启动类型 |
| status | string | 状态 |

**平台**: Windows

#### registry.persistence - 持久化注册表

采集常见持久化位置。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| location | string | 位置 |
| name | string | 名称 |
| value | string | 值 |
| risk | string | 风险级别 |

**平台**: Windows

#### registry.usb_history - USB 历史

采集 USB 设备历史。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| device_id | string | 设备 ID |
| vendor | string | 厂商 |
| product | string | 产品 |
| serial | string | 序列号 |
| first_insert | timestamp | 首次插入 |
| last_insert | timestamp | 最后插入 |

**平台**: Windows

#### registry.user_assist - UserAssist

解析 UserAssist 执行历史。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| path | string | 程序路径 |
| run_count | int | 运行次数 |
| focus_time | int | 焦点时间 (秒) |
| last_run | timestamp | 最后运行 |

**平台**: Windows

#### registry.software - 软件信息

采集已安装软件列表。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| name | string | 软件名 |
| version | string | 版本 |
| publisher | string | 发布者 |
| install_date | date | 安装日期 |
| location | string | 安装位置 |

**平台**: Windows

#### registry.startup - 启动项

采集注册表启动项。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| name | string | 名称 |
| command | string | 命令 |
| location | string | 位置 |
| user | string | 用户 |

**平台**: Windows

### 5.6 用户采集器

#### users.list - 用户列表

列出系统用户。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| username | string | 用户名 |
| uid | int | 用户 ID |
| gid | int | 组 ID |
| home | string | 家目录 |
| shell | string | Shell |
| last_login | timestamp | 最后登录 |

**平台**: Linux, Windows

#### users.login_history - 登录历史

采集用户登录历史。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| user | string | 用户 |
| terminal | string | 终端 |
| host | string | 来源主机 |
| login_time | timestamp | 登录时间 |
| logout_time | timestamp | 登出时间 |

**平台**: Linux, Windows

#### users.groups - 用户组

列出用户组信息。

**输出字段**:

| 字段 | 类型 | 说明 |
|------|------|------|
| name | string | 组名 |
| gid | int | 组 ID |
| members | []string | 成员列表 |

**平台**: Linux, Windows

---

## 6. 检测引擎

### 6.1 IOC 检测

#### 支持的 IOC 类型

| 类型 | 格式 | 示例 |
|------|------|------|
| 文件哈希 | MD5/SHA1/SHA256 | `5f4dcc3b5aa765d61d8327deb882cf99` |
| IP 地址 | IPv4/IPv4 CIDR | `192.168.1.100`, `10.0.0.0/8` |
| 域名 | FQDN | `malware.evil.com` |
| URL | HTTP/HTTPS | `http://evil.com/payload.exe` |
| 文件路径 | 路径模式 | `C:\Windows\Temp\evil.exe` |
| 进程名 | 可执行文件名 | `mimikatz.exe` |

#### IOC 文件格式

```json
{
  "iocs": [
    {
      "type": "hash",
      "value": "5f4dcc3b5aa765d61d8327deb882cf99",
      "description": "Malware sample",
      "severity": "high",
      "source": "MalwareBazaar",
      "first_seen": "2024-01-15"
    },
    {
      "type": "ip",
      "value": "192.168.1.100",
      "description": "C2 server",
      "severity": "high",
      "source": "ThreatFox"
    },
    {
      "type": "domain",
      "value": "evil.malware.com",
      "description": "Malicious domain",
      "severity": "medium"
    }
  ]
}
```

### 6.2 Sigma 检测

#### Sigma 规则结构

```yaml
title: Suspicious PowerShell Execution
id: 12345678-1234-1234-1234-123456789012
status: stable
description: Detects suspicious PowerShell command patterns
author: Mal-Suen
date: 2024/01/15
tags:
  - attack.execution
  - attack.t1059.001
level: high

logsource:
  category: process_creation
  product: windows

detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-encodedcommand'
      - 'downloadstring'
      - 'invoke-webrequest'
      - 'iex'
  condition: selection

falsepositives:
  - Legitimate administrative scripts

output:
  message: Suspicious PowerShell execution detected
  severity: high
  mitre:
    - T1059.001
```

#### 支持的修饰符

| 修饰符 | 说明 | 示例 |
|--------|------|------|
| `contains` | 包含匹配 | `name\|contains: 'powershell'` |
| `startswith` | 前缀匹配 | `path\|startswith: 'C:\Windows'` |
| `endswith` | 后缀匹配 | `Image\|endswith: '.exe'` |
| `re` | 正则表达式 | `cmdline\|re: '.*base64.*'` |
| `base64` | Base64 编码匹配 | `data\|base64: 'command'` |
| `base64offset` | Base64 偏移匹配 | `data\|base64offset: 'http'` |

#### 条件语法

| 条件 | 说明 | 示例 |
|------|------|------|
| `selection` | 单选 | `condition: selection` |
| `AND` | 与逻辑 | `condition: selection1 AND selection2` |
| `OR` | 或逻辑 | `condition: selection1 OR selection2` |
| `NOT` | 非逻辑 | `condition: selection AND NOT filter` |
| `N of them` | N 个匹配 | `condition: 2 of selection*` |
| `count()` | 计数聚合 | `condition: count(EventID) > 5` |

### 6.3 YARA 检测

#### YARA 规则结构

```yara
rule SuspiciousPowerShell {
    meta:
        author = "Mal-Suen"
        description = "Detects suspicious PowerShell patterns"
        severity = "high"
        date = "2024-01-15"
        
    strings:
        $encoded = "-enc" nocase
        $encoded2 = "-encodedcommand" nocase
        $download = "downloadstring" nocase
        $iex = "iex" nocase
        $bypass = "bypass" nocase
        $hidden = "-windowstyle hidden" nocase
        
        // Hex pattern with wildcards
        $hex_pattern = { 4D 5A [0-100] 50 45 00 00 }
        
        // Regex pattern
        $regex_pattern = /base64\s+-[a-z]+\s+[A-Za-z0-9+\/=]+/
        
    condition:
        3 of them
}
```

#### 字符串类型

| 类型 | 语法 | 说明 |
|------|------|------|
| 文本 | `$s = "text"` | 精确文本匹配 |
| 文本 (不区分大小写) | `$s = "text" nocase` | 不区分大小写 |
| Hex | `$h = { 4D 5A }` | 十六进制模式 |
| Hex 通配符 | `$h = { 4D ?? 5A }` | `??` 匹配任意字节 |
| Hex 范围 | `$h = { 4D [10-20] 5A }` | 匹配 10-20 个任意字节 |
| 正则 | `$r = /pattern/` | 正则表达式 |

#### 条件语法

| 条件 | 说明 | 示例 |
|------|------|------|
| `any of them` | 任意一个匹配 | `condition: any of them` |
| `all of them` | 全部匹配 | `condition: all of them` |
| `N of them` | N 个匹配 | `condition: 3 of them` |
| `N of ($s*)` | N 个指定组 | `condition: 2 of ($suspicious*)` |
| `AND` | 与逻辑 | `condition: $a and $b` |
| `OR` | 或逻辑 | `condition: $a or $b` |

### 6.4 内置检测模式

内置 100+ 可疑行为检测模式：

#### PowerShell 攻击模式

- 编码命令执行 (`-enc`, `-encodedcommand`)
- 下载执行 (`DownloadString`, `Invoke-WebRequest`)
- 执行策略绕过 (`-executionpolicy bypass`)
- 隐藏窗口执行 (`-windowstyle hidden`)
- AMSI 绕过 (`amsiInitFailed`, `AmsiScanBuffer`)

#### 凭据窃取

- Mimikatz 相关 (`mimikatz`, `sekurlsa`, `lsadump`)
- SAM 数据库访问 (`sam`, `system`, `security` hive)
- LSASS 内存转储 (`procdump`, `comsvcs.dll`)

#### LOLBins 滥用

- `certutil.exe` 下载
- `bitsadmin.exe` 传输
- `mshta.exe` 执行
- `regsvr32.exe` 远程执行
- `rundll32.exe` 加载
- `wmic.exe` 远程执行

#### 持久化机制

- 注册表 Run 键修改
- 计划任务创建
- 服务创建/修改
- WMI 事件订阅

#### 横向移动

- PsExec 执行
- WMI 远程执行
- SMB 连接
- 远程服务操作

---

## 7. IFQL 查询语言

详见 [IFQL 参考手册](ifql_reference.md)。

### 7.1 基本语法

```sql
SELECT <columns> FROM <source> [WHERE <conditions>] [ORDER BY <column>] [LIMIT <n>]
```

### 7.2 数据源

| 数据源 | 说明 |
|--------|------|
| `process.list` | 进程列表 |
| `process.tree` | 进程树 |
| `network.connections` | 网络连接 |
| `network.listening_ports` | 监听端口 |
| `log.auth` | 认证日志 |
| `log.syslog` | 系统日志 |
| `filesystem.recent_files` | 最近文件 |
| `registry.run_keys` | Run 键 (Windows) |

### 7.3 运算符

| 运算符 | 说明 | 示例 |
|--------|------|------|
| `=` | 等于 | `name = 'powershell.exe'` |
| `!=` | 不等于 | `state != 'ESTABLISHED'` |
| `<` | 小于 | `pid < 1000` |
| `>` | 大于 | `memory_mb > 100` |
| `<=` | 小于等于 | `port <= 1024` |
| `>=` | 大于等于 | `severity >= 3` |
| `LIKE` | SQL 通配符 | `name LIKE '%cmd%'` |
| `IN` | 列表包含 | `port IN (80, 443, 8080)` |
| `BETWEEN` | 范围 | `pid BETWEEN 100 AND 500` |
| `IS NULL` | 空值 | `exe IS NULL` |

### 7.4 示例

```sql
-- 查询可疑进程
SELECT * FROM process.list 
WHERE name LIKE '%powershell%' 
  AND cmdline LIKE '%enc%'

-- 查询外连
SELECT * FROM network.connections 
WHERE state = 'ESTABLISHED' 
  AND remote_ip NOT IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')

-- 查询失败登录
SELECT user, source_ip, COUNT(*) as attempts 
FROM log.auth 
WHERE type = 'failed_login' 
GROUP BY user, source_ip 
HAVING attempts > 5
ORDER BY attempts DESC
```

---

## 8. 配置管理

### 8.1 配置文件

**位置**:
- Linux: `~/.intrusionscope.conf` 或 `/etc/intrusionscope/intrusionscope.conf`
- Windows: `%APPDATA%\intrusionscope\intrusionscope.conf`

**格式**: INI 或 YAML

### 8.2 配置项

```ini
[general]
# 运行模式
mode = standard
# 输出目录
output_dir = ./output
# 日志级别 (debug/info/warn/error)
log_level = info
# 语言 (zh/en)
language = zh

[collection]
# 并发线程数
threads = 4
# 单项超时 (秒)
timeout = 300
# 最大输出大小 (MB)
max_output_size = 100
# 采集后压缩
compress = true

[detection]
# 规则目录
rules_dir = ./rules
# 自动同步
auto_sync = true
# 同步间隔 (小时)
sync_interval = 24
# 最低严重级别
min_severity = low

[network]
# 代理
proxy = 
# 离线模式
offline = false
# 网络超时 (秒)
timeout = 30

[output]
# 默认格式
format = json
# 包含原始数据
include_raw = false
# 时间格式
time_format = rfc3339

[security]
# 加密输出
encrypt = false
# 加密密钥 (留空自动生成)
encryption_key = 
# 执行后清理
cleanup = false
```

### 8.3 环境变量

所有配置项可通过环境变量覆盖，前缀为 `IS_`：

```bash
# 通用配置
export IS_MODE=deep
export IS_OUTPUT_DIR=/tmp/forensics
export IS_LOG_LEVEL=debug

# 采集配置
export IS_THREADS=8
export IS_TIMEOUT=600

# 检测配置
export IS_RULES_DIR=/opt/intrusionscope/rules
export IS_AUTO_SYNC=false

# 网络配置
export IS_OFFLINE=true
export IS_PROXY=http://127.0.0.1:8080
```

### 8.4 命令行优先级

配置优先级: **命令行参数 > 环境变量 > 配置文件 > 默认值**

---

## 9. 输出格式

### 9.1 JSON 格式

```json
{
  "metadata": {
    "tool": "IntrusionScope",
    "version": "0.4",
    "hostname": "workstation-01",
    "os": "Windows 10 Pro",
    "collection_time": "2024-01-15T10:30:00Z",
    "mode": "standard"
  },
  "artifacts": {
    "process.list": [
      {
        "pid": 1234,
        "name": "powershell.exe",
        "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline": "powershell -enc ...",
        "user": "DOMAIN\\user"
      }
    ]
  }
}
```

### 9.2 CSV 格式

```csv
pid,name,exe,cmdline,user
1234,powershell.exe,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,"powershell -enc ...",DOMAIN\user
5678,cmd.exe,C:\Windows\System32\cmd.exe,cmd /c whoami,DOMAIN\user
```

### 9.3 HTML 报告

生成包含以下内容的 HTML 报告：
- 执行摘要
- 系统信息
- 采集统计
- 检测结果
- 时间线
- 详细数据表格

### 9.4 检测报告格式

```json
{
  "summary": {
    "total_detections": 5,
    "high_severity": 2,
    "medium_severity": 3,
    "low_severity": 0,
    "scan_time": "2024-01-15T10:35:00Z",
    "duration_seconds": 12.5
  },
  "detections": [
    {
      "id": "DET-001",
      "rule": "suspicious_powershell",
      "engine": "sigma",
      "severity": "high",
      "title": "Suspicious PowerShell Execution",
      "description": "Detected encoded PowerShell command execution",
      "timestamp": "2024-01-15T10:30:15Z",
      "source": {
        "artifact": "process.list",
        "record": {
          "pid": 1234,
          "name": "powershell.exe",
          "cmdline": "powershell -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0..."
        }
      },
      "mitre": ["T1059.001"],
      "references": [
        "https://attack.mitre.org/techniques/T1059/001/"
      ]
    }
  ]
}
```

---

## 10. 实战场景

### 10.1 应急响应 - 可疑主机调查

```bash
# 1. 快速采集
intrusionscope collect --mode quick --output ./incident_001

# 2. 初步检测
intrusionscope detect -i ./incident_001 -o ./detection_quick.json

# 3. 发现可疑进程，深入调查
intrusionscope query -i ./incident_001 "SELECT * FROM process.list WHERE pid = 1234"

# 4. 查看网络连接
intrusionscope query -i ./incident_001 "SELECT * FROM network.connections WHERE pid = 1234"

# 5. 深度采集
intrusionscope collect --mode deep --output ./incident_001_deep

# 6. 生成报告
intrusionscope report -i ./incident_001_deep -o ./report.html --language zh
```

### 10.2 威胁狩猎 - 横向移动检测

```bash
# 1. 批量采集
for host in $(cat targets.txt); do
  ssh $host "intrusionscope collect --mode standard --output -" > ./hunt/${host}.tar.gz &
done
wait

# 2. 批量检测
for f in ./hunt/*.tar.gz; do
  tar xzf $f -C ./hunt/extracted/
  intrusionscope detect -i ./hunt/extracted/ -o ./hunt/results/$(basename $f .tar.gz).json
done

# 3. 汇总分析
intrusionscope query -i ./hunt/extracted/ "SELECT * FROM network.connections WHERE remote_port IN (445, 3389, 5985, 5986)"
```

### 10.3 离线取证 - 镜像分析

```bash
# 1. 挂载取证镜像
mount -o ro,loop evidence.dd /mnt/evidence

# 2. 离线分析
intrusionscope collect --offline --mode deep --root /mnt/evidence --output ./offline_analysis

# 3. 时间线分析
intrusionscope timeline -i ./offline_analysis -o ./timeline.csv

# 4. 检测分析
intrusionscope detect -i ./offline_analysis -o ./detection.json
```

### 10.4 持续监控 - 定期采集

```bash
# Cron 任务
0 */4 * * * /usr/local/bin/intrusionscope collect --mode quick --output /var/log/intrusionscope/$(date +\%Y\%m\%d_\%H\%M\%S)

# 每日检测
0 2 * * * /usr/local/bin/intrusionscope detect -i /var/log/intrusionscope/$(date -d yesterday +\%Y\%m\%d) --severity high -o /var/log/intrusionscope/alerts/$(date -d yesterday +\%Y\%m\%d).json
```

---

## 11. 故障排除

### 11.1 常见问题

#### 权限不足

**问题**: 部分采集器无法获取数据

**解决**:
```bash
# Linux
sudo intrusionscope collect --mode standard

# Windows (以管理员身份运行)
# 右键 -> 以管理员身份运行
```

#### CGO 编译失败

**问题**: `CGO_ENABLED=1` 编译失败

**解决**:
```bash
# Linux - 安装 GCC
apt-get install build-essential

# Windows - 安装 MinGW-w64
# 下载并安装 MinGW-w64，添加到 PATH

# 或使用 NoCGO 模式
CGO_ENABLED=0 go build -o intrusionscope ./cmd/intrusionscope
```

#### 内存不足

**问题**: 大规模采集时内存溢出

**解决**:
```bash
# 减少并发
intrusionscope collect --mode deep --threads 1

# 分批采集
intrusionscope collect --artifacts process.list --output ./batch1
intrusionscope collect --artifacts network.connections --output ./batch2
```

#### 规则同步失败

**问题**: 无法同步规则库

**解决**:
```bash
# 检查网络
curl -I https://github.com/SigmaHQ/sigma

# 使用代理
intrusionscope sync --proxy http://127.0.0.1:8080

# 离线模式 - 手动导入
git clone https://github.com/SigmaHQ/sigma.git
intrusionscope rules import --sigma ./sigma/rules/
```

### 11.2 日志分析

```bash
# 启用调试日志
intrusionscope collect --mode standard --log-level debug

# 查看日志
cat ~/.intrusionscope/logs/intrusionscope.log
```

### 11.3 性能调优

| 参数 | 说明 | 推荐值 |
|------|------|--------|
| `--threads` | 并发线程数 | CPU 核心数 |
| `--timeout` | 单项超时 | 60-300 秒 |
| `--max-output-size` | 最大输出 | 100-500 MB |

---

## 附录

### A. 命令速查表

| 命令 | 说明 |
|------|------|
| `intrusionscope collect --mode quick` | 快速采集 |
| `intrusionscope collect --mode standard` | 标准采集 |
| `intrusionscope collect --mode deep` | 深度采集 |
| `intrusionscope detect -i <dir>` | 威胁检测 |
| `intrusionscope query "<sql>"` | IFQL 查询 |
| `intrusionscope report -i <dir>` | 生成报告 |
| `intrusionscope timeline -i <dir>` | 生成时间线 |
| `intrusionscope sync` | 同步规则 |
| `intrusionscope rules status` | 规则状态 |
| `intrusionscope version` | 版本信息 |

### B. 数据源速查表

| 数据源 | 平台 | 权限 |
|--------|------|------|
| `process.list` | Linux/Windows | 普通用户 |
| `process.memory` | Linux/Windows | 管理员 |
| `network.connections` | Linux/Windows | 普通用户 |
| `filesystem.mft` | Windows | 管理员 |
| `log.auth` | Linux | root/adm |
| `log.windows_events` | Windows | 管理员 |
| `registry.*` | Windows | 普通用户/管理员 |

### C. 参考资料

- [IFQL 参考手册](ifql_reference.md)
- [Artifact Schema](artifact_schema.md)
- [Sigma 规则规范](https://github.com/SigmaHQ/sigma-specification)
- [YARA 文档](https://yara.readthedocs.io/)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

*Copyright © 2024-2026 Mal-Suen. Released under MIT License.*
