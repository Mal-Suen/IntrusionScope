# IntrusionScope

<div align="center">

**Cross-Platform Rapid Host Forensics & Threat Hunting Tool**

**跨平台快速主机取证与威胁狩猎工具**

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://golang.org/)
[![Rust Version](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/Mal-Suen/IntrusionScope)

</div>

---

## Table of Contents / 目录

- [English](#english)
- [中文](#中文)

---

<a name="english"></a>
## English

### Overview

**IntrusionScope** is a host forensics and threat detection tool designed for incident responders and threat hunters. It integrates best practices from top DFIR tools like Velociraptor, GRR, Hayabusa, and Loki, providing:

- **Comprehensive Collection** - 37 collectors covering processes, network, filesystem, logs, and registry
- **High-Performance Detection** - Rust engine with Aho-Corasick algorithm, 100+ built-in suspicious behavior patterns
- **Flexible Querying** - IFQL SQL-like query language for precise on-demand analysis
- **Cross-Platform** - Unified interface supporting Linux and Windows
- **Multiple Output Formats** - JSON, CSV, HTML reports with Chinese localization support

### Core Features

#### Collection Capabilities

| Category | Collectors | Description |
|----------|------------|-------------|
| **Process** | 5 | Process list, process tree, open files, memory maps, loaded modules |
| **Network** | 5 | Network connections, listening ports, DNS cache, ARP cache, hosts file |
| **Filesystem** | 10 | Recent files, file hashes, MFT, Bash history, Cron jobs, Systemd services, Scheduled tasks, Autostart entries, Downloads, SUID files |
| **Logs** | 7 | Auth logs, system logs, wtmp/btmp, audit logs, Journal, Windows events, Web server logs |
| **Registry** | 7 | Run keys, services, persistence, USB history, UserAssist, software info, startup items (Windows) |
| **User** | 3 | User list, login history, user groups |

**Total**: 37 collectors

#### Detection Engines

| Engine | Capabilities |
|--------|--------------|
| **IOC Matching** | Hashes (MD5/SHA1/SHA256), IP, domain, URL, file path |
| **Sigma Rules** | Full condition parsing, modifier support (contains/re/base64, etc.) |
| **YARA Rules** | text/hex/regex strings, condition evaluation |
| **Built-in Patterns** | 100+ suspicious behavior detection (PowerShell attacks, Mimikatz, LOLBins, etc.) |

#### Preset Collection Modes

| Mode | Data Sources | Duration | Use Case |
|------|--------------|----------|----------|
| `quick` | 4 core | < 1 min | Rapid response, initial assessment |
| `standard` | 15 | < 5 min | Regular investigation, comprehensive assessment |
| `deep` | 28 | < 15 min | Deep forensics, complete analysis |

> Note: The number of data sources in preset modes is approximate and may vary by platform.

### Installation

#### Build from Source

```bash
# Clone repository
git clone https://github.com/Mal-Suen/IntrusionScope.git
cd IntrusionScope

# Build (CGO mode, requires Rust toolchain)
CGO_ENABLED=1 go build -o intrusionscope ./cmd/intrusionscope

# Build (NoCGO mode, pure Go, cross-platform compilation)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o intrusionscope ./cmd/intrusionscope
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o intrusionscope.exe ./cmd/intrusionscope
```

#### Requirements

| Component | Version | Description |
|-----------|---------|-------------|
| Go | 1.21+ | Main program |
| Rust | 1.70+ | High-performance detection engine (CGO mode) |
| GCC/MinGW | - | CGO compilation (Windows) |

### Quick Start

#### Basic Usage

```bash
# Show help
intrusionscope --help

# Quick collection
intrusionscope collect --mode quick --output ./output

# Standard collection
intrusionscope collect --mode standard --output ./output

# Collect all data
intrusionscope collect --all --output ./output

# Collect specific artifacts
intrusionscope collect --artifacts process.list,network.connections --output ./output
```

#### Threat Detection

```bash
# Detect on collected results
intrusionscope detect -i ./output -o ./detection_results.json

# Use custom IOCs
intrusionscope detect -i ./output --ioc-file custom_iocs.json

# Use custom Sigma rules
intrusionscope detect -i ./output --sigma-rules ./custom_sigma/
```

#### IFQL Queries

```bash
# Query suspicious processes
intrusionscope query "SELECT * FROM process.list WHERE name LIKE '%powershell%'"

# Query established network connections
intrusionscope query "SELECT * FROM network.connections WHERE state = 'ESTABLISHED'"

# Query failed logins
intrusionscope query "SELECT * FROM log.auth WHERE type = 'failed_login' LIMIT 100"
```

#### Rule Management

```bash
# Sync rule database
intrusionscope sync

# View rule status
intrusionscope rules status

# Import custom IOCs
intrusionscope rules import --file custom_iocs.json

# Import custom YARA rules
intrusionscope rules import --yara ./custom_yara/
```

### Project Structure

```
IntrusionScope/
├── cmd/intrusionscope/       # CLI entry point
│   ├── main.go               # Main entry
│   └── cli/                  # Subcommands (collect/detect/query/report/sync/rules)
├── pkg/
│   ├── collector/            # Collectors (37 total)
│   ├── detector/             # Detection engines (IOC/Sigma/YARA)
│   ├── ifql/                 # Query language parser
│   └── signature/            # Signature management
├── internal/
│   ├── config/               # Configuration management
│   ├── logger/               # Logging system
│   ├── output/               # Output formatting
│   └── sync/                 # Rule synchronization
├── engine/                   # Rust high-performance engine
│   └── src/
│       ├── ioc.rs            # IOC matcher
│       ├── sigma.rs          # Sigma engine
│       ├── yara.rs           # YARA scanner
│       └── matcher.rs        # Aho-Corasick matcher
├── artifacts/builtin/         # Built-in Artifact definitions
├── rules/                    # Detection rules
│   ├── sigma/                # Sigma rules
│   └── yara/                 # YARA rules
├── configs/
│   ├── default.conf          # Default configuration
│   ├── iocs/                 # Built-in IOC database
│   └── playbooks/            # Investigation playbooks
└── docs/                     # Documentation
    ├── user_guide.md         # User guide
    ├── ifql_reference.md     # IFQL reference
    └── artifact_schema.md    # Artifact schema
```

### Documentation

- [User Guide](docs/user_guide.md) - Complete usage tutorial
- [IFQL Reference](docs/ifql_reference.md) - Query language syntax
- [Artifact Schema](docs/artifact_schema.md) - Artifact definition specification
- [Requirements](REQUIREMENTS.md) - Detailed feature requirements
- [Design Document](DESIGN.md) - Technical architecture design

### Use Cases

#### Case 1: Live Incident Response

```bash
# Quick collection on compromised host
sudo intrusionscope collect --mode quick --output /tmp/forensics

# Remote collection
ssh admin@compromised-host "sudo intrusionscope collect --mode standard --output -" | tar xzf -
```

#### Case 2: Offline Forensic Analysis

```bash
# Offline collection (network disabled)
intrusionscope collect --offline --mode deep --output ./case_001

# Encrypted output
intrusionscope collect --mode standard --encrypt --output ./secure_output
```

#### Case 3: Threat Hunting

```bash
# Query suspicious behavior with IFQL
intrusionscope query "SELECT * FROM process.list WHERE cmdline LIKE '%base64%'"

# Detect with custom Sigma rules
intrusionscope detect -i ./output --sigma-rules ./custom_sigma/
```

#### Case 4: Batch Collection

```bash
# Execute via Ansible
ansible compromised_hosts -m shell -a "intrusionscope collect --mode quick --output /tmp/"

# Execute via SSH loop
for host in host1 host2 host3; do
  ssh $host "intrusionscope collect --mode standard --output /tmp/" &
done
```

### Configuration

#### Configuration File Locations

- Linux: `~/.intrusionscope.conf` or `/etc/intrusionscope/intrusionscope.conf`
- Windows: `%APPDATA%\intrusionscope\intrusionscope.conf`

#### Configuration Example

```ini
[general]
mode = standard
output_dir = ./output
log_level = info
language = en

[collection]
threads = 4
timeout = 300
max_output_size = 100

[detection]
rules_dir = ./rules
auto_sync = true
sync_interval = 24

[network]
proxy =
offline = false
timeout = 30
```

#### Environment Variables

All configuration options can be overridden via environment variables with `IS_` prefix:

```bash
export IS_MODE=deep
export IS_OUTPUT_DIR=/tmp/forensics
export IS_OFFLINE=true
```

### Security Notes

- **Read-Only Operations**: Does not modify system state by default
- **Least Privilege**: Graceful degradation when non-admin
- **Data Encryption**: Supports AES-256-GCM encrypted output
- **Offline Operation**: Core functions work without network
- **Self-Cleanup**: Optional trace cleanup after execution

### Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Create a Pull Request

### License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

### Acknowledgments

This project draws design inspiration from the following excellent tools:

- [Velociraptor](https://github.com/Velocidex/velociraptor) - VQL query-driven, Artifact ecosystem
- [GRR](https://github.com/google/grr) - Remote orchestration, batch Hunt
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) - Timeline generation, threat scoring
- [Loki](https://github.com/Neo23x0/Loki) - Four-dimensional IOC detection
- [Chainsaw](https://github.com/WithSecureLabs/chainsaw) - Rust high-performance parsing
- [Sigma](https://github.com/SigmaHQ/sigma) - Detection rule standard

### Contact

- **Author**: Mal-Suen
- **Blog**: [https://blog.mal-suen.cn](https://blog.mal-suen.cn)
- **GitHub**: [https://github.com/Mal-Suen/IntrusionScope](https://github.com/Mal-Suen/IntrusionScope)

---

<a name="中文"></a>
## 中文

### 项目简介

**IntrusionScope** 是一款专为应急响应人员和威胁猎手设计的主机取证与威胁检测工具。融合 Velociraptor、GRR、Hayabusa、Loki 等顶级 DFIR 工具的最佳实践，提供：

- **全面采集** - 37 个收集器覆盖进程、网络、文件系统、日志、注册表
- **高性能检测** - Rust 引擎 + Aho-Corasick 算法，100+ 内置可疑行为模式
- **灵活查询** - IFQL 类 SQL 查询语言，按需精准分析
- **跨平台** - 统一接口支持 Linux 和 Windows
- **多格式输出** - JSON、CSV、HTML 报告，支持中文本地化

### 核心特性

#### 采集能力

| 类别 | 收集器 | 说明 |
|------|--------|------|
| **进程** | 5 个 | 进程列表、进程树、打开文件、内存映射、加载模块 |
| **网络** | 5 个 | 网络连接、监听端口、DNS缓存、ARP缓存、hosts文件 |
| **文件系统** | 10 个 | 最近文件、文件哈希、MFT、Bash历史、Cron任务、Systemd服务、计划任务、自启动项、下载文件、SUID文件 |
| **日志** | 7 个 | 认证日志、系统日志、wtmp/btmp、审计日志、Journal、Windows事件、Web服务器日志 |
| **注册表** | 7 个 | Run键、服务、持久化、USB历史、UserAssist、软件信息、启动项 (Windows) |
| **用户** | 3 个 | 用户列表、登录历史、用户组 |

**总计**: 37 个收集器

#### 检测引擎

| 引擎 | 能力 |
|------|------|
| **IOC 匹配** | 哈希 (MD5/SHA1/SHA256)、IP、域名、URL、文件路径 |
| **Sigma 规则** | 完整条件解析、修饰符支持 (contains/re/base64等) |
| **YARA 规则** | text/hex/regex 字符串、条件评估 |
| **内置模式** | 100+ 可疑行为检测 (PowerShell攻击、Mimikatz、LOLBins等) |

#### 预设采集模式

| 模式 | 数据源 | 耗时 | 适用场景 |
|------|--------|------|---------|
| `quick` | 4 个核心 | < 1 分钟 | 快速响应、初步评估 |
| `standard` | 15 个 | < 5 分钟 | 常规调查、全面评估 |
| `deep` | 28 个 | < 15 分钟 | 深度取证、完整分析 |

> 注：预设模式包含的数据源数量为近似值，实际数量可能因平台而异。

### 安装

#### 从源码编译

```bash
# 克隆仓库
git clone https://github.com/Mal-Suen/IntrusionScope.git
cd IntrusionScope

# 编译 (CGO 模式，需要 Rust 工具链)
CGO_ENABLED=1 go build -o intrusionscope ./cmd/intrusionscope

# 编译 (NoCGO 模式，纯 Go，跨平台编译)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o intrusionscope ./cmd/intrusionscope
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o intrusionscope.exe ./cmd/intrusionscope
```

#### 环境要求

| 组件 | 版本 | 说明 |
|------|------|------|
| Go | 1.21+ | 主程序 |
| Rust | 1.70+ | 高性能检测引擎 (CGO 模式) |
| GCC/MinGW | - | CGO 编译 (Windows) |

### 快速开始

#### 基本用法

```bash
# 显示帮助
intrusionscope --help

# 快速采集
intrusionscope collect --mode quick --output ./output

# 标准采集
intrusionscope collect --mode standard --output ./output

# 采集所有数据
intrusionscope collect --all --output ./output

# 采集指定数据
intrusionscope collect --artifacts process.list,network.connections --output ./output
```

#### 威胁检测

```bash
# 对采集结果进行检测
intrusionscope detect -i ./output -o ./detection_results.json

# 使用自定义 IOC
intrusionscope detect -i ./output --ioc-file custom_iocs.json

# 使用自定义 Sigma 规则
intrusionscope detect -i ./output --sigma-rules ./custom_sigma/
```

#### IFQL 查询

```bash
# 查询可疑进程
intrusionscope query "SELECT * FROM process.list WHERE name LIKE '%powershell%'"

# 查询已建立的网络连接
intrusionscope query "SELECT * FROM network.connections WHERE state = 'ESTABLISHED'"

# 查询失败的登录
intrusionscope query "SELECT * FROM log.auth WHERE type = 'failed_login' LIMIT 100"
```

#### 规则库管理

```bash
# 同步规则库
intrusionscope sync

# 查看规则库状态
intrusionscope rules status

# 导入自定义 IOC
intrusionscope rules import --file custom_iocs.json

# 导入自定义 YARA 规则
intrusionscope rules import --yara ./custom_yara/
```

### 项目结构

```
IntrusionScope/
├── cmd/intrusionscope/       # CLI 入口
│   ├── main.go               # 主入口
│   └── cli/                  # 子命令 (collect/detect/query/report/sync/rules)
├── pkg/
│   ├── collector/            # 采集器 (37 个)
│   ├── detector/             # 检测引擎 (IOC/Sigma/YARA)
│   ├── ifql/                 # 查询语言解析器
│   └── signature/            # 特征库管理
├── internal/
│   ├── config/               # 配置管理
│   ├── logger/               # 日志系统
│   ├── output/               # 输出格式化
│   └── sync/                 # 规则同步
├── engine/                   # Rust 高性能引擎
│   └── src/
│       ├── ioc.rs            # IOC 匹配器
│       ├── sigma.rs          # Sigma 引擎
│       ├── yara.rs           # YARA 扫描器
│       └── matcher.rs        # Aho-Corasick 匹配器
├── artifacts/builtin/         # 内置 Artifact 定义
├── rules/                    # 检测规则
│   ├── sigma/                # Sigma 规则
│   └── yara/                 # YARA 规则
├── configs/
│   ├── default.conf          # 默认配置
│   ├── iocs/                 # 内置 IOC 数据库
│   └── playbooks/            # 调查 Playbook
└── docs/                     # 文档
    ├── user_guide.md         # 用户指南
    ├── ifql_reference.md     # IFQL 参考手册
    └── artifact_schema.md    # Artifact Schema
```

### 文档

- [用户指南](docs/user_guide.md) - 完整使用教程
- [IFQL 参考手册](docs/ifql_reference.md) - 查询语言语法
- [Artifact Schema](docs/artifact_schema.md) - Artifact 定义规范
- [需求文档](REQUIREMENTS.md) - 功能需求详细说明
- [设计文档](DESIGN.md) - 技术架构设计

### 使用场景

#### 场景 1: 实时应急响应

```bash
# 在受感染主机上快速采集
sudo intrusionscope collect --mode quick --output /tmp/forensics

# 远程执行采集
ssh admin@compromised-host "sudo intrusionscope collect --mode standard --output -" | tar xzf -
```

#### 场景 2: 离线取证分析

```bash
# 离线环境采集 (禁用网络)
intrusionscope collect --offline --mode deep --output ./case_001

# 加密输出
intrusionscope collect --mode standard --encrypt --output ./secure_output
```

#### 场景 3: 威胁狩猎

```bash
# 使用 IFQL 查询可疑行为
intrusionscope query "SELECT * FROM process.list WHERE cmdline LIKE '%base64%'"

# 使用自定义 Sigma 规则检测
intrusionscope detect -i ./output --sigma-rules ./custom_sigma/
```

#### 场景 4: 批量采集

```bash
# 通过 Ansible 批量执行
ansible compromised_hosts -m shell -a "intrusionscope collect --mode quick --output /tmp/"

# 通过 SSH 批量执行
for host in host1 host2 host3; do
  ssh $host "intrusionscope collect --mode standard --output /tmp/" &
done
```

### 配置

#### 配置文件位置

- Linux: `~/.intrusionscope.conf` 或 `/etc/intrusionscope/intrusionscope.conf`
- Windows: `%APPDATA%\intrusionscope\intrusionscope.conf`

#### 配置示例

```ini
[general]
mode = standard
output_dir = ./output
log_level = info
language = zh

[collection]
threads = 4
timeout = 300
max_output_size = 100

[detection]
rules_dir = ./rules
auto_sync = true
sync_interval = 24

[network]
proxy =
offline = false
timeout = 30
```

#### 环境变量

所有配置项可通过环境变量覆盖，前缀为 `IS_`：

```bash
export IS_MODE=deep
export IS_OUTPUT_DIR=/tmp/forensics
export IS_OFFLINE=true
```

### 安全说明

- **只读操作**: 默认不修改系统状态
- **最小权限**: 非管理员权限时优雅降级
- **数据加密**: 支持 AES-256-GCM 加密输出
- **离线运行**: 核心功能无需网络连接
- **自清理**: 可选执行后清理痕迹

### 贡献

欢迎贡献代码、报告问题或提出建议！

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

### 许可证

本项目采用 GNU General Public License v3.0 许可证 - 详见 [LICENSE](LICENSE) 文件。

### 致谢

本项目借鉴了以下优秀工具的设计理念：

- [Velociraptor](https://github.com/Velocidex/velociraptor) - VQL 查询驱动、Artifact 生态
- [GRR](https://github.com/google/grr) - 远程编排、批量 Hunt
- [Hayabusa](https://github.com/Yamato-Security/hayabusa) - 时间线生成、威胁评分
- [Loki](https://github.com/Neo23x0/Loki) - 四维 IOC 检测
- [Chainsaw](https://github.com/WithSecureLabs/chainsaw) - Rust 高性能解析
- [Sigma](https://github.com/SigmaHQ/sigma) - 检测规则标准

### 联系方式

- **作者**: Mal-Suen
- **博客**: [https://blog.mal-suen.cn](https://blog.mal-suen.cn)
- **GitHub**: [https://github.com/Mal-Suen/IntrusionScope](https://github.com/Mal-Suen/IntrusionScope)

---

*Copyright (c) 2024-2026 Mal-Suen. Released under GNU General Public License v3.0.*
