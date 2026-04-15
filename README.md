# IntrusionScope

> **A Cross-Platform Fast Host Forensics and Threat Hunting Tool.**
> **跨平台快速主机取证与威胁狩猎工具。**

[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go 1.21+](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://golang.org/)
[![Rust 1.70+](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/Mal-Suen/IntrusionScope)

---

## 🇬🇧 English Documentation

### 📖 Introduction

IntrusionScope is a powerful host-based forensic artifact collection and threat detection tool designed for incident responders and threat hunters. It combines best practices from top DFIR tools, providing comprehensive artifact collection, custom query language (IFQL), and multi-source threat detection capabilities.

### 🚀 Key Features

| Feature | Description |
| :--- | :--- |
| **🔍 Comprehensive Collection** | Processes, network, filesystem, registry, logs across Windows/Linux/macOS |
| **⚡ Rust Detection Engine** | High-performance IOC/Sigma/YARA detection via CGO integration |
| **📝 IFQL Query Language** | SQL-like syntax for flexible forensic data analysis |
| **🔧 Extensible Architecture** | Plugin-based collectors and detectors |
| **📊 Multiple Output Formats** | JSON, CSV, HTML report generation |

### 🛠️ Collectors

#### Process Collectors
- Running process list (PID, PPID, name, exe, cmdline, user)
- Process tree with parent-child relationships
- Open files by process
- Memory usage information

#### Network Collectors
- Active TCP/UDP connections with process mapping
- Listening ports
- DNS cache entries
- ARP cache
- Hosts file entries

#### Filesystem Collectors
- Recently modified files
- File hash computation (MD5, SHA1, SHA256)
- Bash history (Linux)
- Cron jobs & Systemd services (Linux)
- Scheduled tasks & Autorun entries (Windows)
- SUID/SGID files (Linux)

#### Registry Collectors (Windows)
- Run/RunOnce keys
- Services configuration
- Persistence mechanisms
- USB device history
- UserAssist entries

#### Log Collectors
- Authentication logs (auth.log, secure)
- Syslog & wtmp/btmp
- Auditd logs & Systemd journal
- Windows Event Logs
- Web server logs

### 📊 Detection Engine

The Rust-based detection engine provides:
- **IOC Detection**: Hash, IP, domain, URL matching
- **Sigma Rules**: YAML-based detection rules
- **YARA Patterns**: Pattern matching for files and memory
- **Aho-Corasick Matcher**: Fast multi-pattern matching

### 📝 IFQL Query Language

Query collected data using SQL-like syntax:

```sql
SELECT name, pid, exe FROM process.list WHERE name LIKE '%powershell%'
SELECT * FROM network.connections WHERE state = 'ESTABLISHED' AND remote_port = 443
SELECT * FROM log.auth WHERE type = 'failed_login' LIMIT 100
```

### 🚀 Getting Started

#### Installation

```bash
# Clone the repository
git clone https://github.com/Mal-Suen/IntrusionScope.git
cd IntrusionScope

# Build Go binary
go build -o intrusionscope ./cmd/intrusionscope

# Build Rust engine (optional, for advanced detection)
cd engine && cargo build --release
```

#### Prerequisites

- Go 1.21 or later
- Rust 1.70 or later (for detection engine)
- GCC/MinGW (for CGO on Windows)

#### Basic Usage

```bash
# Show help
intrusionscope --help

# Collect all artifacts
intrusionscope collect --all

# Collect specific artifacts
intrusionscope collect --artifacts process.list,network.connections

# Run detection
intrusionscope detect -i ./output

# Query collected data
intrusionscope query "SELECT * FROM process.list WHERE name LIKE '%cmd%'"

# Output formats
intrusionscope collect --all --output json --file results.json
```

### 📂 Project Structure

```text
IntrusionScope/
├── cmd/intrusionscope/     # Main CLI entry point
├── pkg/
│   ├── collector/          # Artifact collectors
│   ├── detector/           # Detection engine & IOC/Sigma/YARA
│   ├── ifql/               # Query language parser & executor
│   ├── artifact/           # Artifact definitions
│   └── signature/          # Signature management
├── internal/
│   ├── config/             # Configuration handling
│   └── output/             # Output formatting
├── engine/                 # Rust detection engine
├── artifacts/builtin/      # Built-in artifact definitions
└── configs/playbooks/      # Investigation playbooks
```

---

## 🇨🇳 中文文档

### 📖 项目简介

IntrusionScope 是一款强大的主机取证与威胁检测工具，专为应急响应人员和威胁猎手设计。它融合了顶级 DFIR 工具的最佳实践，提供全面的取证数据采集、自定义查询语言 (IFQL) 以及多源威胁检测能力。

### 🚀 核心特性

| 特性 | 描述 |
| :--- | :--- |
| **🔍 全面采集** | 跨 Windows/Linux/macOS 的进程、网络、文件系统、注册表、日志 |
| **⚡ Rust 检测引擎** | 通过 CGO 集成的高性能 IOC/Sigma/YARA 检测 |
| **📝 IFQL 查询语言** | 类 SQL 语法，灵活分析取证数据 |
| **🔧 可扩展架构** | 插件式采集器与检测器 |
| **📊 多种输出格式** | JSON、CSV、HTML 报告生成 |

### 🛠️ 采集器

#### 进程采集器
- 运行进程列表 (PID, PPID, 名称, 路径, 命令行, 用户)
- 父子关系的进程树
- 进程打开的文件
- 内存使用信息

#### 网络采集器
- TCP/UDP 连接及进程映射
- 监听端口
- DNS 缓存
- ARP 缓存
- Hosts 文件

#### 文件系统采集器
- 最近修改的文件
- 文件哈希计算 (MD5, SHA1, SHA256)
- Bash 历史 (Linux)
- Cron 任务 & Systemd 服务 (Linux)
- 计划任务 & 自启动项 (Windows)
- SUID/SGID 文件 (Linux)

#### 注册表采集器 (Windows)
- Run/RunOnce 键
- 服务配置
- 持久化机制
- USB 设备历史
- UserAssist 条目

#### 日志采集器
- 认证日志 (auth.log, secure)
- Syslog & wtmp/btmp
- Auditd 日志 & Systemd journal
- Windows 事件日志
- Web 服务器日志

### 📊 检测引擎

基于 Rust 的高性能检测引擎提供：
- **IOC 检测**: 哈希、IP、域名、URL 匹配
- **Sigma 规则**: 基于 YAML 的检测规则
- **YARA 模式**: 文件和内存的模式匹配
- **Aho-Corasick 匹配器**: 快速多模式匹配

### 📝 IFQL 查询语言

使用类 SQL 语法查询采集数据：

```sql
SELECT name, pid, exe FROM process.list WHERE name LIKE '%powershell%'
SELECT * FROM network.connections WHERE state = 'ESTABLISHED' AND remote_port = 443
SELECT * FROM log.auth WHERE type = 'failed_login' LIMIT 100
```

### 🚀 快速开始

#### 安装

```bash
# 克隆仓库
git clone https://github.com/Mal-Suen/IntrusionScope.git
cd IntrusionScope

# 编译 Go 二进制
go build -o intrusionscope ./cmd/intrusionscope

# 编译 Rust 引擎 (可选，用于高级检测)
cd engine && cargo build --release
```

#### 环境要求

- Go 1.21 或更高版本
- Rust 1.70 或更高版本 (检测引擎)
- GCC/MinGW (Windows 上的 CGO)

#### 基本用法

```bash
# 显示帮助
intrusionscope --help

# 采集所有取证数据
intrusionscope collect --all

# 采集指定数据
intrusionscope collect --artifacts process.list,network.connections

# 运行威胁检测
intrusionscope detect -i ./output

# 查询采集数据
intrusionscope query "SELECT * FROM process.list WHERE name LIKE '%cmd%'"

# 输出格式
intrusionscope collect --all --output json --file results.json
```

### 📂 目录结构

```text
IntrusionScope/
├── cmd/intrusionscope/     # CLI 主入口
├── pkg/
│   ├── collector/          # 取证数据采集器
│   ├── detector/           # 检测引擎 & IOC/Sigma/YARA
│   ├── ifql/               # 查询语言解析器与执行器
│   ├── artifact/           # 取证数据定义
│   └── signature/          # 特征库管理
├── internal/
│   ├── config/             # 配置处理
│   └── output/             # 输出格式化
├── engine/                 # Rust 检测引擎
├── artifacts/builtin/      # 内置取证数据定义
└── configs/playbooks/      # 调查剧本
```

---

## 🤝 Contribution & Contact / 贡献与联系

*   **Author:** Mal-Suen
*   **Blog:** [Mal-Suen's Blog](https://blog.mal-suen.cn)
*   **GitHub:** [https://github.com/Mal-Suen/IntrusionScope](https://github.com/Mal-Suen/IntrusionScope)

## 🙏 Acknowledgments / 致谢

Inspired by:
- [Velociraptor](https://github.com/Velocidex/velociraptor)
- [OSQuery](https://github.com/osquery/osquery)
- [Sigma](https://github.com/SigmaHQ/sigma)

*Copyright © 2024-2026 Mal-Suen. Released under MIT License.*
