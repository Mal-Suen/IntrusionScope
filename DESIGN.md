# IntrusionScope - 设计文档

## 1. 系统架构

### 1.1 整体架构

IntrusionScope 采用**分层插件化架构**,结合 Go 的跨平台编译能力与 Rust 的高性能解析能力,实现统一的取证范式。

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         IntrusionScope CLI (Go)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                           Application Layer                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │    CLI      │    │   Config    │    │   Progress  │    │    Rules    │  │
│  │   Parser    │    │   Manager   │    │   Tracker   │    │   Manager   │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│                           Core Engine Layer                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │    IFQL     │    │  Artifact   │    │  Execution  │    │   Sync      │  │
│  │   Parser    │───▶│   Resolver  │───▶│   Pipeline  │    │   Engine    │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│                           Collector Layer                                   │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   Process   │    │   Network   │    │ Filesystem  │    │   EventLog  │  │
│  │  Collector  │    │  Collector  │    │  Collector  │    │  Collector  │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  Registry   │    │  UserAct    │    │   Memory    │    │   Security  │  │
│  │  Collector  │    │  Collector  │    │  Collector  │    │  Collector  │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│                       Platform Abstraction Layer                            │
│  ┌────────────────────────────┐    ┌────────────────────────────┐          │
│  │       Linux Plugin         │    │      Windows Plugin        │          │
│  │  • /proc filesystem        │    │  • Windows API             │          │
│  │  • shell commands          │    │  • WMI/CIM                 │          │
│  │  • native tools            │    │  • Registry API            │          │
│  │  • systemd/journal         │    │  • ETW                     │          │
│  └────────────────────────────┘    └────────────────────────────┘          │
├─────────────────────────────────────────────────────────────────────────────┤
│                       Detection Engine (Rust FFI)                           │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │    IOC      │    │   Sigma     │    │    YARA     │    │   Parser    │  │
│  │   Matcher   │    │   Engine    │    │   Scanner   │    │  (EVTX/MFT) │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
├─────────────────────────────────────────────────────────────────────────────┤
│                           Output Layer                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │  JSON/CSV   │    │   Report    │    │ Encryption  │    │  Checksum   │  │
│  │ Serializer  │    │  Generator  │    │   Module    │    │  Generator  │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 技术栈选择

| 层级 | 技术选择 | 理由 |
|------|---------|------|
| **主程序** | Go 1.21+ | 跨平台编译、单一二进制、并发模型简单、开发效率高 |
| **高性能解析** | Rust 1.75+ | 内存安全、极致性能、EVTX/MFT 解析库生态 |
| **FFI 桥接** | cgo + C binding | Go 调用 Rust 库的标准方式 |
| **查询语言** | 自定义 IFQL Parser | 借鉴 VQL 理念,简化实现 |
| **配置格式** | YAML | Artifact 定义、用户可读性好 |
| **输出格式** | JSON + Markdown + HTML | 结构化 + 人类可读 |

### 1.3 项目结构

```
intrusionscope/
├── cmd/
│   └── intrusionscope/
│       └── main.go                 # 程序入口
├── internal/
│   ├── cli/                        # CLI 参数解析
│   │   ├── flags.go
│   │   ├── help.go
│   │   └── completion.go
│   ├── config/                     # 配置管理
│   │   ├── config.go
│   │   ├── loader.go
│   │   └── validator.go
│   ├── ifql/                       # IFQL 查询语言
│   │   ├── parser.go
│   │   ├── ast.go
│   │   ├── executor.go
│   │   ├── functions.go
│   │   └── builtins.go
│   ├── artifact/                   # Artifact 管理
│   │   ├── registry.go
│   │   ├── loader.go
│   │   ├── resolver.go
│   │   └── builtin/                # 内置 Artifact
│   │       ├── system.go
│   │       ├── process.go
│   │       ├── network.go
│   │       ├── filesystem.go
│   │       └── ...
│   ├── collector/                  # 采集器
│   │   ├── executor.go
│   │   ├── pipeline.go
│   │   ├── linux/                  # Linux 采集插件
│   │   │   ├── process.go
│   │   │   ├── network.go
│   │   │   ├── filesystem.go
│   │   │   └── ...
│   │   └── windows/                # Windows 采集插件
│   │       ├── process.go
│   │       ├── network.go
│   │       ├── registry.go
│   │       └── ...
│   ├── detection/                  # 检测引擎(Rust FFI)
│   │   ├── ioc_matcher.go
│   │   ├── sigma_engine.go
│   │   ├── yara_scanner.go
│   │   └── rust_bindings.go
│   ├── rules/                      # 规则库管理
│   │   ├── manager.go
│   │   ├── sync.go
│   │   ├── sources.go
│   │   └── index.go
│   ├── analysis/                   # 分析模块
│   │   ├── threat_scorer.go
│   │   ├── timeline.go
│   │   ├── mitre_mapping.go
│   │   └── correlator.go
│   ├── output/                     # 输出模块
│   │   ├── serializer.go
│   │   ├── report.go
│   │   ├── encryptor.go
│   │   └── checksum.go
│   └── platform/                   # 平台抽象
│       ├── interface.go
│       ├── linux.go
│       └── windows.go
├── rust/                           # Rust 高性能解析
│   ├── src/
│   │   ├── lib.rs
│   │   ├── evtx_parser.rs
│   │   ├── mft_parser.rs
│   │   ├── sigma_engine.rs
│   │   ├── yara_wrapper.rs
│   │   ├── ioc_matcher.rs
│   │   └── bloom_filter.rs
│   └── Cargo.toml
├── artifacts/                      # Artifact 定义(YAML)
│   ├── linux/
│   │   ├── system.yaml
│   │   ├── process.yaml
│   │   ├── network.yaml
│   │   └── ...
│   └── windows/
│       ├── system.yaml
│       ├── registry.yaml
│       ├── eventlog.yaml
│       └── ...
├── rules/                          # 检测规则
│   ├── ioc/
│   │   ├── hashes.json
│   │   ├── c2_indicators.json
│   │   └── filenames.json
│   ├── sigma/
│   │   └── ...
│   ├── yara/
│   │   └── ...
│   └── index.json                  # 规则索引
├── scripts/                        # 辅助脚本
│   ├── build.sh
│   ├── release.sh
│   └── rules_sync.py
├── configs/                        # 配置模板
│   ├── intrusionscope.conf.example
│   └── playbook_example.yaml
├── docs/                           # 文档
│   ├── user_guide.md
│   ├── ifql_reference.md
│   ├── artifact_schema.md
│   └── api_reference.md
├── go.mod
├── go.sum
├── Makefile
├── README.md
├── LICENSE
└── CHANGELOG.md
```

---

## 2. IFQL 查询语言设计

### 2.1 设计理念

IFQL (IntrusionScope Forensic Query Language) 是一种声明式查询语言,借鉴 Velociraptor VQL 的设计理念:

- **声明式**: 描述"采集什么",而非"如何采集"
- **可组合**: 查询可组合、可嵌套、可引用
- **类型安全**: 静态类型检查,编译时错误
- **可扩展**: 支持自定义函数与插件

### 2.2 语法规范

#### 2.2.1 基本语法

```sql
-- 基本查询结构
SELECT <columns>
FROM <source>
[WHERE <condition>]
[ORDER BY <column> [ASC|DESC]]
[LIMIT <n>]

-- 示例: 查询所有进程
SELECT pid, name, cmdline, user
FROM process()

-- 示例: 查询可疑进程
SELECT *
FROM process()
WHERE name IN ('powershell.exe', 'cmd.exe', 'wscript.exe')
  OR cmdline LIKE '%base64%'
  OR parent_name = 'explorer.exe'
```

#### 2.2.2 数据源 (Sources)

| 数据源 | 说明 | 平台 |
|--------|------|------|
| `process()` | 进程列表 | All |
| `network()` | 网络连接 | All |
| `file(path, pattern)` | 文件搜索 | All |
| `registry(key)` | 注册表查询 | Windows |
| `eventlog(source, id)` | 事件日志 | All |
| `artifact(name)` | Artifact 引用 | All |

#### 2.2.3 内置函数

**字符串函数:**
```
contains(str, substr)      -- 包含子串
matches(str, regex)        -- 正则匹配
lower(str) / upper(str)    -- 大小写转换
split(str, sep)            -- 分割字符串
hash(path, algo)           -- 计算文件哈希
```

**集合函数:**
```
in(value, list)            -- 成员检查
any(list, condition)       -- 存在满足条件
all(list, condition)       -- 全部满足条件
count(list)                -- 计数
```

**时间函数:**
```
now()                      -- 当前时间
timestamp(str)             -- 解析时间戳
age(timestamp)             -- 距今时长
```

**文件函数:**
```
size(path)                 -- 文件大小
mtime(path)                -- 修改时间
exists(path)               -- 文件存在检查
readfile(path, limit)      -- 读取文件内容
```

#### 2.2.4 完整语法示例

```sql
-- 查询所有网络连接并关联进程
SELECT 
    n.proto,
    n.local_addr,
    n.remote_addr,
    n.state,
    p.name AS process_name,
    p.cmdline AS process_cmdline
FROM network() AS n
LEFT JOIN process() AS p ON n.pid = p.pid
WHERE n.state = 'ESTABLISHED'
  AND n.remote_port NOT IN (80, 443, 8080)

-- 查询最近修改的系统文件
SELECT 
    path,
    size(path) AS file_size,
    mtime(path) AS modified_time,
    hash(path, 'sha256') AS sha256
FROM file('/etc', '**/*')
WHERE mtime(path) > now() - interval('7d')
  AND size(path) < 10*1024*1024
ORDER BY mtime(path) DESC
LIMIT 100

-- 查询可疑注册表启动项
SELECT 
    key,
    value,
    data
FROM registry('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\*')
WHERE data LIKE '%.exe%'
  AND NOT matches(data, 'C:\\\\Program Files\\\\.*')

-- 使用 Artifact
SELECT *
FROM artifact('windows.scheduled_tasks')
WHERE command LIKE '%powershell%'
  OR command LIKE '%cmd.exe /c%'
```

### 2.3 AST 定义

```go
// 抽象语法树节点定义
type Node interface {
    String() string
    Position() token.Position
}

type Query struct {
    Select   *SelectClause
    From     *FromClause
    Where    *WhereClause
    OrderBy  *OrderByClause
    Limit    *LimitClause
}

type SelectClause struct {
    Columns []Expression
    Distinct bool
}

type FromClause struct {
    Source   Expression
    Alias    string
    Joins    []*JoinClause
}

type WhereClause struct {
    Condition Expression
}

type Expression interface {
    Node
    exprNode()
}

// 表达式类型
type BinaryExpr struct {
    Op  token.Token  // AND, OR, =, <, >, LIKE, IN, etc.
    LHS Expression
    RHS Expression
}

type CallExpr struct {
    Func string
    Args []Expression
}

type Identifier struct {
    Name string
}

type Literal struct {
    Value interface{}
    Kind  token.Token  // STRING, NUMBER, BOOL
}
```

### 2.4 执行流程

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   源代码    │ ──▶ │   Lexer     │ ──▶ │   Parser    │ ──▶ │    AST      │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                  │
                                                                  ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   结果集    │ ◀── │  Executor   │ ◀── │   Planner   │ ◀── │  Validator  │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

---

## 3. Artifact 系统设计

### 3.1 Artifact 定义格式

```yaml
# Artifact 元数据
name: windows.suspicious_processes
description: 检测可疑进程特征
version: 1.0.0
author: IntrusionScope Team
tags: [process, detection, windows]
platform: windows
references:
  - https://attack.mitre.org/techniques/T1059/

# 依赖声明
dependencies:
  - system.info  # 依赖系统信息采集

# 参数定义
parameters:
  - name: suspicious_names
    type: list
    default: ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"]
    description: 可疑进程名列表

  - name: max_results
    type: integer
    default: 100
    description: 最大返回结果数

# 采集逻辑 (IFQL)
sources:
  - query: |
      SELECT 
        pid,
        name,
        cmdline,
        user,
        parent_pid,
        parent_name,
        start_time
      FROM process()
      WHERE name IN ($suspicious_names)
         OR cmdline LIKE '%base64%'
         OR cmdline LIKE '%downloadstring%'
         OR cmdline LIKE '%iex%'
      ORDER BY start_time DESC
      LIMIT $max_results

# 后处理规则
analysis:
  - type: threat_score
    condition: "cmdline LIKE '%base64%' AND parent_name = 'explorer.exe'"
    score: high
    mitre: [T1059.001]

  - type: threat_score
    condition: "name = 'powershell.exe' AND cmdline LIKE '%download%'"
    score: critical
    mitre: [T1059.001, T1105]

# 输出格式
output:
  format: json
  filename: suspicious_processes.json
```

### 3.2 Artifact Schema 定义

```yaml
# Artifact Schema (JSON Schema 格式)
$schema: "http://json-schema.org/draft-07/schema#"
type: object
required:
  - name
  - version
  - platform
  - sources
properties:
  name:
    type: string
    pattern: "^[a-z0-9_]+(\\.[a-z0-9_]+)*$"
    description: "Artifact 唯一标识,如 windows.scheduled_tasks"
  
  description:
    type: string
    maxLength: 500
  
  version:
    type: string
    pattern: "^\\d+\\.\\d+\\.\\d+$"
  
  author:
    type: string
  
  tags:
    type: array
    items:
      type: string
      enum: [process, network, file, registry, eventlog, detection, memory, user]
  
  platform:
    type: string
    enum: [linux, windows, all]
  
  references:
    type: array
    items:
      type: string
      format: uri
  
  dependencies:
    type: array
    items:
      type: string
  
  parameters:
    type: array
    items:
      type: object
      required: [name, type]
      properties:
        name:
          type: string
        type:
          type: string
          enum: [string, integer, boolean, list, path]
        default:
          description: 默认值
        description:
          type: string
        required:
          type: boolean
          default: false
  
  sources:
    type: array
    items:
      type: object
      required: [query]
      properties:
        query:
          type: string
          description: IFQL 查询语句
        precondition:
          type: string
          description: 执行前置条件
  
  analysis:
    type: array
    items:
      type: object
      required: [type, condition]
      properties:
        type:
          type: string
          enum: [threat_score, ioc_match, mitre_map]
        condition:
          type: string
        score:
          type: string
          enum: [informational, low, medium, high, critical]
        mitre:
          type: array
          items:
            type: string
  
  output:
    type: object
    properties:
      format:
        type: string
        enum: [json, csv, jsonl]
        default: json
      filename:
        type: string
```

### 3.3 内置 Artifact 清单

| Artifact 名称 | 说明 | 平台 |
|--------------|------|------|
| `system.info` | 系统基础信息 | All |
| `system.users` | 用户列表 | All |
| `system.services` | 服务列表 | All |
| `system.packages` | 已安装软件 | All |
| `process.list` | 进程列表 | All |
| `process.tree` | 进程树 | All |
| `process.connections` | 进程网络连接 | All |
| `process.modules` | 进程模块/DLL | All |
| `network.connections` | 网络连接 | All |
| `network.listeners` | 监听端口 | All |
| `network.arp` | ARP 表 | All |
| `network.routes` | 路由表 | All |
| `filesystem.timeline` | 文件时间线 | All |
| `filesystem.hashes` | 文件哈希 | All |
| `filesystem.suspicious` | 可疑文件 | All |
| `registry.run_keys` | 启动项注册表 | Windows |
| `registry.services` | 服务注册表 | Windows |
| `registry.persistence` | 持久化注册表 | Windows |
| `eventlog.security` | 安全事件日志 | Windows |
| `eventlog.system` | 系统事件日志 | Windows |
| `eventlog.powershell` | PowerShell 日志 | Windows |
| `eventlog.sysmon` | Sysmon 日志 | Windows |
| `scheduled_tasks.list` | 计划任务 | All |
| `startup.items` | 启动项 | All |
| `user.history` | 命令历史 | All |
| `user.logins` | 登录历史 | All |
| `security.av_status` | 杀软状态 | All |
| `security.firewall` | 防火墙规则 | All |

---

## 4. 威胁特征库设计

### 4.1 三层特征库模型

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Layer 1: 内置库 (Built-in)                                                 │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • 随工具发布, 离线可用                                                      │
│  • 包含高频恶意哈希 + 核心 YARA + 基础 Sigma                                 │
│  • 大小: ~50MB                                                              │
│  • 更新: 随版本发布更新                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 2: 用户库 (Custom)                                                   │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • 用户自定义/企业情报导入                                                   │
│  • 格式: JSON/YAML                                                          │
│  • 支持私有 IOC、自定义 YARA、企业 Sigma 规则                                │
│  • 优先级最高,可覆盖内置规则                                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  Layer 3: 云端库 (Cloud/Sync)                                               │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • 在线同步最新威胁情报                                                      │
│  • 接入免费公开数据源                                                        │
│  • 离线环境不使用                                                            │
│  • 增量更新,原子替换                                                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 免费数据源配置

```yaml
# 数据源配置文件: rules/sources.yaml
sources:
  malwarebazaar:
    name: MalwareBazaar
    type: hash
    url: https://bazaar.abuse.ch/export/csv/sha256/
    format: csv
    fields: [sha256, first_seen, tags]
    update_interval: 24h
    enabled: true
    requires_auth: false

  urlhaus:
    name: URLhaus
    type: url
    url: https://urlhaus.abuse.ch/export/csv/
    format: csv
    fields: [url, threat_type, first_seen]
    update_interval: 24h
    enabled: true
    requires_auth: false

  threatfox:
    name: ThreatFox
    type: ioc
    url: https://threatfox.abuse.ch/export/json/recent/
    format: json
    fields: [ioc, ioc_type, threat_type, tags]
    update_interval: 24h
    enabled: true
    requires_auth: false

  dshield_block:
    name: DShield Blocklist
    type: ip
    url: https://feeds.dshield.org/block.txt
    format: text
    fields: [start_ip, end_ip, attacks]
    update_interval: 24h
    enabled: true
    requires_auth: false

  spamhaus_drop:
    name: Spamhaus DROP
    type: ip
    url: https://www.spamhaus.org/drop/drop.txt
    format: text
    fields: [cidr, sbl_id]
    update_interval: 24h
    enabled: true
    requires_auth: false

  sigma_hq:
    name: SigmaHQ Rules
    type: sigma
    url: https://github.com/SigmaHQ/sigma/releases/latest/download/rules.tar.gz
    format: tarball
    update_interval: 168h  # 每周
    enabled: true
    requires_auth: false

  neo23x0_yara:
    name: Neo23x0 signature-base
    type: yara
    url: https://github.com/Neo23x0/signature-base/archive/refs/heads/master.tar.gz
    format: tarball
    update_interval: 168h
    enabled: true
    requires_auth: false

  nsql_rds:
    name: NSRL RDS
    type: whitelist
    url: https://www.nist.gov/programs-projects/national-software-reference-library
    format: custom
    update_interval: 720h  # 每月
    enabled: false  # 默认关闭,体积大
    requires_auth: false
    note: "需手动下载,用于白名单过滤"
```

### 4.3 规则索引结构

```json
{
  "version": "2026041500",
  "created": "2026-04-15T00:00:00Z",
  "updated": "2026-04-15T10:30:00Z",
  "sources": {
    "malwarebazaar": {
      "version": "20260415",
      "updated": "2026-04-15T08:00:00Z",
      "count": 1250000,
      "size_mb": 45
    },
    "urlhaus": {
      "version": "20260415",
      "updated": "2026-04-15T08:00:00Z",
      "count": 580000,
      "size_mb": 12
    },
    "sigma_hq": {
      "version": "20260410",
      "updated": "2026-04-10T00:00:00Z",
      "count": 5200,
      "size_mb": 8
    }
  },
  "statistics": {
    "hash_count": 1250000,
    "url_count": 580000,
    "ip_count": 25000,
    "yara_count": 350,
    "sigma_count": 5200,
    "whitelist_count": 0
  },
  "checksums": {
    "hashes_sha256": "abc123...",
    "c2_sha256": "def456...",
    "sigma_sha256": "ghi789..."
  }
}
```

### 4.4 同步流程

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           规则同步流程                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. 启动检查                                                                │
│     ├── 检查 rules/index.json 是否存在                                      │
│     ├── 不存在 → 触发首次同步                                               │
│     └── 存在 → 检查 last_sync 时间                                          │
│                                                                             │
│  2. 同步决策                                                                │
│     ├── 距上次同步 > update_interval → 触发后台同步                         │
│     ├── --no-sync 参数 → 跳过同步                                           │
│     └── --offline 参数 → 完全禁用网络                                       │
│                                                                             │
│  3. 同步执行 (后台异步)                                                      │
│     ├── 并发下载各数据源 (默认 4 并发)                                       │
│     ├── 下载到临时目录                                                       │
│     ├── 校验数据完整性                                                       │
│     ├── 构建索引与加速结构                                                   │
│     └── 原子替换规则目录                                                     │
│                                                                             │
│  4. 同步状态                                                                 │
│     ├── 成功 → 更新 index.json                                              │
│     ├── 部分失败 → 记录失败源,继续使用已有规则                               │
│     └── 全部失败 → 警告用户,使用内置规则                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.5 性能优化设计

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           查询加速结构                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Bloom Filter (布隆过滤器)                                                   │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • 用于哈希 IOC 快速预过滤                                                   │
│  • 查询复杂度: O(k), k 为哈希函数数量                                        │
│  • 空间效率: 1% 误报率下,每元素仅需 9.6 bits                                 │
│  • 100 万哈希仅需 ~1.2MB 内存                                                │
│                                                                             │
│  Trie Tree (前缀树)                                                         │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • 用于 C2 IP/域名匹配                                                       │
│  • 支持 CIDR 前缀匹配                                                        │
│  • 查询复杂度: O(k), k 为字符串长度                                          │
│                                                                             │
│  Hash Map (哈希表)                                                          │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • 用于精确哈希匹配                                                          │
│  • 查询复杂度: O(1)                                                          │
│                                                                             │
│  Rule Cache (规则缓存)                                                      │
│  ─────────────────────────────────────────────────────────────────────────  │
│  • YARA 规则预编译为字节码                                                   │
│  • Sigma 规则预编译为查询树                                                  │
│  • 缓存命中率 > 95%                                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. 检测引擎设计

### 5.1 检测引擎架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      Detection Engine (Rust)                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         Rule Loader                                  │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐        │   │
│  │  │   IOC     │  │  Sigma    │  │   YARA    │  │ Whitelist │        │   │
│  │  │  Loader   │  │  Loader   │  │  Loader   │  │  Loader   │        │   │
│  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         Index Builder                                │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐        │   │
│  │  │   Bloom   │  │   Trie    │  │  HashMap  │  │  Compiled │        │   │
│  │  │  Filter   │  │   Tree    │  │  Index    │  │   Rules   │        │   │
│  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         Match Engine                                 │   │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐        │   │
│  │  │   IOC     │  │  Sigma    │  │   YARA    │  │  Result   │        │   │
│  │  │  Matcher  │  │  Matcher  │  │  Scanner  │  │ Aggregator│        │   │
│  │  └───────────┘  └───────────┘  └───────────┘  └───────────┘        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 IOC 匹配器

```rust
// Rust 实现
pub struct IOCMatcher {
    // 布隆过滤器用于快速预过滤
    bloom_filter: BloomFilter,
    // 精确哈希表用于确认匹配
    hash_map: HashMap<[u8; 32], IOCEntry>,
    // 前缀树用于 IP/域名匹配
    ip_trie: Trie<IpAddr, IOCEntry>,
    domain_trie: Trie<String, IOCEntry>,
    // 白名单过滤器
    whitelist: WhitelistFilter,
}

pub struct IOCEntry {
    pub value: String,
    pub ioc_type: IOCType,
    pub threat: String,
    pub confidence: Confidence,
    pub tags: Vec<String>,
    pub source: String,
    pub first_seen: DateTime,
}

pub enum IOCType {
    HashSHA256,
    HashMD5,
    HashSHA1,
    IPAddress,
    Domain,
    URL,
    Filename,
}

impl IOCMatcher {
    // 检查哈希是否为恶意
    pub fn check_hash(&self, hash: &[u8]) -> Option<&IOCEntry> {
        // 1. 白名单检查
        if self.whitelist.contains_hash(hash) {
            return None;
        }
        // 2. 布隆过滤器预过滤
        if !self.bloom_filter.contains(hash) {
            return None;
        }
        // 3. 精确匹配
        self.hash_map.get(hash)
    }
    
    // 检查 IP 是否为恶意
    pub fn check_ip(&self, ip: &IpAddr) -> Option<&IOCEntry> {
        if self.whitelist.contains_ip(ip) {
            return None;
        }
        self.ip_trie.longest_prefix_match(ip)
    }
}
```

### 5.3 Sigma 引擎

```rust
pub struct SigmaEngine {
    rules: Vec<CompiledSigmaRule>,
    field_mappings: FieldMappings,
}

pub struct CompiledSigmaRule {
    pub id: String,
    pub title: String,
    pub level: ThreatLevel,
    pub logsource: LogSource,
    pub detection: DetectionTree,
    pub mitre: Vec<String>,
}

// 检测树 (预编译的查询结构)
pub enum DetectionTree {
    And(Vec<DetectionTree>),
    Or(Vec<DetectionTree>),
    Not(Box<DetectionTree>),
    FieldMatch {
        field: String,
        op: MatchOp,
        value: Value,
    },
}

impl SigmaEngine {
    // 匹配事件日志
    pub fn match_event(&self, event: &LogEvent) -> Vec<MatchResult> {
        let mut results = Vec::new();
        for rule in &self.rules {
            if rule.matches(event, &self.field_mappings) {
                results.push(MatchResult {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    level: rule.level,
                    mitre: rule.mitre.clone(),
                    event: event.clone(),
                });
            }
        }
        results
    }
}
```

### 5.4 YARA 扫描器

```rust
pub struct YARAScanner {
    compiled_rules: CompiledRules,
    timeout: Duration,
}

impl YARAScanner {
    // 扫描文件
    pub fn scan_file(&self, path: &Path) -> Result<Vec<YARAMatch>> {
        let mut results = Vec::new();
        let scanner = Scanner::new(&self.compiled_rules);
        
        scanner.scan_file(path, self.timeout, |rule| {
            results.push(YARAMatch {
                rule_id: rule.identifier(),
                namespace: rule.namespace(),
                tags: rule.tags(),
                meta: rule.metadata(),
                strings: rule.matched_strings(),
            });
            Ok(())
        })?;
        
        Ok(results)
    }
    
    // 扫描进程内存
    pub fn scan_process(&self, pid: u32) -> Result<Vec<YARAMatch>> {
        // ...
    }
}
```

### 5.5 Go-Rust FFI 接口

```go
// Go 侧绑定
package detection

/*
#cgo LDFLAGS: -L${SRCDIR}/../rust/target/release -lintrusionscope_rust
#include "bindings.h"
*/
import "C"

// IOC 匹配
func (m *IOCMatcher) CheckHash(sha256 string) (*IOCMatch, error) {
    cHash := C.CString(sha256)
    defer C.free(unsafe.Pointer(cHash))
    
    result := C.ioc_check_hash(m.handle, cHash)
    if result.found == 0 {
        return nil, nil
    }
    
    return &IOCMatch{
        Threat:     C.GoString(result.threat),
        Confidence: Confidence(result.confidence),
        Tags:       strings.Split(C.GoString(result.tags), ","),
    }, nil
}

// Sigma 匹配
func (e *SigmaEngine) MatchEvent(event map[string]interface{}) ([]SigmaMatch, error) {
    jsonBytes, err := json.Marshal(event)
    if err != nil {
        return nil, err
    }
    
    cJson := C.CString(string(jsonBytes))
    defer C.free(unsafe.Pointer(cJson))
    
    result := C.sigma_match_event(e.handle, cJson)
    // 解析结果...
}

// YARA 扫描
func (s *YARAScanner) ScanFile(path string) ([]YARAMatch, error) {
    cPath := C.CString(path)
    defer C.free(unsafe.Pointer(cPath))
    
    result := C.yara_scan_file(s.handle, cPath)
    // 解析结果...
}
```

```rust
// Rust 侧导出
#[no_mangle]
pub extern "C" fn ioc_check_hash(
    matcher: *const IOCMatcher,
    hash: *const c_char,
) -> CIOCResult {
    // ...
}

#[no_mangle]
pub extern "C" fn sigma_match_event(
    engine: *const SigmaEngine,
    event_json: *const c_char,
) -> CSigmaResult {
    // ...
}

#[no_mangle]
pub extern "C" fn yara_scan_file(
    scanner: *const YARAScanner,
    path: *const c_char,
) -> CYARAResult {
    // ...
}
```

---

## 6. 配置文件设计

### 6.1 主配置文件

```ini
# IntrusionScope 配置文件
# 位置: ~/.intrusionscope.conf 或 /etc/intrusionscope/intrusionscope.conf

[general]
# 默认采集模式
mode = standard

# 输出目录
output_dir = ./intrusionscope_output

# 日志级别: debug, info, warn, error
log_level = info

# 彩色输出: auto, always, never
color = auto

# 语言: zh, en
language = zh

[collection]
# 采集并发线程数
threads = 4

# 单项采集超时(秒)
timeout = 300

# 最大输出文件大小(MB)
max_output_size = 100

# 内存转储
memory_dump = false

[detection]
# 规则库目录
rules_dir = ./rules

# 规则加载模式: minimal, standard, full
rules_mode = standard

# 自动同步规则
auto_sync = true

# 同步间隔(小时)
sync_interval = 24

# YARA 超时(秒)
yara_timeout = 60

# Sigma 规则目录
sigma_dir = ./rules/sigma

[network]
# HTTP 代理
proxy = 

# 代理认证
proxy_auth = 

# 请求超时(秒)
timeout = 30

# 离线模式
offline = false

# 跳过 TLS 验证(不推荐)
insecure = false

[sources]
# 启用的数据源
malwarebazaar = true
urlhaus = true
threatfox = true
dshield = true
spamhaus = true
sigma_hq = true
neo23x0_yara = true
nsql_rds = false

[output]
# 输出格式: json, csv, markdown, html, all
format = all

# 压缩输出
compress = true

# 加密输出
encrypt = false

# 包含时间线 CSV
timeline = true

# 包含 MITRE 映射
mitre_map = true

[analysis]
# 威胁评分阈值
score_threshold = medium

# 误报排除规则文件
false_positives = ./false_positives.yaml

# 白名单文件
whitelist = ./whitelist.yaml
```

### 6.2 Playbook 配置

```yaml
# Playbook: 自定义采集场景
name: lateral_movement_investigation
description: 横向移动调查 Playbook
version: 1.0.0

# 目标平台
platforms: [windows, linux]

# 采集阶段
stages:
  - name: volatile_data
    description: 易失性数据采集
    priority: 1
    artifacts:
      - process.list
      - process.tree
      - network.connections
      - network.listeners

  - name: persistence_check
    description: 持久化机制检查
    priority: 2
    artifacts:
      - scheduled_tasks.list
      - startup.items
      - registry.run_keys      # Windows only
      - registry.services      # Windows only

  - name: lateral_movement
    description: 横向移动痕迹
    priority: 3
    artifacts:
      - eventlog.security
      - eventlog.powershell
      - user.logins
    filters:
      - event_id: [4624, 4625, 4648, 3]  # 登录相关事件

  - name: file_analysis
    description: 文件分析
    priority: 4
    artifacts:
      - filesystem.timeline
      - filesystem.hashes
    parameters:
      paths:
        - /tmp
        - /var/tmp
        - C:\Windows\Temp
        - C:\Users\*\AppData\Local\Temp

# 检测规则
detection:
  sigma_rules:
    - rules/lateral_movement/
  yara_rules:
    - rules/yara/malware/
  ioc_files:
    - custom_iocs.json

# 输出配置
output:
  format: all
  compress: true
  report: detailed
```

---

## 7. 错误码与日志规范

### 7.1 错误码定义

```go
// 错误码定义
const (
    // 成功
    ErrSuccess ErrorCode = 0
    
    // 通用错误 (1-99)
    ErrUnknown           ErrorCode = 1
    ErrInvalidArgument   ErrorCode = 2
    ErrConfigLoad        ErrorCode = 3
    ErrPermissionDenied  ErrorCode = 4
    ErrTimeout           ErrorCode = 5
    ErrInterrupted       ErrorCode = 6
    
    // 采集错误 (100-199)
    ErrCollectionBase        ErrorCode = 100
    ErrCollectionTimeout     ErrorCode = 101
    ErrCollectionPermission  ErrorCode = 102
    ErrCollectionResource    ErrorCode = 103
    ErrCollectionPlatform    ErrorCode = 104
    
    // 检测错误 (200-299)
    ErrDetectionBase         ErrorCode = 200
    ErrRuleLoad              ErrorCode = 201
    ErrRuleCompile           ErrorCode = 202
    ErrRuleMatch             ErrorCode = 203
    ErrYARAScan              ErrorCode = 204
    ErrSigmaMatch            ErrorCode = 205
    
    // 规则同步错误 (300-399)
    ErrSyncBase              ErrorCode = 300
    ErrSyncNetwork           ErrorCode = 301
    ErrSyncDownload          ErrorCode = 302
    ErrSyncChecksum          ErrorCode = 303
    ErrSyncExtract           ErrorCode = 304
    
    // 输出错误 (400-499)
    ErrOutputBase            ErrorCode = 400
    ErrOutputWrite           ErrorCode = 401
    ErrOutputEncrypt         ErrorCode = 402
    ErrOutputCompress        ErrorCode = 403
    
    // 平台错误 (500-599)
    ErrPlatformBase          ErrorCode = 500
    ErrPlatformLinux         ErrorCode = 501
    ErrPlatformWindows       ErrorCode = 502
)

// 错误结构
type Error struct {
    Code      ErrorCode
    Message   string
    Context   map[string]interface{}
    Cause     error
}

func (e *Error) Error() string {
    return fmt.Sprintf("[%d] %s: %v", e.Code, e.Message, e.Cause)
}
```

### 7.2 日志格式规范

```json
{
  "timestamp": "2026-04-15T10:30:00.123Z",
  "level": "info",
  "component": "collector",
  "message": "Starting process collection",
  "context": {
    "hostname": "compromised-host",
    "mode": "standard",
    "pid": 12345
  },
  "duration_ms": 150,
  "trace_id": "abc123-def456"
}
```

**日志级别:**
| 级别 | 说明 | 输出目标 |
|------|------|---------|
| DEBUG | 详细调试信息 | 文件 |
| INFO | 正常操作信息 | 终端 + 文件 |
| WARN | 警告信息 | 终端 + 文件 |
| ERROR | 错误信息 | 终端 + 文件 |
| FATAL | 致命错误 | 终端 + 文件 + 退出 |

**日志轮转策略:**
- 单文件最大: 10MB
- 保留文件数: 5
- 压缩旧日志: 是
- 轮转间隔: 每日

---

## 8. 输出数据模型

### 8.1 统一数据模型

```go
// 进程信息 (跨平台统一)
type ProcessInfo struct {
    // 通用字段
    PID         int       `json:"pid"`
    PPID        int       `json:"ppid"`
    Name        string    `json:"name"`
    Path        string    `json:"path"`
    CmdLine     string    `json:"cmdline"`
    User        string    `json:"user"`
    UID         int       `json:"uid,omitempty"`      // Linux
    GID         int       `json:"gid,omitempty"`      // Linux
    SID         string    `json:"sid,omitempty"`      // Windows
    StartTime   time.Time `json:"start_time"`
    ExeHash     string    `json:"exe_hash,omitempty"`
    
    // 扩展信息
    ParentName  string    `json:"parent_name"`
    Threads     int       `json:"threads"`
    MemoryMB    int64     `json:"memory_mb"`
    CPUPercent  float64   `json:"cpu_percent"`
    
    // 异常标记
    Anomalies   []string  `json:"anomalies,omitempty"`
    RiskScore   int       `json:"risk_score,omitempty"`
    
    // 平台特定
    Platform    string    `json:"platform"`
    PlatformEx  interface{} `json:"platform_ex,omitempty"`
}

// 网络连接信息
type NetworkConnection struct {
    Proto       string    `json:"proto"`
    LocalAddr   string    `json:"local_addr"`
    LocalPort   int       `json:"local_port"`
    RemoteAddr  string    `json:"remote_addr"`
    RemotePort  int       `json:"remote_port"`
    State       string    `json:"state"`
    PID         int       `json:"pid"`
    ProcessName string    `json:"process_name"`
    
    // 异常标记
    IsListening bool     `json:"is_listening"`
    Anomalies   []string `json:"anomalies,omitempty"`
    IOC         *IOCMatch `json:"ioc_match,omitempty"`
}

// 文件信息
type FileInfo struct {
    Path        string    `json:"path"`
    Name        string    `json:"name"`
    Size        int64     `json:"size"`
    Mode        string    `json:"mode"`
    ModTime     time.Time `json:"mtime"`
    AccTime     time.Time `json:"atime"`
    ChangeTime  time.Time `json:"ctime,omitempty"`
    BirthTime   time.Time `json:"btime,omitempty"`
    
    // 哈希
    MD5         string    `json:"md5,omitempty"`
    SHA1        string    `json:"sha1,omitempty"`
    SHA256      string    `json:"sha256,omitempty"`
    
    // 异常标记
    Anomalies   []string  `json:"anomalies,omitempty"`
    IOC         *IOCMatch `json:"ioc_match,omitempty"`
    YARAMatches []YARAMatch `json:"yara_matches,omitempty"`
}
```

### 8.2 检测结果模型

```go
// IOC 匹配结果
type IOCMatch struct {
    Type        string    `json:"type"`        // hash, ip, domain, url, filename
    Value       string    `json:"value"`
    Threat      string    `json:"threat"`
    Confidence  string    `json:"confidence"`  // high, medium, low
    Tags        []string  `json:"tags"`
    Source      string    `json:"source"`      // 数据源
    FirstSeen   time.Time `json:"first_seen"`
}

// Sigma 匹配结果
type SigmaMatch struct {
    RuleID      string                 `json:"rule_id"`
    RuleTitle   string                 `json:"rule_title"`
    RuleLevel   string                 `json:"rule_level"`
    Event       map[string]interface{} `json:"event"`
    MITRE       []string               `json:"mitre"`
    Timestamp   time.Time              `json:"timestamp"`
}

// YARA 匹配结果
type YARAMatch struct {
    RuleID      string            `json:"rule_id"`
    Namespace   string            `json:"namespace"`
    Tags        []string          `json:"tags"`
    Meta        map[string]string `json:"meta"`
    Strings     []MatchedString   `json:"strings"`
    FilePath    string            `json:"file_path"`
}

// 威胁评分
type ThreatScore struct {
    OverallScore  int            `json:"overall_score"`
    RiskLevel     string         `json:"risk_level"`
    Summary       ScoreSummary   `json:"summary"`
    TopFindings   []Finding      `json:"top_findings"`
    MITREHeatmap  map[string]int `json:"mitre_heatmap"`
}

type ScoreSummary struct {
    Critical      int `json:"critical"`
    High          int `json:"high"`
    Medium        int `json:"medium"`
    Low           int `json:"low"`
    Informational int `json:"informational"`
}

type Finding struct {
    Type        string   `json:"type"`
    Severity    string   `json:"severity"`
    Description string   `json:"description"`
    Evidence    string   `json:"evidence"`
    MITRE       []string `json:"mitre"`
    Timestamp   time.Time `json:"timestamp"`
}
```

---

## 9. 性能基准

### 9.1 目标性能指标

| 操作 | 目标 | 测试条件 |
|------|------|---------|
| 工具启动 | < 3s | 冷启动 |
| 规则加载 (minimal) | < 2s | 核心规则 (~1000 条) |
| 规则加载 (standard) | < 10s | 标准规则 (~5000 条) |
| 规则加载 (full) | < 30s | 全量规则 (~100 万哈希) |
| 进程采集 | < 5s | 500 进程 |
| 网络采集 | < 3s | 200 连接 |
| 文件时间线 | < 30s | 10000 文件 |
| EVTX 解析 | < 10s | 1GB 日志 |
| Sigma 匹配 | < 5s | 1GB 日志 + 5000 规则 |
| YARA 扫描 | < 60s | 1000 文件 + 300 规则 |
| 哈希计算 | < 10s | 1000 文件 (平均 1MB) |

### 9.2 内存使用目标

| 组件 | 内存上限 |
|------|---------|
| 主程序 | 64MB |
| 规则索引 (minimal) | 32MB |
| 规则索引 (standard) | 128MB |
| 规则索引 (full) | 512MB |
| Bloom Filter | 16MB |
| 采集缓冲 | 32MB |
| **总计 (standard)** | **~256MB** |

---

## 10. 安全设计

### 10.1 工具安全

- **代码签名**: 发布版本使用 GPG 签名
- **哈希校验**: 发布包提供 SHA256 校验和
- **无后门**: 开源审计,无隐藏功能
- **最小权限**: 仅请求必要权限

### 10.2 数据安全

- **加密输出**: AES-256-GCM 加密
- **凭证脱敏**: 敏感信息不记录明文
- **代理认证**: 不持久化代理密码
- **传输安全**: HTTPS 下载规则

### 10.3 运行安全

- **只读操作**: 默认不修改系统
- **自清理**: 可选清理执行痕迹
- **资源限制**: 防止资源耗尽
- **超时控制**: 防止无限等待

---

## 11. 扩展接口

### 11.1 插件接口

```go
// 采集器插件接口
type CollectorPlugin interface {
    // 插件信息
    Name() string
    Version() string
    Platform() Platform
    
    // 初始化
    Init(config map[string]interface{}) error
    
    // 采集执行
    Collect(ctx context.Context) ([]interface{}, error)
    
    // 清理
    Close() error
}

// 检测器插件接口
type DetectorPlugin interface {
    Name() string
    Version() string
    
    Init(rules []byte) error
    Detect(data interface{}) ([]Match, error)
    Close() error
}
```

### 11.2 输出插件接口

```go
// 输出处理器接口
type OutputHandler interface {
    Name() string
    
    Write(data interface{}) error
    Flush() error
    Close() error
}

// 报告生成器接口
type ReportGenerator interface {
    Name() string
    
    Generate(results *CollectionResult) ([]byte, error)
    Format() string  // markdown, html, pdf, etc.
}
```

---

**文档版本**: v0.3
**创建日期**: 2026-04-15
**最后更新**: 2026-04-15
**状态**: 完善版 - 修复编码问题，补充 IFQL 语法、Artifact Schema、配置格式、错误码规范
