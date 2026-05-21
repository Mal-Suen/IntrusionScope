# Artifact Schema 规范

**IntrusionScope Artifact 定义格式**

**版本**: v0.4  
**更新日期**: 2026-05-21  
**作者**: Mal-Suen

---

## 目录

1. [概述](#1-概述)
2. [Artifact 结构](#2-artifact-结构)
3. [元数据定义](#3-元数据定义)
4. [参数定义](#4-参数定义)
5. [数据源定义](#5-数据源定义)
6. [分析规则](#6-分析规则)
7. [输出配置](#7-输出配置)
8. [完整示例](#8-完整示例)
9. [内置 Artifact 参考](#9-内置-artifact-参考)
10. [最佳实践](#10-最佳实践)

---

## 1. 概述

### 1.1 什么是 Artifact？

**Artifact** 是 IntrusionScope 中定义取证数据采集和分析的基本单元。每个 Artifact 描述：

- **采集什么**: 数据源和采集方法
- **如何采集**: 参数配置和执行条件
- **如何分析**: 检测规则和可疑行为判定
- **输出什么**: 结果格式和字段定义

### 1.2 设计理念

借鉴 Velociraptor 的 Artifact 设计：

- **声明式**: 描述期望结果，而非执行步骤
- **可组合**: 支持引用和组合其他 Artifact
- **可扩展**: 支持自定义参数和规则
- **跨平台**: 统一格式，平台特定实现

### 1.3 文件格式

- **格式**: YAML
- **扩展名**: `.yaml`
- **位置**: `artifacts/builtin/` 或 `artifacts/custom/`

---

## 2. Artifact 结构

### 2.1 基本结构

```yaml
# Artifact 定义文件
name: artifact.name
version: "1.0"
description: "Artifact 描述"
author: "作者"
reference: "https://..."

# 支持的平台
supported_os:
  - linux
  - windows

# 参数定义
parameters:
  - name: param1
    type: string
    default: "value"
    description: "参数说明"

# 数据源定义
sources:
  - name: source1
    query: |
      SELECT * FROM ...

# 分析规则
analysis:
  - name: rule1
    type: suspicious
    condition: field LIKE '%pattern%'

# 输出配置
output:
  format: json
  fields:
    - field1
    - field2
```

### 2.2 结构元素

| 元素 | 必需 | 说明 |
|------|------|------|
| `name` | ✓ | Artifact 唯一标识 |
| `version` | ✓ | 版本号 |
| `description` | ✓ | 功能描述 |
| `author` | ✗ | 作者信息 |
| `supported_os` | ✓ | 支持的平台 |
| `parameters` | ✗ | 参数列表 |
| `sources` | ✓ | 数据源定义 |
| `analysis` | ✗ | 分析规则 |
| `output` | ✗ | 输出配置 |

---

## 3. 元数据定义

### 3.1 基本信息

```yaml
name: process.list                    # Artifact 名称 (必需)
version: "1.0"                        # 版本号 (必需)
description: "采集运行进程列表"        # 功能描述 (必需)
author: "Mal-Suen"                    # 作者
reference: "https://..."              # 参考链接
tags:                                 # 标签
  - forensic
  - process
  - t1057
```

### 3.2 名称规范

Artifact 名称采用 `<category>.<artifact>` 格式：

| 类别 | 前缀 | 示例 |
|------|------|------|
| 进程 | `process.` | `process.list`, `process.tree` |
| 网络 | `network.` | `network.connections` |
| 文件系统 | `filesystem.` | `filesystem.recent_files` |
| 日志 | `log.` | `log.auth`, `log.syslog` |
| 注册表 | `registry.` | `registry.run_keys` |
| 用户 | `users.` | `users.list` |

### 3.3 平台支持

```yaml
# 支持多平台
supported_os:
  - linux
  - windows

# 仅支持 Linux
supported_os:
  - linux

# 仅支持 Windows
supported_os:
  - windows
```

---

## 4. 参数定义

### 4.1 参数类型

| 类型 | 说明 | 示例 |
|------|------|------|
| `string` | 字符串 | `"C:\Windows"` |
| `int` | 整数 | `100` |
| `bool` | 布尔 | `true` |
| `float` | 浮点数 | `0.5` |
| `string_array` | 字符串数组 | `["a", "b", "c"]` |
| `int_array` | 整数数组 | `[80, 443, 8080]` |

### 4.2 参数定义

```yaml
parameters:
  # 字符串参数
  - name: directory
    type: string
    default: "/var/log"
    description: "扫描目录"
    
  # 整数参数
  - name: limit
    type: int
    default: 1000
    description: "结果限制"
    
  # 布尔参数
  - name: include_hidden
    type: bool
    default: false
    description: "包含隐藏文件"
    
  # 数组参数
  - name: extensions
    type: string_array
    default:
      - ".exe"
      - ".dll"
      - ".bat"
    description: "文件扩展名过滤"
    
  # 枚举参数
  - name: severity
    type: string
    default: "medium"
    description: "严重级别"
    allowed_values:
      - "low"
      - "medium"
      - "high"
      - "critical"
```

### 4.3 参数验证

```yaml
parameters:
  - name: port
    type: int
    default: 80
    description: "端口号"
    validation:
      min: 1
      max: 65535
      
  - name: path
    type: string
    default: "/tmp"
    description: "文件路径"
    validation:
      regex: "^/[a-zA-Z0-9/_-]+$"
```

---

## 5. 数据源定义

### 5.1 单数据源

```yaml
sources:
  - name: default
    query: |
      SELECT 
        pid,
        name,
        exe,
        cmdline,
        user
      FROM process.list
```

### 5.2 条件数据源

根据平台选择不同查询：

```yaml
sources:
  # Linux 数据源
  - name: linux_source
    os: linux
    query: |
      SELECT 
        pid,
        name,
        exe,
        cmdline,
        user,
        uid
      FROM process.list
      
  # Windows 数据源
  - name: windows_source
    os: windows
    query: |
      SELECT 
        pid,
        name,
        exe,
        cmdline,
        user,
        domain
      FROM process.list
```

### 5.3 参数化数据源

使用参数动态构建查询：

```yaml
parameters:
  - name: target_user
    type: string
    default: ""
    description: "目标用户 (空=所有)"

sources:
  - name: filtered
    query: |
      SELECT * FROM process.list
      {{ if .target_user }}
      WHERE user = '{{ .target_user }}'
      {{ end }}
```

### 5.4 预处理

```yaml
sources:
  - name: default
    query: |
      SELECT * FROM process.list
    preprocess: |
      # 预处理脚本
      echo "Starting collection..."
    postprocess: |
      # 后处理脚本
      echo "Collection complete"
```

---

## 6. 分析规则

### 6.1 规则类型

| 类型 | 说明 | 严重级别 |
|------|------|----------|
| `suspicious` | 可疑行为 | medium |
| `malicious` | 恶意行为 | high |
| `info` | 信息提示 | low |
| `benign` | 良性标记 | info |

### 6.2 规则定义

```yaml
analysis:
  # 可疑进程名
  - name: suspicious_process_name
    type: suspicious
    severity: high
    condition: name IN ('mimikatz.exe', 'procdump.exe', 'pwdump.exe')
    message: "检测到可疑进程名"
    mitre:
      - T1003
      
  # 可疑命令行
  - name: suspicious_cmdline
    type: suspicious
    severity: high
    condition: |
      cmdline LIKE '%-enc%' OR
      cmdline LIKE '%downloadstring%' OR
      cmdline LIKE '%iex%' OR
      cmdline LIKE '%bypass%'
    message: "检测到可疑 PowerShell 命令"
    mitre:
      - T1059.001
      
  # 可疑路径
  - name: suspicious_path
    type: suspicious
    severity: medium
    condition: |
      exe LIKE '%Temp%' OR
      exe LIKE '%AppData%' OR
      exe LIKE '%Public%'
    message: "进程从可疑路径执行"
```

### 6.3 复合条件

```yaml
analysis:
  # 多条件组合
  - name: encoded_powershell
    type: malicious
    severity: critical
    condition: |
      name LIKE '%powershell%' AND (
        cmdline LIKE '%-enc%' OR
        cmdline LIKE '%encodedcommand%'
      )
    message: "检测到编码的 PowerShell 命令"
    mitre:
      - T1059.001
    references:
      - "https://attack.mitre.org/techniques/T1059/001/"
```

### 6.4 白名单规则

```yaml
analysis:
  # 排除良性进程
  - name: benign_system_process
    type: benign
    condition: |
      name IN ('system', 'init', 'launchd', 'smss.exe', 'csrss.exe')
    message: "系统进程"
```

---

## 7. 输出配置

### 7.1 输出格式

```yaml
output:
  format: json          # json, csv, table
  pretty: true          # 格式化输出
  include_metadata: true # 包含元数据
```

### 7.2 字段选择

```yaml
output:
  fields:
    - pid
    - name
    - exe
    - cmdline
    - user
    - analysis_result    # 分析结果字段
```

### 7.3 字段重命名

```yaml
output:
  field_aliases:
    pid: process_id
    exe: executable_path
    cmdline: command_line
```

### 7.4 输出模板

```yaml
output:
  template: |
    {{ range . }}
    [{{ .severity }}] {{ .name }} (PID: {{ .pid }})
      Path: {{ .exe }}
      Command: {{ .cmdline }}
      User: {{ .user }}
    {{ end }}
```

---

## 8. 完整示例

### 8.1 进程列表 Artifact

```yaml
name: process.list
version: "1.0"
description: "采集运行进程列表，检测可疑进程"
author: "Mal-Suen"
reference: "https://attack.mitre.org/techniques/T1057/"
tags:
  - forensic
  - process
  - t1057

supported_os:
  - linux
  - windows

parameters:
  - name: include_cmdline
    type: bool
    default: true
    description: "包含命令行参数"
    
  - name: suspicious_names
    type: string_array
    default:
      - "mimikatz"
      - "procdump"
      - "pwdump"
      - "wce"
      - "psexec"
      - "nc"
      - "ncat"
    description: "可疑进程名列表"
    
  - name: max_results
    type: int
    default: 10000
    description: "最大结果数"

sources:
  - name: linux_processes
    os: linux
    query: |
      SELECT 
        pid,
        ppid,
        name,
        exe,
        cmdline,
        user,
        uid,
        gid,
        memory_mb,
        cpu_percent,
        threads,
        start_time
      FROM process.list
      LIMIT {{ .max_results }}
      
  - name: windows_processes
    os: windows
    query: |
      SELECT 
        pid,
        ppid,
        name,
        exe,
        cmdline,
        user,
        domain,
        memory_mb,
        cpu_percent,
        threads,
        handles,
        start_time
      FROM process.list
      LIMIT {{ .max_results }}

analysis:
  - name: suspicious_name
    type: suspicious
    severity: high
    condition: |
      LOWER(name) IN ({{ range $i, $v := .suspicious_names }}{{ if $i }},{{ end }}LOWER('{{$v}}'){{ end }})
    message: "检测到可疑进程名: {{ .name }}"
    mitre:
      - T1003
      
  - name: encoded_powershell
    type: malicious
    severity: critical
    condition: |
      LOWER(name) LIKE '%powershell%' AND (
        LOWER(cmdline) LIKE '%-enc%' OR
        LOWER(cmdline) LIKE '%-encodedcommand%'
      )
    message: "检测到编码的 PowerShell 命令"
    mitre:
      - T1059.001
      
  - name: suspicious_path
    type: suspicious
    severity: medium
    condition: |
      exe LIKE '%Temp%' OR
      exe LIKE '%AppData%' OR
      exe LIKE '%Public%' OR
      exe LIKE '%tmp%'
    message: "进程从可疑路径执行"
    
  - name: no_parent
    type: suspicious
    severity: high
    condition: ppid = 0 AND name NOT IN ('system', 'init', 'launchd')
    message: "无父进程的异常进程"

output:
  format: json
  fields:
    - pid
    - ppid
    - name
    - exe
    - cmdline
    - user
    - memory_mb
    - cpu_percent
    - start_time
    - analysis_result
```

### 8.2 网络连接 Artifact

```yaml
name: network.connections
version: "1.0"
description: "采集网络连接，检测可疑外连"
author: "Mal-Suen"
reference: "https://attack.mitre.org/techniques/T1071/"
tags:
  - forensic
  - network
  - t1071

supported_os:
  - linux
  - windows

parameters:
  - name: suspicious_ports
    type: int_array
    default:
      - 4444
      - 5555
      - 6666
      - 7777
      - 8888
      - 9999
    description: "可疑端口列表"
    
  - name: private_ranges
    type: string_array
    default:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
      - "127.0.0.0/8"
    description: "内网 IP 范围"

sources:
  - name: connections
    query: |
      SELECT 
        protocol,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        state,
        pid,
        process_name
      FROM network.connections
      WHERE state IN ('ESTABLISHED', 'LISTEN', 'SYN_SENT')

analysis:
  - name: suspicious_port
    type: suspicious
    severity: high
    condition: |
      remote_port IN ({{ range $i, $v := .suspicious_ports }}{{ if $i }},{{ end }}{{$v}}{{ end }}) OR
      local_port IN ({{ range $i, $v := .suspicious_ports }}{{ if $i }},{{ end }}{{$v}}{{ end }})
    message: "检测到可疑端口连接"
    mitre:
      - T1571
      
  - name: external_connection
    type: info
    severity: medium
    condition: |
      state = 'ESTABLISHED' AND
      remote_ip NOT IN ({{ range $i, $v := .private_ranges }}{{ if $i }},{{ end }}'{{$v}}'{{ end }})
    message: "外网连接"

output:
  format: json
  fields:
    - protocol
    - local_ip
    - local_port
    - remote_ip
    - remote_port
    - state
    - pid
    - process_name
    - analysis_result
```

### 8.3 Windows 持久化 Artifact

```yaml
name: windows.persistence
version: "1.0"
description: "检测 Windows 持久化机制"
author: "Mal-Suen"
reference: "https://attack.mitre.org/tactics/TA0003/"
tags:
  - forensic
  - persistence
  - windows
  - ta0003

supported_os:
  - windows

parameters:
  - name: check_all
    type: bool
    default: true
    description: "检查所有持久化位置"

sources:
  # Run 键
  - name: run_keys
    query: |
      SELECT 
        'registry.run_keys' AS source,
        key AS location,
        name,
        value,
        hive
      FROM registry.run_keys
      
  # 计划任务
  - name: scheduled_tasks
    query: |
      SELECT 
        'filesystem.scheduled_tasks' AS source,
        path AS location,
        name,
        command,
        status
      FROM filesystem.scheduled_tasks
      
  # 服务
  - name: services
    query: |
      SELECT 
        'registry.services' AS source,
        name AS location,
        display_name,
        image_path,
        start_type
      FROM registry.services
      
  # 启动文件夹
  - name: startup
    query: |
      SELECT 
        'registry.startup' AS source,
        location,
        name,
        command
      FROM registry.startup

analysis:
  - name: suspicious_run_key
    type: suspicious
    severity: high
    condition: |
      source = 'registry.run_keys' AND (
        value LIKE '%powershell%' OR
        value LIKE '%cmd%' OR
        value LIKE '%wscript%' OR
        value LIKE '%cscript%' OR
        value LIKE '%http%' OR
        value LIKE '%base64%'
      )
    message: "可疑 Run 键值"
    mitre:
      - T1547.001
      
  - name: suspicious_task
    type: suspicious
    severity: high
    condition: |
      source = 'filesystem.scheduled_tasks' AND (
        command LIKE '%powershell%' OR
        command LIKE '%-enc%' OR
        command LIKE '%download%' OR
        command LIKE '%http%'
      )
    message: "可疑计划任务"
    mitre:
      - T1053.005
      
  - name: suspicious_service
    type: suspicious
    severity: high
    condition: |
      source = 'registry.services' AND (
        image_path LIKE '%Temp%' OR
        image_path LIKE '%AppData%' OR
        image_path LIKE '%Public%'
      )
    message: "可疑服务路径"
    mitre:
      - T1543.003

output:
  format: json
  fields:
    - source
    - location
    - name
    - value
    - command
    - analysis_result
```

---

## 9. 内置 Artifact 参考

### 9.1 进程类

| Artifact | 说明 | 平台 |
|----------|------|------|
| `process.list` | 进程列表 | Linux/Windows |
| `process.tree` | 进程树 | Linux/Windows |
| `process.open_files` | 打开文件 | Linux/Windows |
| `process.memory` | 内存映射 | Linux/Windows |
| `process.modules` | 加载模块 | Linux/Windows |

### 9.2 网络类

| Artifact | 说明 | 平台 |
|----------|------|------|
| `network.connections` | 网络连接 | Linux/Windows |
| `network.listening_ports` | 监听端口 | Linux/Windows |
| `network.dns_cache` | DNS 缓存 | Linux/Windows |
| `network.arp_cache` | ARP 缓存 | Linux/Windows |
| `network.hosts` | Hosts 文件 | Linux/Windows |

### 9.3 文件系统类

| Artifact | 说明 | 平台 |
|----------|------|------|
| `filesystem.recent_files` | 最近文件 | Linux/Windows |
| `filesystem.file_hash` | 文件哈希 | Linux/Windows |
| `filesystem.mft` | MFT 记录 | Windows |
| `filesystem.bash_history` | Bash 历史 | Linux |
| `filesystem.cron_jobs` | Cron 任务 | Linux |
| `filesystem.scheduled_tasks` | 计划任务 | Windows |
| `filesystem.autoruns` | 自启动项 | Linux/Windows |
| `filesystem.suid_files` | SUID 文件 | Linux |

### 9.4 日志类

| Artifact | 说明 | 平台 |
|----------|------|------|
| `log.auth` | 认证日志 | Linux/Windows |
| `log.syslog` | 系统日志 | Linux |
| `log.wtmp` | 登录记录 | Linux |
| `log.audit` | 审计日志 | Linux |
| `log.journal` | Journal 日志 | Linux |
| `log.windows_events` | Windows 事件 | Windows |

### 9.5 注册表类

| Artifact | 说明 | 平台 |
|----------|------|------|
| `registry.run_keys` | Run 键 | Windows |
| `registry.services` | 服务 | Windows |
| `registry.persistence` | 持久化 | Windows |
| `registry.usb_history` | USB 历史 | Windows |
| `registry.user_assist` | UserAssist | Windows |

---

## 10. 最佳实践

### 10.1 命名规范

- 使用小写字母和点分隔
- 遵循 `<category>.<artifact>` 格式
- 名称应描述性且简洁

### 10.2 参数设计

- 提供合理的默认值
- 添加详细的描述
- 使用验证规则确保输入有效

### 10.3 分析规则

- 规则应具体且可操作
- 包含 MITRE ATT&CK 映射
- 避免过多误报

### 10.4 性能考虑

- 使用 LIMIT 限制结果
- 避免复杂正则表达式
- 按需选择字段

### 10.5 文档

- 添加清晰的描述
- 包含参考链接
- 说明参数用途

---

## 附录

### A. YAML 格式说明

```yaml
# 注释以 # 开头

# 字符串
name: "value"

# 多行字符串
query: |
  SELECT *
  FROM table

# 数组
tags:
  - item1
  - item2

# 对象
parameters:
  - name: param1
    value: value1
```

### B. 模板语法

使用 Go 模板语法：

```
{{ .parameter_name }}          # 参数引用
{{ if .condition }}...{{ end }} # 条件判断
{{ range .items }}...{{ end }}  # 循环
{{ .field | lower }}           # 管道操作
```

### C. MITRE ATT&CK 映射

| 战术 | ID | 示例技术 |
|------|-----|----------|
| 侦察 | TA0043 | T1595 |
| 资源开发 | TA0042 | T1583 |
| 初始访问 | TA0001 | T1190 |
| 执行 | TA0002 | T1059 |
| 持久化 | TA0003 | T1547 |
| 权限提升 | TA0004 | T1548 |
| 防御规避 | TA0005 | T1562 |
| 凭据访问 | TA0006 | T1003 |
| 发现 | TA0007 | T1046 |
| 横向移动 | TA0008 | T1021 |
| 收集 | TA0009 | T1560 |
| 命令与控制 | TA0011 | T1071 |
| 数据渗出 | TA0010 | T1041 |
| 影响 | TA0040 | T1486 |

---

*Copyright © 2024-2026 Mal-Suen. Released under MIT License.*