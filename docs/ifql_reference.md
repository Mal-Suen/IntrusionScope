# IFQL 参考手册

**IntrusionScope Forensic Query Language**

**版本**: v0.4  
**更新日期**: 2026-05-21  
**作者**: Mal-Suen

---

## 目录

1. [概述](#1-概述)
2. [语法结构](#2-语法结构)
3. [数据源](#3-数据源)
4. [SELECT 子句](#4-select-子句)
5. [FROM 子句](#5-from-子句)
6. [WHERE 子句](#6-where-子句)
7. [ORDER BY 子句](#7-order-by-子句)
8. [LIMIT 和 OFFSET](#8-limit-和-offset)
9. [GROUP BY 和 HAVING](#9-group-by-和-having)
10. [函数](#10-函数)
11. [表达式](#11-表达式)
12. [实战示例](#12-实战示例)
13. [最佳实践](#13-最佳实践)

---

## 1. 概述

### 1.1 什么是 IFQL？

**IFQL (IntrusionScope Forensic Query Language)** 是一种类 SQL 的查询语言，专门设计用于分析 IntrusionScope 采集的取证数据。

### 1.2 设计目标

- **熟悉性**: 采用 SQL 语法，降低学习成本
- **灵活性**: 支持复杂条件组合和聚合分析
- **性能**: 针对取证数据结构优化
- **可扩展**: 支持自定义函数和数据源

### 1.3 与 SQL 的区别

| 特性 | SQL | IFQL |
|------|-----|------|
| 数据源 | 数据库表 | 采集结果 JSON |
| 存储 | 持久化 | 临时文件 |
| 索引 | 支持 | 不支持 |
| JOIN | 支持 | 不支持 |
| 聚合 | 完整支持 | 基础支持 |
| 子查询 | 支持 | 不支持 |

---

## 2. 语法结构

### 2.1 基本语法

```sql
SELECT <columns>
FROM <source>
[WHERE <conditions>]
[GROUP BY <columns>]
[HAVING <conditions>]
[ORDER BY <column> [ASC|DESC]]
[LIMIT <n> [OFFSET <m>]]
```

### 2.2 语句元素

| 元素 | 必需 | 说明 |
|------|------|------|
| SELECT | ✓ | 选择输出列 |
| FROM | ✓ | 指定数据源 |
| WHERE | ✗ | 过滤条件 |
| GROUP BY | ✗ | 分组聚合 |
| HAVING | ✗ | 分组过滤 |
| ORDER BY | ✗ | 结果排序 |
| LIMIT | ✗ | 结果限制 |
| OFFSET | ✗ | 结果偏移 |

### 2.3 执行顺序

1. FROM - 加载数据源
2. WHERE - 应用过滤条件
3. GROUP BY - 分组
4. HAVING - 分组过滤
5. SELECT - 选择列
6. ORDER BY - 排序
7. LIMIT/OFFSET - 限制结果

---

## 3. 数据源

### 3.1 数据源命名

数据源采用 `<category>.<artifact>` 格式：

```
process.list
network.connections
log.auth
filesystem.recent_files
registry.run_keys
```

### 3.2 可用数据源

#### 进程类

| 数据源 | 说明 | 平台 |
|--------|------|------|
| `process.list` | 进程列表 | Linux/Windows |
| `process.tree` | 进程树 | Linux/Windows |
| `process.open_files` | 打开文件 | Linux/Windows |
| `process.memory` | 内存映射 | Linux/Windows |
| `process.modules` | 加载模块 | Linux/Windows |

#### 网络类

| 数据源 | 说明 | 平台 |
|--------|------|------|
| `network.connections` | 网络连接 | Linux/Windows |
| `network.listening_ports` | 监听端口 | Linux/Windows |
| `network.dns_cache` | DNS 缓存 | Linux/Windows |
| `network.arp_cache` | ARP 缓存 | Linux/Windows |
| `network.hosts` | Hosts 文件 | Linux/Windows |

#### 文件系统类

| 数据源 | 说明 | 平台 |
|--------|------|------|
| `filesystem.recent_files` | 最近文件 | Linux/Windows |
| `filesystem.file_hash` | 文件哈希 | Linux/Windows |
| `filesystem.mft` | MFT 记录 | Windows |
| `filesystem.bash_history` | Bash 历史 | Linux |
| `filesystem.cron_jobs` | Cron 任务 | Linux |
| `filesystem.systemd_services` | Systemd 服务 | Linux |
| `filesystem.scheduled_tasks` | 计划任务 | Windows |
| `filesystem.autoruns` | 自启动项 | Linux/Windows |
| `filesystem.suid_files` | SUID 文件 | Linux |

#### 日志类

| 数据源 | 说明 | 平台 |
|--------|------|------|
| `log.auth` | 认证日志 | Linux/Windows |
| `log.syslog` | 系统日志 | Linux |
| `log.wtmp` | 登录记录 | Linux |
| `log.audit` | 审计日志 | Linux |
| `log.journal` | Journal 日志 | Linux |
| `log.windows_events` | Windows 事件 | Windows |
| `log.web_server` | Web 日志 | Linux/Windows |

#### 注册表类 (Windows)

| 数据源 | 说明 | 平台 |
|--------|------|------|
| `registry.run_keys` | Run 键 | Windows |
| `registry.services` | 服务 | Windows |
| `registry.persistence` | 持久化 | Windows |
| `registry.usb_history` | USB 历史 | Windows |
| `registry.user_assist` | UserAssist | Windows |
| `registry.software` | 软件信息 | Windows |
| `registry.startup` | 启动项 | Windows |

#### 用户类

| 数据源 | 说明 | 平台 |
|--------|------|------|
| `users.list` | 用户列表 | Linux/Windows |
| `users.login_history` | 登录历史 | Linux/Windows |
| `users.groups` | 用户组 | Linux/Windows |

### 3.3 数据源字段

每个数据源有特定的字段，详见 [用户指南 - 采集器参考](user_guide.md#5-采集器参考)。

---

## 4. SELECT 子句

### 4.1 选择所有列

```sql
SELECT * FROM process.list
```

### 4.2 选择特定列

```sql
SELECT name, pid, exe FROM process.list
```

### 4.3 列别名

```sql
SELECT name AS process_name, pid AS process_id FROM process.list
```

### 4.4 表达式列

```sql
SELECT name, pid, memory_mb / 1024 AS memory_gb FROM process.list
```

### 4.5 函数列

```sql
SELECT COUNT(*) AS total, COUNT(DISTINCT user) AS unique_users FROM process.list
```

---

## 5. FROM 子句

### 5.1 单数据源

```sql
SELECT * FROM process.list
```

### 5.2 数据源别名

```sql
SELECT p.name, p.pid FROM process.list AS p
```

---

## 6. WHERE 子句

### 6.1 比较运算符

| 运算符 | 说明 | 示例 |
|--------|------|------|
| `=` | 等于 | `name = 'powershell.exe'` |
| `!=` 或 `<>` | 不等于 | `state != 'ESTABLISHED'` |
| `<` | 小于 | `pid < 1000` |
| `>` | 大于 | `memory_mb > 100` |
| `<=` | 小于等于 | `port <= 1024` |
| `>=` | 大于等于 | `severity >= 3` |

#### 示例

```sql
-- 等于
SELECT * FROM process.list WHERE name = 'cmd.exe'

-- 不等于
SELECT * FROM network.connections WHERE state != 'CLOSED'

-- 数值比较
SELECT * FROM process.list WHERE memory_mb > 100
```

### 6.2 逻辑运算符

| 运算符 | 说明 | 示例 |
|--------|------|------|
| `AND` | 与 | `a AND b` |
| `OR` | 或 | `a OR b` |
| `NOT` | 非 | `NOT a` |

#### 示例

```sql
-- AND
SELECT * FROM process.list WHERE name = 'powershell.exe' AND memory_mb > 50

-- OR
SELECT * FROM process.list WHERE name = 'cmd.exe' OR name = 'powershell.exe'

-- NOT
SELECT * FROM process.list WHERE NOT name = 'system'

-- 组合
SELECT * FROM process.list 
WHERE (name = 'powershell.exe' OR name = 'cmd.exe') 
  AND memory_mb > 50
```

### 6.3 LIKE 运算符

SQL 通配符模式匹配：

| 通配符 | 说明 |
|--------|------|
| `%` | 匹配任意字符序列 |
| `_` | 匹配单个字符 |

#### 示例

```sql
-- 包含
SELECT * FROM process.list WHERE name LIKE '%powershell%'

-- 前缀
SELECT * FROM process.list WHERE exe LIKE 'C:\Windows%'

-- 后缀
SELECT * FROM process.list WHERE name LIKE '%.exe'

-- 单字符
SELECT * FROM process.list WHERE name LIKE 'cmd_.exe'
```

### 6.4 NOT LIKE 运算符

```sql
SELECT * FROM process.list WHERE name NOT LIKE '%system%'
```

### 6.5 IN 运算符

列表包含检查：

```sql
-- 数值列表
SELECT * FROM network.connections WHERE port IN (80, 443, 8080, 8443)

-- 字符列表
SELECT * FROM process.list WHERE name IN ('cmd.exe', 'powershell.exe', 'wmic.exe')

-- NOT IN
SELECT * FROM network.connections WHERE state NOT IN ('CLOSED', 'TIME_WAIT')
```

### 6.6 BETWEEN 运算符

范围检查：

```sql
-- 数值范围
SELECT * FROM process.list WHERE pid BETWEEN 100 AND 500

-- 时间范围
SELECT * FROM log.auth WHERE timestamp BETWEEN '2024-01-01' AND '2024-01-31'
```

### 6.7 IS NULL / IS NOT NULL

空值检查：

```sql
-- 空值
SELECT * FROM process.list WHERE exe IS NULL

-- 非空
SELECT * FROM process.list WHERE cmdline IS NOT NULL
```

### 6.8 正则表达式

使用 `REGEXP` 或 `RLIKE`：

```sql
SELECT * FROM process.list WHERE cmdline REGEXP '.*base64.*'

SELECT * FROM process.list WHERE name RLIKE '^[a-z]+\.exe$'
```

---

## 7. ORDER BY 子句

### 7.1 单列排序

```sql
-- 升序 (默认)
SELECT * FROM process.list ORDER BY pid

-- 降序
SELECT * FROM process.list ORDER BY memory_mb DESC
```

### 7.2 多列排序

```sql
SELECT * FROM process.list ORDER BY user ASC, memory_mb DESC
```

### 7.3 表达式排序

```sql
SELECT * FROM process.list ORDER BY memory_mb + cpu_percent DESC
```

---

## 8. LIMIT 和 OFFSET

### 8.1 LIMIT

限制结果数量：

```sql
-- 限制 10 条
SELECT * FROM process.list LIMIT 10

-- 限制 100 条
SELECT * FROM log.auth LIMIT 100
```

### 8.2 OFFSET

跳过指定数量：

```sql
-- 跳过前 10 条，取 20 条
SELECT * FROM process.list LIMIT 20 OFFSET 10

-- 分页示例 (第 3 页，每页 50 条)
SELECT * FROM log.auth LIMIT 50 OFFSET 100
```

---

## 9. GROUP BY 和 HAVING

### 9.1 GROUP BY

分组聚合：

```sql
-- 按用户分组计数
SELECT user, COUNT(*) AS process_count 
FROM process.list 
GROUP BY user

-- 按状态分组
SELECT state, COUNT(*) AS count 
FROM network.connections 
GROUP BY state

-- 多列分组
SELECT user, name, COUNT(*) AS count 
FROM process.list 
GROUP BY user, name
```

### 9.2 HAVING

分组过滤：

```sql
-- 筛选进程数大于 10 的用户
SELECT user, COUNT(*) AS process_count 
FROM process.list 
GROUP BY user 
HAVING process_count > 10

-- 筛选失败登录超过 5 次的 IP
SELECT source_ip, COUNT(*) AS failed_attempts 
FROM log.auth 
WHERE type = 'failed_login' 
GROUP BY source_ip 
HAVING failed_attempts > 5
```

---

## 10. 函数

### 10.1 聚合函数

| 函数 | 说明 | 示例 |
|------|------|------|
| `COUNT(*)` | 总行数 | `COUNT(*)` |
| `COUNT(col)` | 非空行数 | `COUNT(name)` |
| `COUNT(DISTINCT col)` | 唯一值数 | `COUNT(DISTINCT user)` |
| `SUM(col)` | 求和 | `SUM(memory_mb)` |
| `AVG(col)` | 平均值 | `AVG(memory_mb)` |
| `MIN(col)` | 最小值 | `MIN(pid)` |
| `MAX(col)` | 最大值 | `MAX(pid)` |

#### 示例

```sql
-- 总进程数
SELECT COUNT(*) AS total FROM process.list

-- 唯一用户数
SELECT COUNT(DISTINCT user) AS unique_users FROM process.list

-- 平均内存
SELECT AVG(memory_mb) AS avg_memory FROM process.list

-- 最大 PID
SELECT MAX(pid) AS max_pid FROM process.list
```

### 10.2 字符串函数

| 函数 | 说明 | 示例 |
|------|------|------|
| `LOWER(s)` | 转小写 | `LOWER(name)` |
| `UPPER(s)` | 转大写 | `UPPER(name)` |
| `LENGTH(s)` | 字符串长度 | `LENGTH(cmdline)` |
| `SUBSTR(s, start, len)` | 子串 | `SUBSTR(name, 1, 4)` |
| `CONCAT(s1, s2, ...)` | 连接 | `CONCAT(name, ':', pid)` |
| `TRIM(s)` | 去空格 | `TRIM(name)` |
| `REPLACE(s, old, new)` | 替换 | `REPLACE(path, 'C:', 'D:')` |

#### 示例

```sql
-- 转小写
SELECT LOWER(name) FROM process.list

-- 字符串长度
SELECT name, LENGTH(cmdline) AS cmdline_len FROM process.list

-- 连接
SELECT CONCAT(name, ' (PID: ', pid, ')') AS process_info FROM process.list
```

### 10.3 数值函数

| 函数 | 说明 | 示例 |
|------|------|------|
| `ABS(n)` | 绝对值 | `ABS(memory_mb)` |
| `ROUND(n, d)` | 四舍五入 | `ROUND(memory_mb, 2)` |
| `FLOOR(n)` | 向下取整 | `FLOOR(memory_mb)` |
| `CEIL(n)` | 向上取整 | `CEIL(memory_mb)` |
| `MOD(n, m)` | 取模 | `MOD(pid, 100)` |

#### 示例

```sql
-- 四舍五入
SELECT name, ROUND(memory_mb, 2) AS memory FROM process.list

-- 取模
SELECT pid, MOD(pid, 100) AS pid_mod FROM process.list
```

### 10.4 时间函数

| 函数 | 说明 | 示例 |
|------|------|------|
| `YEAR(ts)` | 年 | `YEAR(timestamp)` |
| `MONTH(ts)` | 月 | `MONTH(timestamp)` |
| `DAY(ts)` | 日 | `DAY(timestamp)` |
| `HOUR(ts)` | 时 | `HOUR(timestamp)` |
| `MINUTE(ts)` | 分 | `MINUTE(timestamp)` |
| `SECOND(ts)` | 秒 | `SECOND(timestamp)` |
| `DATE(ts)` | 日期部分 | `DATE(timestamp)` |
| `TIME(ts)` | 时间部分 | `TIME(timestamp)` |
| `NOW()` | 当前时间 | `NOW()` |
| `DATEDIFF(ts1, ts2)` | 日期差 | `DATEDIFF(end, start)` |

#### 示例

```sql
-- 按小时分组
SELECT HOUR(timestamp) AS hour, COUNT(*) AS events 
FROM log.auth 
GROUP BY hour

-- 日期范围
SELECT * FROM log.auth 
WHERE DATE(timestamp) = '2024-01-15'

-- 时间差
SELECT * FROM process.list 
WHERE DATEDIFF(NOW(), start_time) < 1
```

### 10.5 条件函数

| 函数 | 说明 | 示例 |
|------|------|------|
| `COALESCE(v1, v2, ...)` | 返回第一个非空值 | `COALESCE(exe, name)` |
| `IFNULL(v, default)` | 空值替换 | `IFNULL(cmdline, 'N/A')` |
| `CASE WHEN ... THEN ... END` | 条件表达式 | 见示例 |

#### CASE 示例

```sql
-- 简单 CASE
SELECT name,
  CASE state
    WHEN 'ESTABLISHED' THEN 'Active'
    WHEN 'LISTEN' THEN 'Listening'
    ELSE 'Other'
  END AS status
FROM network.connections

-- 搜索 CASE
SELECT name,
  CASE
    WHEN memory_mb > 500 THEN 'High'
    WHEN memory_mb > 100 THEN 'Medium'
    ELSE 'Low'
  END AS memory_level
FROM process.list
```

---

## 11. 表达式

### 11.1 算术表达式

| 运算符 | 说明 | 示例 |
|--------|------|------|
| `+` | 加 | `memory_mb + 10` |
| `-` | 减 | `memory_mb - 10` |
| `*` | 乘 | `memory_mb * 2` |
| `/` | 除 | `memory_mb / 1024` |
| `%` | 取模 | `pid % 100` |

### 11.2 字符串表达式

```sql
-- 字符串连接
SELECT name || ' (' || pid || ')' AS info FROM process.list

-- 或使用 CONCAT
SELECT CONCAT(name, ' (', pid, ')') AS info FROM process.list
```

### 11.3 嵌套表达式

```sql
-- 嵌套算术
SELECT (memory_mb * 100) / total_memory AS percent FROM process.list

-- 嵌套函数
SELECT ROUND(AVG(memory_mb), 2) AS avg_memory FROM process.list
```

---

## 12. 实战示例

### 12.1 进程分析

```sql
-- 查找可疑 PowerShell 进程
SELECT * FROM process.list 
WHERE name LIKE '%powershell%' 
  AND (cmdline LIKE '%enc%' OR cmdline LIKE '%download%')

-- 查找无父进程的异常进程
SELECT * FROM process.list 
WHERE ppid = 0 AND name NOT IN ('system', 'init', 'launchd')

-- 查找高内存进程
SELECT name, pid, user, memory_mb 
FROM process.list 
WHERE memory_mb > 100 
ORDER BY memory_mb DESC 
LIMIT 20

-- 按用户统计进程
SELECT user, COUNT(*) AS count, SUM(memory_mb) AS total_memory 
FROM process.list 
GROUP BY user 
ORDER BY count DESC

-- 查找可疑命令行
SELECT name, pid, cmdline 
FROM process.list 
WHERE cmdline REGEXP '(base64|iex|download|bypass|hidden)'
```

### 12.2 网络分析

```sql
-- 查找外连
SELECT * FROM network.connections 
WHERE state = 'ESTABLISHED' 
  AND remote_ip NOT LIKE '10.%'
  AND remote_ip NOT LIKE '172.1[6-9].%'
  AND remote_ip NOT LIKE '172.2[0-9].%'
  AND remote_ip NOT LIKE '172.3[0-1].%'
  AND remote_ip NOT LIKE '192.168.%'

-- 查找可疑端口
SELECT * FROM network.connections 
WHERE remote_port IN (4444, 5555, 6666, 7777, 8888, 9999)
  OR local_port IN (4444, 5555, 6666, 7777, 8888, 9999)

-- 查找监听端口
SELECT * FROM network.listening_ports 
WHERE port < 1024 OR port > 49152

-- 按进程统计连接
SELECT process_name, COUNT(*) AS connections 
FROM network.connections 
WHERE state = 'ESTABLISHED' 
GROUP BY process_name 
ORDER BY connections DESC
```

### 12.3 日志分析

```sql
-- 查找失败登录
SELECT user, source_ip, timestamp 
FROM log.auth 
WHERE type = 'failed_login' 
ORDER BY timestamp DESC 
LIMIT 100

-- 统计暴力破解
SELECT source_ip, user, COUNT(*) AS attempts 
FROM log.auth 
WHERE type = 'failed_login' 
GROUP BY source_ip, user 
HAVING attempts > 5 
ORDER BY attempts DESC

-- 查找异常时间登录
SELECT * FROM log.auth 
WHERE type = 'login' 
  AND HOUR(timestamp) BETWEEN 0 AND 5

-- 查找 sudo 使用
SELECT user, timestamp, message 
FROM log.auth 
WHERE type = 'sudo' 
ORDER BY timestamp DESC
```

### 12.4 文件系统分析

```sql
-- 查找最近修改的可执行文件
SELECT * FROM filesystem.recent_files 
WHERE path LIKE '%.exe' 
  AND mtime > DATE('now', '-7 days')

-- 查找可疑路径
SELECT * FROM filesystem.recent_files 
WHERE path LIKE '%Temp%' 
  OR path LIKE '%AppData%'
  OR path LIKE '%startup%'

-- 查找大文件
SELECT path, size 
FROM filesystem.recent_files 
WHERE size > 100000000 
ORDER BY size DESC
```

### 12.5 注册表分析 (Windows)

```sql
-- 查找可疑 Run 键
SELECT * FROM registry.run_keys 
WHERE value LIKE '%powershell%' 
  OR value LIKE '%cmd%'
  OR value LIKE '%http%'

-- 查找可疑服务
SELECT * FROM registry.services 
WHERE image_path LIKE '%Temp%'
  OR image_path LIKE '%AppData%'
```

### 12.6 综合分析

```sql
-- 结合进程和网络
-- (注意: IFQL 不支持 JOIN，需分步查询)

-- 步骤 1: 找可疑进程
SELECT pid, name FROM process.list WHERE name LIKE '%powershell%'

-- 步骤 2: 查进程的网络连接
SELECT * FROM network.connections WHERE pid IN (1234, 5678)

-- 步骤 3: 查进程打开的文件
SELECT * FROM process.open_files WHERE pid IN (1234, 5678)
```

---

## 13. 最佳实践

### 13.1 性能优化

| 建议 | 说明 |
|------|------|
| 先过滤后排序 | WHERE 在 ORDER BY 前执行 |
| 使用 LIMIT | 避免返回大量数据 |
| 避免复杂正则 | 正则表达式性能开销大 |
| 选择必要列 | 避免 SELECT * |

### 13.2 查询技巧

```sql
-- 好的做法
SELECT name, pid, cmdline FROM process.list 
WHERE name LIKE '%powershell%' 
LIMIT 100

-- 避免
SELECT * FROM process.list 
WHERE cmdline REGEXP '.*[a-zA-Z0-9+/=]{100,}.*'
```

### 13.3 调试技巧

```sql
-- 先看数据结构
SELECT * FROM process.list LIMIT 1

-- 检查字段值
SELECT DISTINCT state FROM network.connections

-- 检查数据范围
SELECT MIN(pid), MAX(pid), COUNT(*) FROM process.list
```

### 13.4 安全考虑

- 查询不修改原始数据
- 结果仅用于分析
- 敏感数据需妥善保管

---

## 附录

### A. 运算符优先级

| 优先级 | 运算符 |
|--------|--------|
| 1 | `()` |
| 2 | `NOT` |
| 3 | `AND` |
| 4 | `OR` |
| 5 | `=, !=, <, >, <=, >=, LIKE, IN, BETWEEN` |
| 6 | `+, -` |
| 7 | `*, /, %` |

### B. 数据类型

| 类型 | 说明 | 示例 |
|------|------|------|
| STRING | 字符串 | `'powershell.exe'` |
| INT | 整数 | `1234` |
| FLOAT | 浮点数 | `123.45` |
| BOOL | 布尔 | `true`, `false` |
| TIMESTAMP | 时间戳 | `'2024-01-15T10:30:00Z'` |
| NULL | 空值 | `NULL` |

### C. 关键字列表

```
SELECT, FROM, WHERE, AND, OR, NOT, IN, LIKE, BETWEEN,
IS, NULL, AS, ORDER, BY, ASC, DESC, LIMIT, OFFSET,
GROUP, HAVING, COUNT, SUM, AVG, MIN, MAX, DISTINCT,
CASE, WHEN, THEN, ELSE, END, REGEXP, RLIKE
```

---

*Copyright © 2024-2026 Mal-Suen. Released under MIT License.*