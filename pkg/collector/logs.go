// Package collector 提供取证工件收集能力
// 本文件包含日志相关的收集器实现
package collector

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// LogAuthCollector 认证日志收集器，收集 auth.log/secure 日志
type LogAuthCollector struct{}

// Name 返回收集器名称
func (c *LogAuthCollector) Name() string {
	return "log.auth"
}

// Description 返回收集器描述
func (c *LogAuthCollector) Description() string {
	return "Collects authentication logs (auth.log / secure)"
}

// Platform 返回支持的平台（仅 Linux）
func (c *LogAuthCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *LogAuthCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集认证日志
func (c *LogAuthCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 认证日志位置
	authLogs := []string{
		"/var/log/auth.log",
		"/var/log/auth.log.1",
		"/var/log/secure",
		"/var/log/secure.1",
	}

	for _, logPath := range authLogs {
		c.readLogFile(logPath, "auth", &records)
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}

// LogSyslogCollector Syslog 收集器，收集系统日志条目
type LogSyslogCollector struct{}

// Name 返回收集器名称
func (c *LogSyslogCollector) Name() string {
	return "log.syslog"
}

// Description 返回收集器描述
func (c *LogSyslogCollector) Description() string {
	return "Collects syslog entries"
}

// Platform 返回支持的平台（仅 Linux）
func (c *LogSyslogCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *LogSyslogCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集 syslog 条目
func (c *LogSyslogCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Syslog 位置
	syslogs := []string{
		"/var/log/syslog",
		"/var/log/syslog.1",
		"/var/log/messages",
		"/var/log/messages.1",
	}

	for _, logPath := range syslogs {
		c.readLogFile(logPath, "syslog", &records)
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}

// readLogFile 读取日志文件内容
func (c *LogSyslogCollector) readLogFile(path, source string, records *[]Record) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	var reader io.Reader = file
	// 处理 gzip 压缩的日志文件
	if strings.HasSuffix(path, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return
		}
		defer gzReader.Close()
		reader = gzReader
	}

	scanner := bufio.NewScanner(reader)
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// 解析 syslog 格式：Mon DD HH:MM:SS hostname process[pid]: message
		if record := c.parseSyslogLine(line, path, lineNum, source); record != nil {
			*records = append(*records, *record)
		}
	}
}

// parseSyslogLine 解析 syslog 格式的日志行
func (c *LogSyslogCollector) parseSyslogLine(line, path string, lineNum int, source string) *Record {
	data := map[string]interface{}{
		"source_file": path,
		"line":        lineNum,
		"raw":         line,
	}

	// 尝试解析标准 syslog 格式
	// 示例：Apr 15 10:30:00 hostname process[1234]: message
	parts := strings.SplitN(line, ":", 2)
	if len(parts) >= 2 {
		data["message"] = strings.TrimSpace(parts[1])

		header := parts[0]
		headerParts := strings.Fields(header)
		if len(headerParts) >= 4 {
			// 提取时间戳
			data["timestamp"] = headerParts[0] + " " + headerParts[1] + " " + headerParts[2]
			data["hostname"] = headerParts[3]

			if len(headerParts) >= 5 {
				// 提取进程名和 PID
				processField := headerParts[4]
				if idx := strings.Index(processField, "["); idx != -1 {
					data["process"] = processField[:idx]
					if endIdx := strings.Index(processField, "]"); endIdx != -1 {
						data["pid"] = processField[idx+1 : endIdx]
					}
				} else {
					data["process"] = processField
				}
			}
		}
	}

	return &Record{
		Timestamp: time.Now(),
		Source:    source,
		Data:      data,
	}
}

// LogWtmpCollector 登录历史收集器，从 wtmp/btmp 文件收集登录历史
type LogWtmpCollector struct{}

// Name 返回收集器名称
func (c *LogWtmpCollector) Name() string {
	return "log.wtmp"
}

// Description 返回收集器描述
func (c *LogWtmpCollector) Description() string {
	return "Collects login history from wtmp/btmp files"
}

// Platform 返回支持的平台（仅 Linux）
func (c *LogWtmpCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *LogWtmpCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集登录历史
func (c *LogWtmpCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 使用 last 命令解析 wtmp（成功登录）
	cmd := exec.CommandContext(ctx, "last", "-F", "-x")
	output, err := cmd.Output()
	if err == nil {
		c.parseLastOutput(string(output), "wtmp", &records)
	}

	// 使用 lastb 解析 btmp（失败登录）
	cmd = exec.CommandContext(ctx, "lastb", "-F")
	if output, err := cmd.Output(); err == nil {
		c.parseLastOutput(string(output), "btmp", &records)
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}

// parseLastOutput 解析 last/lastb 命令输出
func (c *LogWtmpCollector) parseLastOutput(output, source string, records *[]Record) {
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "wtmp") || strings.HasPrefix(line, "btmp") {
			continue
		}

		// 解析 last 输出格式
		// 格式：user     pts/0        192.168.1.1     Mon Apr 15 10:00:00 2024 - Mon Apr 15 11:00:00 2024  (01:00)
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			data := map[string]interface{}{
				"user":   fields[0],
				"source": source,
				"raw":    line,
			}

			if len(fields) >= 2 {
				data["terminal"] = fields[1]
			}
			if len(fields) >= 3 {
				data["from"] = fields[2]
			}

			*records = append(*records, Record{
				Timestamp: time.Now(),
				Source:    source,
				Data:      data,
			})
		}
	}
}

// LogAuditCollector Auditd 日志收集器，收集审计日志
type LogAuditCollector struct{}

// Name 返回收集器名称
func (c *LogAuditCollector) Name() string {
	return "log.audit"
}

// Description 返回收集器描述
func (c *LogAuditCollector) Description() string {
	return "Collects auditd logs"
}

// Platform 返回支持的平台（仅 Linux）
func (c *LogAuditCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *LogAuditCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集 auditd 日志
func (c *LogAuditCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 审计日志位置
	auditLogs := []string{
		"/var/log/audit/audit.log",
		"/var/log/audit/audit.log.1",
	}

	for _, logPath := range auditLogs {
		c.readAuditLog(logPath, &records)
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}

// readAuditLog 读取审计日志文件
func (c *LogAuditCollector) readAuditLog(path string, records *[]Record) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		data := map[string]interface{}{
			"source_file": path,
			"raw":         line,
		}

		// 解析 key=value 格式
		// 示例：type=EXECVE msg=audit(1618483800.123:456): argc=3 a0="ls" a1="-la" a2="/tmp"
		if strings.HasPrefix(line, "type=") {
			pairs := strings.Fields(line)
			for _, pair := range pairs {
				if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
					key := kv[0]
					value := strings.Trim(kv[1], "\"")
					data[key] = value
				}
			}
		}

		*records = append(*records, Record{
			Timestamp: time.Now(),
			Source:    "audit",
			Data:      data,
		})
	}
}

// LogJournalCollector Systemd Journal 收集器，收集 systemd 日志条目
type LogJournalCollector struct{}

// Name 返回收集器名称
func (c *LogJournalCollector) Name() string {
	return "log.journal"
}

// Description 返回收集器描述
func (c *LogJournalCollector) Description() string {
	return "Collects systemd journal entries"
}

// Platform 返回支持的平台（仅 Linux）
func (c *LogJournalCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *LogJournalCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集 systemd journal 条目
func (c *LogJournalCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 使用 journalctl 导出日志（JSON 格式）
	cmd := exec.CommandContext(ctx, "journalctl", "-o", "json", "--no-pager", "-n", "1000")
	output, err := cmd.Output()
	if err != nil {
		return &Result{
			Collector: c.Name(),
			Timestamp: start,
			Success:   false,
			Error:     fmt.Sprintf("failed to run journalctl: %v", err),
		}, err
	}

	// 解析 JSON 输出（每行一个 JSON 对象）
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// 暂时存储原始 JSON
		records = append(records, Record{
			Timestamp: time.Now(),
			Source:    "journal",
			Data: map[string]interface{}{
				"json": line,
			},
		})
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}

// LogWindowsEventCollector Windows 事件日志收集器
type LogWindowsEventCollector struct{}

// Name 返回收集器名称
func (c *LogWindowsEventCollector) Name() string {
	return "log.windows_events"
}

// Description 返回收集器描述
func (c *LogWindowsEventCollector) Description() string {
	return "Collects Windows Event Logs"
}

// Platform 返回支持的平台（仅 Windows）
func (c *LogWindowsEventCollector) Platform() string {
	return "windows"
}

// IsAvailable 检查收集器是否可用
func (c *LogWindowsEventCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// Collect 收集 Windows 事件日志
func (c *LogWindowsEventCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 要收集的事件日志
	eventLogs := []string{
		"Security",
		"System",
		"Application",
		"Microsoft-Windows-PowerShell/Operational",
		"Microsoft-Windows-Sysmon/Operational",
	}

	for _, logName := range eventLogs {
		c.collectEventLog(ctx, logName, &records)
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}

// collectEventLog 收集单个事件日志
func (c *LogWindowsEventCollector) collectEventLog(ctx context.Context, logName string, records *[]Record) {
	// 使用 wevtutil 查询事件
	cmd := exec.CommandContext(ctx, "wevtutil", "qe", logName, "/f:Text", "/c:100")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	// 解析文本输出
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var currentEvent map[string]interface{}
	var currentField string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Event[") {
			// 新事件开始
			if currentEvent != nil {
				*records = append(*records, Record{
					Timestamp: time.Now(),
					Source:    logName,
					Data:      currentEvent,
				})
			}
			currentEvent = map[string]interface{}{
				"log": logName,
			}
			continue
		}

		if currentEvent == nil {
			continue
		}

		// 解析字段: 值 格式
		if idx := strings.Index(line, ":"); idx != -1 {
			field := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			currentField = field
			currentEvent[field] = value
		} else if currentField != "" && strings.TrimSpace(line) != "" {
			// 上一字段的续行
			if existing, ok := currentEvent[currentField].(string); ok {
				currentEvent[currentField] = existing + "\n" + strings.TrimSpace(line)
			}
		}
	}

	// 添加最后一个事件
	if currentEvent != nil {
		*records = append(*records, Record{
			Timestamp: time.Now(),
			Source:    logName,
			Data:      currentEvent,
		})
	}
}

// LogWebServerCollector Web 服务器日志收集器，收集访问/错误日志
type LogWebServerCollector struct{}

// Name 返回收集器名称
func (c *LogWebServerCollector) Name() string {
	return "log.webserver"
}

// Description 返回收集器描述
func (c *LogWebServerCollector) Description() string {
	return "Collects web server access/error logs"
}

// Platform 返回支持的平台（仅 Linux）
func (c *LogWebServerCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *LogWebServerCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集 Web 服务器日志
func (c *LogWebServerCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 常见 Web 服务器日志目录
	logDirs := []string{
		"/var/log/nginx",
		"/var/log/apache2",
		"/var/log/httpd",
	}

	for _, dir := range logDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			logPath := filepath.Join(dir, entry.Name())
			c.readWebLog(logPath, &records)
		}
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}

// readWebLog 读取 Web 服务器日志文件
func (c *LogWebServerCollector) readWebLog(path string, records *[]Record) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	var reader io.Reader = file
	// 处理 gzip 压缩的日志文件
	if strings.HasSuffix(path, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return
		}
		defer gzReader.Close()
		reader = gzReader
	}

	scanner := bufio.NewScanner(reader)
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		if line == "" {
			continue
		}

		// 解析通用日志格式或组合日志格式
		data := c.parseWebLogLine(line)
		data["source_file"] = path
		data["line"] = lineNum

		*records = append(*records, Record{
			Timestamp: time.Now(),
			Source:    "webserver",
			Data:      data,
		})
	}
}

// parseWebLogLine 解析 Web 日志行
func (c *LogWebServerCollector) parseWebLogLine(line string) map[string]interface{} {
	data := map[string]interface{}{
		"raw": line,
	}

	// 尝试解析组合日志格式
	// 示例：192.168.1.1 - - [15/Apr/2024:10:00:00 +0000] "GET /path HTTP/1.1" 200 1234 "http://referer" "User-Agent"

	// 简单的无正则解析
	parts := strings.Fields(line)
	if len(parts) >= 7 {
		data["client_ip"] = parts[0]

		// 查找引号之间的请求部分
		if idx := strings.Index(line, "\""); idx != -1 {
			if endIdx := strings.Index(line[idx+1:], "\""); endIdx != -1 {
				request := line[idx+1 : idx+1+endIdx]
				data["request"] = request

				reqParts := strings.Fields(request)
				if len(reqParts) >= 2 {
					data["method"] = reqParts[0]
					data["path"] = reqParts[1]
				}
			}
		}
	}

	return data
}

// readLogFile 读取认证日志文件（LogAuthCollector 的辅助方法）
func (c *LogAuthCollector) readLogFile(path, source string, records *[]Record) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	var reader io.Reader = file
	// 处理 gzip 压缩的日志文件
	if strings.HasSuffix(path, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return
		}
		defer gzReader.Close()
		reader = gzReader
	}

	scanner := bufio.NewScanner(reader)
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		if line == "" {
			continue
		}

		// 解析认证日志
		data := map[string]interface{}{
			"source_file": path,
			"line":        lineNum,
			"raw":         line,
		}

		// 提取有用信息
		if strings.Contains(line, "Failed password") {
			data["type"] = "failed_login"
			// 提取用户名
			if idx := strings.Index(line, "for "); idx != -1 {
				rest := line[idx+4:]
				if fields := strings.Fields(rest); len(fields) >= 1 {
					data["user"] = fields[0]
				}
			}
		} else if strings.Contains(line, "Accepted password") {
			data["type"] = "successful_login"
			if idx := strings.Index(line, "for "); idx != -1 {
				rest := line[idx+4:]
				if fields := strings.Fields(rest); len(fields) >= 1 {
					data["user"] = fields[0]
				}
			}
		} else if strings.Contains(line, "session opened") {
			data["type"] = "session_open"
		} else if strings.Contains(line, "session closed") {
			data["type"] = "session_close"
		} else if strings.Contains(line, "sudo:") {
			data["type"] = "sudo"
		}

		*records = append(*records, Record{
			Timestamp: time.Now(),
			Source:    source,
			Data:      data,
		})
	}
}
