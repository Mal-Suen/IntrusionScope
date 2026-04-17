// Package collector provides forensic artifact collection capabilities
// This file contains log-related collectors
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

// LogAuthCollector collects authentication logs
type LogAuthCollector struct{}

func (c *LogAuthCollector) Name() string {
	return "log.auth"
}

func (c *LogAuthCollector) Description() string {
	return "Collects authentication logs (auth.log / secure)"
}

func (c *LogAuthCollector) Platform() string {
	return "linux"
}

func (c *LogAuthCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *LogAuthCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Auth log locations
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

// LogSyslogCollector collects syslog entries
type LogSyslogCollector struct{}

func (c *LogSyslogCollector) Name() string {
	return "log.syslog"
}

func (c *LogSyslogCollector) Description() string {
	return "Collects syslog entries"
}

func (c *LogSyslogCollector) Platform() string {
	return "linux"
}

func (c *LogSyslogCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *LogSyslogCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Syslog locations
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

func (c *LogSyslogCollector) readLogFile(path, source string, records *[]Record) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(path, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			// file will be closed by defer
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

		// Parse syslog format: Mon DD HH:MM:SS hostname process[pid]: message
		if record := c.parseSyslogLine(line, path, lineNum, source); record != nil {
			*records = append(*records, *record)
		}
	}
}

func (c *LogSyslogCollector) parseSyslogLine(line, path string, lineNum int, source string) *Record {
	// Basic syslog parsing
	data := map[string]interface{}{
		"source_file": path,
		"line":        lineNum,
		"raw":         line,
	}

	// Try to parse standard syslog format
	// Example: Apr 15 10:30:00 hostname process[1234]: message
	parts := strings.SplitN(line, ":", 2)
	if len(parts) >= 2 {
		data["message"] = strings.TrimSpace(parts[1])

		header := parts[0]
		headerParts := strings.Fields(header)
		if len(headerParts) >= 4 {
			// Extract timestamp
			data["timestamp"] = headerParts[0] + " " + headerParts[1] + " " + headerParts[2]
			data["hostname"] = headerParts[3]

			if len(headerParts) >= 5 {
				// Extract process and PID
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

// LogWtmpCollector collects login history from wtmp/btmp
type LogWtmpCollector struct{}

func (c *LogWtmpCollector) Name() string {
	return "log.wtmp"
}

func (c *LogWtmpCollector) Description() string {
	return "Collects login history from wtmp/btmp files"
}

func (c *LogWtmpCollector) Platform() string {
	return "linux"
}

func (c *LogWtmpCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *LogWtmpCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Use last command to parse wtmp
	cmd := exec.CommandContext(ctx, "last", "-F", "-x")
	output, err := cmd.Output()
	if err == nil {
		c.parseLastOutput(string(output), "wtmp", &records)
	}

	// Use lastb for failed logins (btmp)
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

func (c *LogWtmpCollector) parseLastOutput(output, source string, records *[]Record) {
	scanner := bufio.NewScanner(strings.NewReader(output))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "wtmp") || strings.HasPrefix(line, "btmp") {
			continue
		}

		// Parse last output
		// Format: user     pts/0        192.168.1.1     Mon Apr 15 10:00:00 2024 - Mon Apr 15 11:00:00 2024  (01:00)
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

// LogAuditCollector collects auditd logs
type LogAuditCollector struct{}

func (c *LogAuditCollector) Name() string {
	return "log.audit"
}

func (c *LogAuditCollector) Description() string {
	return "Collects auditd logs"
}

func (c *LogAuditCollector) Platform() string {
	return "linux"
}

func (c *LogAuditCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *LogAuditCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Read audit log
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

		// Parse audit log format
		data := map[string]interface{}{
			"source_file": path,
			"raw":         line,
		}

		// Parse key=value pairs
		// Example: type=EXECVE msg=audit(1618483800.123:456): argc=3 a0="ls" a1="-la" a2="/tmp"
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

// LogJournalCollector collects systemd journal entries
type LogJournalCollector struct{}

func (c *LogJournalCollector) Name() string {
	return "log.journal"
}

func (c *LogJournalCollector) Description() string {
	return "Collects systemd journal entries"
}

func (c *LogJournalCollector) Platform() string {
	return "linux"
}

func (c *LogJournalCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *LogJournalCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Use journalctl to export logs
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

	// Parse JSON output (one JSON object per line)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Store raw JSON for now
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

// LogWindowsEventCollector collects Windows Event Logs
type LogWindowsEventCollector struct{}

func (c *LogWindowsEventCollector) Name() string {
	return "log.windows_events"
}

func (c *LogWindowsEventCollector) Description() string {
	return "Collects Windows Event Logs"
}

func (c *LogWindowsEventCollector) Platform() string {
	return "windows"
}

func (c *LogWindowsEventCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

func (c *LogWindowsEventCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Event logs to collect
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

func (c *LogWindowsEventCollector) collectEventLog(ctx context.Context, logName string, records *[]Record) {
	// Use wevtutil to query events
	cmd := exec.CommandContext(ctx, "wevtutil", "qe", logName, "/f:Text", "/c:100")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	// Parse text output
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var currentEvent map[string]interface{}
	var currentField string

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Event[") {
			// New event
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

		// Parse field: value
		if idx := strings.Index(line, ":"); idx != -1 {
			field := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			currentField = field
			currentEvent[field] = value
		} else if currentField != "" && strings.TrimSpace(line) != "" {
			// Continuation of previous field
			if existing, ok := currentEvent[currentField].(string); ok {
				currentEvent[currentField] = existing + "\n" + strings.TrimSpace(line)
			}
		}
	}

	// Add last event
	if currentEvent != nil {
		*records = append(*records, Record{
			Timestamp: time.Now(),
			Source:    logName,
			Data:      currentEvent,
		})
	}
}

// LogWebServerCollector collects web server logs
type LogWebServerCollector struct{}

func (c *LogWebServerCollector) Name() string {
	return "log.webserver"
}

func (c *LogWebServerCollector) Description() string {
	return "Collects web server access/error logs"
}

func (c *LogWebServerCollector) Platform() string {
	return "linux"
}

func (c *LogWebServerCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *LogWebServerCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Common web server log locations
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

func (c *LogWebServerCollector) readWebLog(path string, records *[]Record) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	var reader io.Reader = file
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

		// Parse common log format or combined log format
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

func (c *LogWebServerCollector) parseWebLogLine(line string) map[string]interface{} {
	data := map[string]interface{}{
		"raw": line,
	}

	// Try to parse Combined Log Format
	// Example: 192.168.1.1 - - [15/Apr/2024:10:00:00 +0000] "GET /path HTTP/1.1" 200 1234 "http://referer" "User-Agent"

	// Simple regex-free parsing
	parts := strings.Fields(line)
	if len(parts) >= 7 {
		data["client_ip"] = parts[0]

		// Find the request part between quotes
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

// Helper function for LogAuthCollector
func (c *LogAuthCollector) readLogFile(path, source string, records *[]Record) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	var reader io.Reader = file
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

		// Parse auth log
		data := map[string]interface{}{
			"source_file": path,
			"line":        lineNum,
			"raw":         line,
		}

		// Extract useful information
		if strings.Contains(line, "Failed password") {
			data["type"] = "failed_login"
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
