// Package collector 提供取证工件收集能力
// 本文件包含用户相关的收集器实现
package collector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// LoggedInUsersCollector 已登录用户收集器，收集当前登录的用户信息
type LoggedInUsersCollector struct{}

// Name 返回收集器名称
func (c *LoggedInUsersCollector) Name() string {
	return "users.logged_in"
}

// Description 返回收集器描述
func (c *LoggedInUsersCollector) Description() string {
	return "Collects currently logged in users"
}

// Platform 返回支持的平台
func (c *LoggedInUsersCollector) Platform() string {
	return "all"
}

// IsAvailable 检查收集器是否可用
func (c *LoggedInUsersCollector) IsAvailable() bool {
	return true
}

// Collect 收集当前登录的用户信息
func (c *LoggedInUsersCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 根据操作系统选择不同的收集方法
	if runtime.GOOS == "linux" {
		records = c.collectLinux()
	} else {
		records = c.collectWindows()
	}

	result := &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}

	return result, nil
}

// collectLinux 在 Linux 系统上收集登录用户信息
func (c *LoggedInUsersCollector) collectLinux() []Record {
	var records []Record

	// 通过 /var/run/utmp 获取登录用户信息
	// 简化实现：读取 /var/run/utmp 二进制格式
	// 目前使用 w 命令输出解析

	file, err := os.Open("/var/run/utmp")
	if err != nil {
		// 回退：返回占位信息
		records = append(records, Record{
			Timestamp: time.Now(),
			Source:    "utmp",
			Data: map[string]interface{}{
				"message": "utmp parsing requires binary format implementation",
			},
		})
		return records
	}
	defer file.Close()

	// TODO: 解析 utmp 二进制格式
	// utmp 结构定义在 /usr/include/bits/utmp.h

	return records
}

// collectWindows 在 Windows 系统上收集登录用户信息
func (c *LoggedInUsersCollector) collectWindows() []Record {
	var records []Record

	// 使用 query user 命令获取登录用户
	cmd := exec.Command("query", "user")
	output, err := cmd.Output()
	if err != nil {
		// 回退：使用 whoami 获取当前用户
		records = c.collectWindowsFallback()
		return records
	}

	// 解析输出格式：
	// 用户名                会话名             ID  状态    空闲时间   登录时间
	// >malco                 console             1  运行中      无     2026/4/16 10:47
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	lineNum := 0

	// 正则表达式解析每行
	lineRegex := regexp.MustCompile(`^([> ])?(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$`)

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// 跳过标题行
		if lineNum == 1 || strings.TrimSpace(line) == "" {
			continue
		}

		matches := lineRegex.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		record := Record{
			Timestamp: time.Now(),
			Source:    "query_user",
			Data: map[string]interface{}{
				"username":     matches[2],
				"session_name": matches[3],
				"session_id":   matches[4],
				"status":       matches[5],
				"idle_time":    matches[6],
				"logon_time":   matches[7],
				"current":      matches[1] == ">",
			},
		}
		records = append(records, record)
	}

	return records
}

// collectWindowsFallback Windows 回退方法，使用 whoami 获取当前用户
func (c *LoggedInUsersCollector) collectWindowsFallback() []Record {
	var records []Record

	// 使用 whoami 获取当前用户
	cmd := exec.Command("whoami")
	output, err := cmd.Output()
	if err != nil {
		return records
	}

	username := strings.TrimSpace(string(output))
	if username == "" {
		return records
	}

	// 分离域和用户名
	parts := strings.Split(username, "\\")
	user := username
	domain := ""
	if len(parts) == 2 {
		domain = parts[0]
		user = parts[1]
	}

	records = append(records, Record{
		Timestamp: time.Now(),
		Source:    "whoami",
		Data: map[string]interface{}{
			"username": user,
			"domain":   domain,
			"current":  true,
		},
	})

	return records
}

// SudoHistoryCollector Sudo 命令历史收集器，从日志收集 sudo 命令历史
type SudoHistoryCollector struct{}

// Name 返回收集器名称
func (c *SudoHistoryCollector) Name() string {
	return "users.sudo_history"
}

// Description 返回收集器描述
func (c *SudoHistoryCollector) Description() string {
	return "Collects sudo command history from logs"
}

// Platform 返回支持的平台（仅 Linux）
func (c *SudoHistoryCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *SudoHistoryCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集 sudo 命令历史
func (c *SudoHistoryCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// sudo 日志通常在 auth.log 或 syslog 中
	logFiles := []string{
		"/var/log/auth.log",
		"/var/log/secure",
	}

	for _, logFile := range logFiles {
		file, err := os.Open(logFile)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()

			// 查找 sudo 条目
			if strings.Contains(line, "sudo:") {
				records = append(records, Record{
					Timestamp: time.Now(),
					Source:    "auth_log",
					Data: map[string]interface{}{
						"file": logFile,
						"line": line,
					},
				})
			}
		}
		file.Close() // 在循环中立即关闭，不使用 defer
	}

	result := &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}

	return result, nil
}

// BashHistoryCollector Bash 命令历史收集器，收集所有用户的 bash 命令历史
type BashHistoryCollector struct{}

// Name 返回收集器名称
func (c *BashHistoryCollector) Name() string {
	return "users.bash_history"
}

// Description 返回收集器描述
func (c *BashHistoryCollector) Description() string {
	return "Collects bash command history for all users"
}

// Platform 返回支持的平台（仅 Linux）
func (c *BashHistoryCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *BashHistoryCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集所有用户的 bash 命令历史
func (c *BashHistoryCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 读取 /etc/passwd 获取用户主目录
	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("failed to read /etc/passwd: %w", err)
	}
	defer passwdFile.Close()

	scanner := bufio.NewScanner(passwdFile)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 6 {
			continue
		}

		username := fields[0]
		homeDir := fields[5]

		// 读取用户的 .bash_history 文件
		historyFile := homeDir + "/.bash_history"
		content, err := os.ReadFile(historyFile)
		if err != nil {
			continue
		}

		// 解析历史文件内容
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			if line == "" {
				continue
			}

			records = append(records, Record{
				Timestamp: time.Now(),
				Source:    "bash_history",
				Data: map[string]interface{}{
					"user":     username,
					"home":     homeDir,
					"line_num": i + 1,
					"command":  line,
				},
			})
		}
	}

	result := &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}

	return result, nil
}
