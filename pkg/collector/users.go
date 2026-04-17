// Package collector provides forensic artifact collection capabilities
// This file contains user-related collectors
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

// LoggedInUsersCollector collects currently logged in users
type LoggedInUsersCollector struct{}

func (c *LoggedInUsersCollector) Name() string {
	return "users.logged_in"
}

func (c *LoggedInUsersCollector) Description() string {
	return "Collects currently logged in users"
}

func (c *LoggedInUsersCollector) Platform() string {
	return "all"
}

func (c *LoggedInUsersCollector) IsAvailable() bool {
	return true
}

func (c *LoggedInUsersCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	if runtime.GOOS == "linux" {
		// Parse utmp/wtmp
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

func (c *LoggedInUsersCollector) collectLinux() []Record {
	var records []Record

	// Use 'who' command output via /var/run/utmp
	// Simplified: read /var/run/utmp binary format
	// For now, use w command output parsing

	file, err := os.Open("/var/run/utmp")
	if err != nil {
		// Fallback: return placeholder
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

	// TODO: Parse utmp binary format
	// The utmp structure is defined in /usr/include/bits/utmp.h

	return records
}

func (c *LoggedInUsersCollector) collectWindows() []Record {
	var records []Record

	// Use 'query user' command to get logged in users
	cmd := exec.Command("query", "user")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: try 'whoami' for current user
		records = c.collectWindowsFallback()
		return records
	}

	// Parse output:
	// 用户名                会话名             ID  状态    空闲时间   登录时间
	// >malco                 console             1  运行中      无     2026/4/16 10:47
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	lineNum := 0

	// Regex to parse the line
	// Format: [>]username session id status idle logonTime
	lineRegex := regexp.MustCompile(`^([> ])?(\S+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$`)

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// Skip header line
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

func (c *LoggedInUsersCollector) collectWindowsFallback() []Record {
	var records []Record

	// Use whoami to get current user
	cmd := exec.Command("whoami")
	output, err := cmd.Output()
	if err != nil {
		return records
	}

	username := strings.TrimSpace(string(output))
	if username == "" {
		return records
	}

	// Split domain\user if present
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

// SudoHistoryCollector collects sudo command history
type SudoHistoryCollector struct{}

func (c *SudoHistoryCollector) Name() string {
	return "users.sudo_history"
}

func (c *SudoHistoryCollector) Description() string {
	return "Collects sudo command history from logs"
}

func (c *SudoHistoryCollector) Platform() string {
	return "linux"
}

func (c *SudoHistoryCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *SudoHistoryCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Read sudo log (typically in auth.log or syslog)
	logFiles := []string{
		"/var/log/auth.log",
		"/var/log/secure",
	}

	for _, logFile := range logFiles {
		file, err := os.Open(logFile)
		if err != nil {
			continue
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()

			// Look for sudo entries
			if strings.Contains(line, "sudo:") {
				records = append(records, Record{
					Timestamp: time.Now(),
					Source:    "auth_log",
					Data: map[string]interface{}{
						"file":    logFile,
						"line":    line,
					},
				})
			}
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

// BashHistoryCollector collects bash command history
type BashHistoryCollector struct{}

func (c *BashHistoryCollector) Name() string {
	return "users.bash_history"
}

func (c *BashHistoryCollector) Description() string {
	return "Collects bash command history for all users"
}

func (c *BashHistoryCollector) Platform() string {
	return "linux"
}

func (c *BashHistoryCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *BashHistoryCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Read /etc/passwd to find home directories
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

		historyFile := homeDir + "/.bash_history"
		content, err := os.ReadFile(historyFile)
		if err != nil {
			continue
		}

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
