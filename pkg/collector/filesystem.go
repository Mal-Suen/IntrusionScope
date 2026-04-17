// Package collector 提供取证工件收集能力
// 本文件包含文件系统相关的收集器实现
package collector

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// FilesystemRecentFilesCollector 最近修改文件收集器，收集最近修改的文件信息
type FilesystemRecentFilesCollector struct{}

// Name 返回收集器名称
func (c *FilesystemRecentFilesCollector) Name() string {
	return "filesystem.recent_files"
}

// Description 返回收集器描述
func (c *FilesystemRecentFilesCollector) Description() string {
	return "Collects recently modified files"
}

// Platform 返回支持的平台
func (c *FilesystemRecentFilesCollector) Platform() string {
	return "all"
}

// IsAvailable 检查收集器是否可用
func (c *FilesystemRecentFilesCollector) IsAvailable() bool {
	return true
}

// Collect 收集最近修改的文件信息
func (c *FilesystemRecentFilesCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 默认收集最近 7 天修改的文件
	daysBack := 7
	if opts != nil && opts.DaysBack > 0 {
		daysBack = opts.DaysBack
	}
	cutoff := start.AddDate(0, 0, -daysBack)

	// 根据操作系统确定扫描目录
	var scanDirs []string
	if runtime.GOOS == "windows" {
		// Windows: 扫描用户目录、系统临时目录等
		userProfile := os.Getenv("USERPROFILE")
		systemRoot := os.Getenv("SystemRoot")
		temp := os.Getenv("TEMP")

		if userProfile != "" {
			scanDirs = append(scanDirs, userProfile)
		}
		if systemRoot != "" {
			scanDirs = append(scanDirs, filepath.Join(systemRoot, "Temp"))
		}
		if temp != "" {
			scanDirs = append(scanDirs, temp)
		}
	} else {
		// Linux: 扫描临时目录和用户主目录
		scanDirs = []string{
			"/tmp",
			"/var/tmp",
			"/home",
		}
	}

	// 遍历目录收集文件信息
	for _, dir := range scanDirs {
		if dir == "" {
			continue
		}

		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// 只收集在截止时间之后修改的文件
			if info.ModTime().After(cutoff) {
				records = append(records, Record{
					Timestamp: time.Now(),
					Source:    "filesystem_walk",
					Data: map[string]interface{}{
						"path":     path,
						"size":     info.Size(),
						"mod_time": info.ModTime().Format(time.RFC3339),
						"is_dir":   info.IsDir(),
						"mode":     info.Mode().String(),
					},
				})
			}

			return nil
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

// FilesystemFileHashCollector 文件哈希收集器，计算指定文件的 MD5、SHA1、SHA256 哈希值
type FilesystemFileHashCollector struct{}

// Name 返回收集器名称
func (c *FilesystemFileHashCollector) Name() string {
	return "filesystem.file_hash"
}

// Description 返回收集器描述
func (c *FilesystemFileHashCollector) Description() string {
	return "Computes MD5, SHA1, SHA256 hashes for specified files"
}

// Platform 返回支持的平台
func (c *FilesystemFileHashCollector) Platform() string {
	return "all"
}

// IsAvailable 检查收集器是否可用
func (c *FilesystemFileHashCollector) IsAvailable() bool {
	return true
}

// Collect 计算指定文件的哈希值
func (c *FilesystemFileHashCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 检查是否指定了目标文件
	if opts == nil || len(opts.TargetFiles) == 0 {
		return &Result{
			Collector: c.Name(),
			Timestamp: start,
			Success:   true,
			Records:   records,
		}, nil
	}

	// 遍历目标文件计算哈希
	for _, filePath := range opts.TargetFiles {
		hashes, err := c.computeHashes(filePath)
		if err != nil {
			// 记录错误信息
			records = append(records, Record{
				Timestamp: time.Now(),
				Source:    "file_hash",
				Data: map[string]interface{}{
					"path":  filePath,
					"error": err.Error(),
				},
			})
			continue
		}

		records = append(records, Record{
			Timestamp: time.Now(),
			Source:    "file_hash",
			Data:      hashes,
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

// computeHashes 计算单个文件的多种哈希值
func (c *FilesystemFileHashCollector) computeHashes(filePath string) (map[string]interface{}, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	// 创建多个哈希计算器
	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	// 使用 MultiWriter 同时计算多个哈希
	multiWriter := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)
	if _, err := io.Copy(multiWriter, file); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"path":     filePath,
		"size":     stat.Size(),
		"mod_time": stat.ModTime().Format(time.RFC3339),
		"md5":      hex.EncodeToString(md5Hash.Sum(nil)),
		"sha1":     hex.EncodeToString(sha1Hash.Sum(nil)),
		"sha256":   hex.EncodeToString(sha256Hash.Sum(nil)),
	}, nil
}

// FilesystemMFTCollector NTFS MFT 收集器，收集 NTFS 主文件表条目（仅 Windows）
type FilesystemMFTCollector struct{}

// Name 返回收集器名称
func (c *FilesystemMFTCollector) Name() string {
	return "filesystem.mft"
}

// Description 返回收集器描述
func (c *FilesystemMFTCollector) Description() string {
	return "Collects NTFS MFT entries (Windows only)"
}

// Platform 返回支持的平台（仅 Windows）
func (c *FilesystemMFTCollector) Platform() string {
	return "windows"
}

// IsAvailable 检查收集器是否可用
func (c *FilesystemMFTCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// Collect 收集 NTFS MFT 条目
func (c *FilesystemMFTCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 使用 fsutil 读取 USN 日志条目
	cmd := exec.CommandContext(ctx, "fsutil", "usn", "readjournal", "C:")
	output, err := cmd.Output()
	if err != nil {
		// MFT 收集需要管理员权限
		return &Result{
			Collector: c.Name(),
			Timestamp: start,
			Success:   false,
			Error:     "MFT collection requires administrator privileges",
		}, nil
	}

	// 解析 USN 日志输出
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		records = append(records, Record{
			Timestamp: time.Now(),
			Source:    "usn_journal",
			Data: map[string]interface{}{
				"raw": line,
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

// FilesystemBashHistoryCollector Bash 命令历史收集器，收集所有用户的 bash 命令历史
type FilesystemBashHistoryCollector struct{}

// Name 返回收集器名称
func (c *FilesystemBashHistoryCollector) Name() string {
	return "filesystem.bash_history"
}

// Description 返回收集器描述
func (c *FilesystemBashHistoryCollector) Description() string {
	return "Collects bash command history for all users"
}

// Platform 返回支持的平台（仅 Linux）
func (c *FilesystemBashHistoryCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *FilesystemBashHistoryCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集所有用户的 bash 命令历史
func (c *FilesystemBashHistoryCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 查找所有用户的主目录
	homeDirs := []string{}

	// 从 /etc/passwd 读取用户主目录
	passwd, err := os.Open("/etc/passwd")
	if err == nil {
		scanner := bufio.NewScanner(passwd)
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Split(line, ":")
			if len(fields) >= 6 {
				homeDir := fields[5]
				if homeDir != "" {
					homeDirs = append(homeDirs, homeDir)
				}
			}
		}
		passwd.Close()
	}

	// 同时检查 /home 目录下的用户
	homeEntries, _ := os.ReadDir("/home")
	for _, entry := range homeEntries {
		if entry.IsDir() {
			homeDirs = append(homeDirs, "/home/"+entry.Name())
		}
	}

	// 读取每个用户的 shell 历史文件
	for _, homeDir := range homeDirs {
		// 读取 .bash_history
		historyPath := homeDir + "/.bash_history"
		c.readHistoryFile(historyPath, homeDir, &records)

		// 读取 .zsh_history（zsh shell）
		zshHistoryPath := homeDir + "/.zsh_history"
		c.readHistoryFile(zshHistoryPath, homeDir, &records)

		// 读取 .sh_history（ksh shell）
		shHistoryPath := homeDir + "/.sh_history"
		c.readHistoryFile(shHistoryPath, homeDir, &records)
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

// readHistoryFile 读取单个历史文件内容
func (c *FilesystemBashHistoryCollector) readHistoryFile(path, homeDir string, records *[]Record) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		if strings.TrimSpace(line) == "" {
			continue
		}

		*records = append(*records, Record{
			Timestamp: time.Now(),
			Source:    "bash_history",
			Data: map[string]interface{}{
				"user":     filepath.Base(homeDir),
				"home_dir": homeDir,
				"history":  path,
				"line":     lineNum,
				"command":  line,
			},
		})
	}
}

// FilesystemCronJobsCollector Cron 任务收集器，收集定时任务定义
type FilesystemCronJobsCollector struct{}

// Name 返回收集器名称
func (c *FilesystemCronJobsCollector) Name() string {
	return "filesystem.cron_jobs"
}

// Description 返回收集器描述
func (c *FilesystemCronJobsCollector) Description() string {
	return "Collects cron job definitions"
}

// Platform 返回支持的平台（仅 Linux）
func (c *FilesystemCronJobsCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *FilesystemCronJobsCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集 cron 任务定义
func (c *FilesystemCronJobsCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 读取系统 crontab
	c.readCrontab("/etc/crontab", "system", &records)

	// 读取 cron.d 目录下的任务
	cronDEntries, _ := os.ReadDir("/etc/cron.d")
	for _, entry := range cronDEntries {
		if !entry.IsDir() {
			c.readCrontab("/etc/cron.d/"+entry.Name(), "cron.d", &records)
		}
	}

	// 读取用户 crontabs
	crontabsDir := "/var/spool/cron/crontabs"
	crontabEntries, err := os.ReadDir(crontabsDir)
	if err == nil {
		for _, entry := range crontabEntries {
			if !entry.IsDir() {
				user := entry.Name()
				c.readCrontab(crontabsDir+"/"+user, "user:"+user, &records)
			}
		}
	}

	// 读取周期性任务目录（cron.daily, cron.hourly 等）
	for _, period := range []string{"hourly", "daily", "weekly", "monthly"} {
		dir := "/etc/cron." + period
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				records = append(records, Record{
					Timestamp: time.Now(),
					Source:    "cron_period",
					Data: map[string]interface{}{
						"period": period,
						"file":   dir + "/" + entry.Name(),
						"name":   entry.Name(),
					},
				})
			}
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

// readCrontab 读取单个 crontab 文件
func (c *FilesystemCronJobsCollector) readCrontab(path, source string, records *[]Record) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		lineNum++

		// 跳过注释和空行
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		*records = append(*records, Record{
			Timestamp: time.Now(),
			Source:    "crontab",
			Data: map[string]interface{}{
				"file":  path,
				"line":  lineNum,
				"job":   line,
				"owner": source,
			},
		})
	}
}

// FilesystemSystemdServicesCollector Systemd 服务收集器，收集 systemd 服务定义
type FilesystemSystemdServicesCollector struct{}

// Name 返回收集器名称
func (c *FilesystemSystemdServicesCollector) Name() string {
	return "filesystem.systemd_services"
}

// Description 返回收集器描述
func (c *FilesystemSystemdServicesCollector) Description() string {
	return "Collects systemd service definitions"
}

// Platform 返回支持的平台（仅 Linux）
func (c *FilesystemSystemdServicesCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *FilesystemSystemdServicesCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集 systemd 服务定义
func (c *FilesystemSystemdServicesCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 服务文件目录
	serviceDirs := []string{
		"/etc/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
	}

	// 遍历目录收集 .service 文件
	for _, dir := range serviceDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			name := entry.Name()
			if strings.HasSuffix(name, ".service") {
				servicePath := dir + "/" + name

				// 读取服务文件内容
				content, err := os.ReadFile(servicePath)
				if err != nil {
					continue
				}

				records = append(records, Record{
					Timestamp: time.Now(),
					Source:    "systemd_service",
					Data: map[string]interface{}{
						"name":    name,
						"path":    servicePath,
						"content": string(content),
					},
				})
			}
		}
	}

	// 使用 systemctl 获取活动服务状态
	cmd := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-pager")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, ".service") {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					records = append(records, Record{
						Timestamp: time.Now(),
						Source:    "systemctl",
						Data: map[string]interface{}{
							"unit":   fields[0],
							"load":   fields[1],
							"active": fields[2],
							"sub":    fields[3],
						},
					})
				}
			}
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

// FilesystemScheduledTasksCollector Windows 计划任务收集器
type FilesystemScheduledTasksCollector struct{}

// Name 返回收集器名称
func (c *FilesystemScheduledTasksCollector) Name() string {
	return "filesystem.scheduled_tasks"
}

// Description 返回收集器描述
func (c *FilesystemScheduledTasksCollector) Description() string {
	return "Collects Windows scheduled tasks"
}

// Platform 返回支持的平台（仅 Windows）
func (c *FilesystemScheduledTasksCollector) Platform() string {
	return "windows"
}

// IsAvailable 检查收集器是否可用
func (c *FilesystemScheduledTasksCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// Collect 收集 Windows 计划任务
func (c *FilesystemScheduledTasksCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 使用 schtasks 命令列出任务
	cmd := exec.CommandContext(ctx, "schtasks", "/query", "/fo", "csv", "/v")
	output, err := cmd.Output()
	if err != nil {
		return &Result{
			Collector: c.Name(),
			Timestamp: start,
			Success:   false,
			Error:     fmt.Sprintf("failed to run schtasks: %v", err),
		}, err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	lineNum := 0
	var headers []string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNum++

		if line == "" {
			continue
		}

		// 解析 CSV 行
		fields := strings.Split(line, ",")
		for i := range fields {
			fields[i] = strings.Trim(fields[i], "\"")
		}

		if lineNum == 1 {
			// 第一行为标题行
			headers = fields
			continue
		}

		// 构建记录数据
		data := make(map[string]interface{})
		for i, field := range fields {
			if i < len(headers) {
				data[headers[i]] = field
			}
		}

		records = append(records, Record{
			Timestamp: time.Now(),
			Source:    "schtasks",
			Data:      data,
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

// FilesystemAutorunsCollector Windows 自启动项收集器
type FilesystemAutorunsCollector struct{}

// Name 返回收集器名称
func (c *FilesystemAutorunsCollector) Name() string {
	return "filesystem.autoruns"
}

// Description 返回收集器描述
func (c *FilesystemAutorunsCollector) Description() string {
	return "Collects Windows autorun entries"
}

// Platform 返回支持的平台（仅 Windows）
func (c *FilesystemAutorunsCollector) Platform() string {
	return "windows"
}

// IsAvailable 检查收集器是否可用
func (c *FilesystemAutorunsCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// Collect 收集 Windows 自启动项
func (c *FilesystemAutorunsCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 自启动注册表位置
	autorunKeys := []struct {
		key  string
		name string
	}{
		{"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM_Run"},
		{"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM_RunOnce"},
		{"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU_Run"},
		{"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU_RunOnce"},
		{"HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM_Run_Wow64"},
	}

	// 查询每个自启动位置
	for _, ar := range autorunKeys {
		cmd := exec.CommandContext(ctx, "reg", "query", ar.key)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, ar.key) {
				continue
			}

			// 解析 REG_SZ 或 REG_EXPAND_SZ 类型的条目
			if strings.Contains(line, "REG_SZ") || strings.Contains(line, "REG_EXPAND_SZ") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					name := fields[0]
					value := strings.Join(fields[2:], " ")

					records = append(records, Record{
						Timestamp: time.Now(),
						Source:    "autorun",
						Data: map[string]interface{}{
							"location": ar.name,
							"key":      ar.key,
							"name":     name,
							"value":    value,
						},
					})
				}
			}
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

// FilesystemDownloadsCollector 下载文件收集器，收集最近下载的文件
type FilesystemDownloadsCollector struct{}

// Name 返回收集器名称
func (c *FilesystemDownloadsCollector) Name() string {
	return "filesystem.downloads"
}

// Description 返回收集器描述
func (c *FilesystemDownloadsCollector) Description() string {
	return "Collects recently downloaded files"
}

// Platform 返回支持的平台
func (c *FilesystemDownloadsCollector) Platform() string {
	return "all"
}

// IsAvailable 检查收集器是否可用
func (c *FilesystemDownloadsCollector) IsAvailable() bool {
	return true
}

// Collect 收集最近下载的文件
func (c *FilesystemDownloadsCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 根据操作系统确定下载目录
	var downloadDirs []string
	if runtime.GOOS == "windows" {
		userProfile := os.Getenv("USERPROFILE")
		downloadDirs = []string{
			userProfile + "\\Downloads",
		}
	} else {
		// Linux: 检查常见下载位置
		home := os.Getenv("HOME")
		downloadDirs = []string{
			home + "/Downloads",
			home + "/downloads",
			"/tmp",
		}
	}

	// 默认收集最近 30 天的下载文件
	daysBack := 30
	if opts != nil && opts.DaysBack > 0 {
		daysBack = opts.DaysBack
	}
	cutoff := start.AddDate(0, 0, -daysBack)

	// 遍历下载目录
	for _, dir := range downloadDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}

			// 只收集在截止时间之后修改的文件
			if info.ModTime().After(cutoff) {
				records = append(records, Record{
					Timestamp: time.Now(),
					Source:    "downloads",
					Data: map[string]interface{}{
						"path":     dir + string(os.PathSeparator) + entry.Name(),
						"name":     entry.Name(),
						"size":     info.Size(),
						"mod_time": info.ModTime().Format(time.RFC3339),
						"is_dir":   entry.IsDir(),
					},
				})
			}
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

// FilesystemSuidFilesCollector SUID/SGID 文件收集器，收集具有特殊权限的文件（仅 Linux）
type FilesystemSuidFilesCollector struct{}

// Name 返回收集器名称
func (c *FilesystemSuidFilesCollector) Name() string {
	return "filesystem.suid_files"
}

// Description 返回收集器描述
func (c *FilesystemSuidFilesCollector) Description() string {
	return "Collects SUID/SGID files (Linux)"
}

// Platform 返回支持的平台（仅 Linux）
func (c *FilesystemSuidFilesCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *FilesystemSuidFilesCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集 SUID/SGID 文件
func (c *FilesystemSuidFilesCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 使用 find 命令查找 SUID/SGID 文件
	cmd := exec.CommandContext(ctx, "find", "/", "-perm", "-4000", "-o", "-perm", "-2000",
		"-type", "f", "-ls", "2>/dev/null")
	output, err := cmd.Output()
	if err != nil {
		// 如果 find 命令失败，回退到扫描常见目录
		return c.scanForSuidFiles(ctx, &records)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 11 {
			// 解析 find -ls 输出格式
			// 格式：inode blocks perms links owner group size month day time/year path
			records = append(records, Record{
				Timestamp: time.Now(),
				Source:    "find_suid",
				Data: map[string]interface{}{
					"inode": fields[0],
					"perms": fields[2],
					"owner": fields[4],
					"group": fields[5],
					"size":  fields[6],
					"path":  fields[len(fields)-1],
				},
			})
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

// scanForSuidFiles 扫描常见目录查找 SUID/SGID 文件（作为 find 命令的备选方案）
func (c *FilesystemSuidFilesCollector) scanForSuidFiles(ctx context.Context, records *[]Record) (*Result, error) {
	start := time.Now()

	// 扫描常见二进制目录
	scanDirs := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"}

	for _, dir := range scanDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}

			mode := info.Mode()
			// 检查 SUID (04000) 或 SGID (02000) 位
			if mode&04000 != 0 || mode&02000 != 0 {
				*records = append(*records, Record{
					Timestamp: time.Now(),
					Source:    "suid_scan",
					Data: map[string]interface{}{
						"path":  dir + "/" + entry.Name(),
						"mode":  mode.String(),
						"suid":  mode&04000 != 0,
						"sgid":  mode&02000 != 0,
					},
				})
			}
		}
	}

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     *records,
		RecordCount: len(*records),
		Duration:    time.Since(start),
	}, nil
}

// parseSize 解析文件大小字符串
func parseSize(sizeStr string) int64 {
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return 0
	}
	return size
}
