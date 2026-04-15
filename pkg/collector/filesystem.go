// Package collector provides forensic artifact collection capabilities
// This file contains filesystem-related collectors
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

// FilesystemRecentFilesCollector collects recently modified files
type FilesystemRecentFilesCollector struct{}

func (c *FilesystemRecentFilesCollector) Name() string {
	return "filesystem.recent_files"
}

func (c *FilesystemRecentFilesCollector) Description() string {
	return "Collects recently modified files"
}

func (c *FilesystemRecentFilesCollector) Platform() string {
	return "all"
}

func (c *FilesystemRecentFilesCollector) IsAvailable() bool {
	return true
}

func (c *FilesystemRecentFilesCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Default: files modified in last 7 days
	daysBack := 7
	if opts != nil && opts.DaysBack > 0 {
		daysBack = opts.DaysBack
	}
	cutoff := start.AddDate(0, 0, -daysBack)

	// Directories to scan
	var scanDirs []string
	if runtime.GOOS == "windows" {
		scanDirs = []string{
			os.Getenv("USERPROFILE"),
			os.Getenv("SystemRoot") + "\\Temp",
			os.Getenv("TEMP"),
		}
	} else {
		scanDirs = []string{
			"/tmp",
			"/var/tmp",
			"/home",
		}
	}

	for _, dir := range scanDirs {
		if dir == "" {
			continue
		}

		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if info.ModTime().After(cutoff) {
				records = append(records, Record{
					Timestamp: time.Now(),
					Source:    "filesystem_walk",
					Data: map[string]interface{}{
						"path":       path,
						"size":       info.Size(),
						"mod_time":   info.ModTime().Format(time.RFC3339),
						"is_dir":     info.IsDir(),
						"mode":       info.Mode().String(),
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

// FilesystemFileHashCollector computes hashes for files
type FilesystemFileHashCollector struct{}

func (c *FilesystemFileHashCollector) Name() string {
	return "filesystem.file_hash"
}

func (c *FilesystemFileHashCollector) Description() string {
	return "Computes MD5, SHA1, SHA256 hashes for specified files"
}

func (c *FilesystemFileHashCollector) Platform() string {
	return "all"
}

func (c *FilesystemFileHashCollector) IsAvailable() bool {
	return true
}

func (c *FilesystemFileHashCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	if opts == nil || len(opts.TargetFiles) == 0 {
		return &Result{
			Collector: c.Name(),
			Timestamp: start,
			Success:   true,
			Records:   records,
		}, nil
	}

	for _, filePath := range opts.TargetFiles {
		hashes, err := c.computeHashes(filePath)
		if err != nil {
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

	md5Hash := md5.New()
	sha1Hash := sha1.New()
	sha256Hash := sha256.New()

	multiWriter := io.MultiWriter(md5Hash, sha1Hash, sha256Hash)
	if _, err := io.Copy(multiWriter, file); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"path":      filePath,
		"size":      stat.Size(),
		"mod_time":  stat.ModTime().Format(time.RFC3339),
		"md5":       hex.EncodeToString(md5Hash.Sum(nil)),
		"sha1":      hex.EncodeToString(sha1Hash.Sum(nil)),
		"sha256":    hex.EncodeToString(sha256Hash.Sum(nil)),
	}, nil
}

// FilesystemMFTCollector collects NTFS MFT entries (Windows)
type FilesystemMFTCollector struct{}

func (c *FilesystemMFTCollector) Name() string {
	return "filesystem.mft"
}

func (c *FilesystemMFTCollector) Description() string {
	return "Collects NTFS MFT entries (Windows only)"
}

func (c *FilesystemMFTCollector) Platform() string {
	return "windows"
}

func (c *FilesystemMFTCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

func (c *FilesystemMFTCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Use fsutil to get USN journal entries
	cmd := exec.CommandContext(ctx, "fsutil", "usn", "readjournal", "C:")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: just record that MFT collection requires admin
		return &Result{
			Collector: c.Name(),
			Timestamp: start,
			Success:   false,
			Error:     "MFT collection requires administrator privileges",
		}, nil
	}

	// Parse USN journal output
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

// FilesystemBashHistoryCollector collects bash command history
type FilesystemBashHistoryCollector struct{}

func (c *FilesystemBashHistoryCollector) Name() string {
	return "filesystem.bash_history"
}

func (c *FilesystemBashHistoryCollector) Description() string {
	return "Collects bash command history for all users"
}

func (c *FilesystemBashHistoryCollector) Platform() string {
	return "linux"
}

func (c *FilesystemBashHistoryCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *FilesystemBashHistoryCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Find all users' home directories
	homeDirs := []string{}

	// Read /etc/passwd to find home directories
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

	// Also check /home
	homeEntries, _ := os.ReadDir("/home")
	for _, entry := range homeEntries {
		if entry.IsDir() {
			homeDirs = append(homeDirs, "/home/"+entry.Name())
		}
	}

	// Read bash history for each user
	for _, homeDir := range homeDirs {
		historyPath := homeDir + "/.bash_history"
		c.readHistoryFile(historyPath, homeDir, &records)

		// Also check .zsh_history
		zshHistoryPath := homeDir + "/.zsh_history"
		c.readHistoryFile(zshHistoryPath, homeDir, &records)

		// And .sh_history (ksh)
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
				"user":       filepath.Base(homeDir),
				"home_dir":   homeDir,
				"history":    path,
				"line":       lineNum,
				"command":    line,
			},
		})
	}
}

// FilesystemCronJobsCollector collects cron jobs
type FilesystemCronJobsCollector struct{}

func (c *FilesystemCronJobsCollector) Name() string {
	return "filesystem.cron_jobs"
}

func (c *FilesystemCronJobsCollector) Description() string {
	return "Collects cron job definitions"
}

func (c *FilesystemCronJobsCollector) Platform() string {
	return "linux"
}

func (c *FilesystemCronJobsCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *FilesystemCronJobsCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Read system crontab
	c.readCrontab("/etc/crontab", "system", &records)

	// Read cron.d directory
	cronDEntries, _ := os.ReadDir("/etc/cron.d")
	for _, entry := range cronDEntries {
		if !entry.IsDir() {
			c.readCrontab("/etc/cron.d/"+entry.Name(), "cron.d", &records)
		}
	}

	// Read user crontabs from /var/spool/cron/crontabs
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

	// Read cron.daily, cron.hourly, etc.
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
						"period":    period,
						"file":      dir + "/" + entry.Name(),
						"name":      entry.Name(),
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

		// Skip comments and empty lines
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		*records = append(*records, Record{
			Timestamp: time.Now(),
			Source:    "crontab",
			Data: map[string]interface{}{
				"file":      path,
				"line":      lineNum,
				"job":       line,
				"owner":     source,
			},
		})
	}
}

// FilesystemSystemdServicesCollector collects systemd service files
type FilesystemSystemdServicesCollector struct{}

func (c *FilesystemSystemdServicesCollector) Name() string {
	return "filesystem.systemd_services"
}

func (c *FilesystemSystemdServicesCollector) Description() string {
	return "Collects systemd service definitions"
}

func (c *FilesystemSystemdServicesCollector) Platform() string {
	return "linux"
}

func (c *FilesystemSystemdServicesCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *FilesystemSystemdServicesCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Directories to scan for service files
	serviceDirs := []string{
		"/etc/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
	}

	for _, dir := range serviceDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			name := entry.Name()
			if strings.HasSuffix(name, ".service") {
				servicePath := dir + "/" + name

				// Read service file content
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

	// Also get active services using systemctl
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

// FilesystemScheduledTasksCollector collects Windows scheduled tasks
type FilesystemScheduledTasksCollector struct{}

func (c *FilesystemScheduledTasksCollector) Name() string {
	return "filesystem.scheduled_tasks"
}

func (c *FilesystemScheduledTasksCollector) Description() string {
	return "Collects Windows scheduled tasks"
}

func (c *FilesystemScheduledTasksCollector) Platform() string {
	return "windows"
}

func (c *FilesystemScheduledTasksCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

func (c *FilesystemScheduledTasksCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Use schtasks to list tasks
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

		// Parse CSV line
		fields := strings.Split(line, ",")
		for i := range fields {
			fields[i] = strings.Trim(fields[i], "\"")
		}

		if lineNum == 1 {
			headers = fields
			continue
		}

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

// FilesystemAutorunsCollector collects autorun entries (Windows)
type FilesystemAutorunsCollector struct{}

func (c *FilesystemAutorunsCollector) Name() string {
	return "filesystem.autoruns"
}

func (c *FilesystemAutorunsCollector) Description() string {
	return "Collects Windows autorun entries"
}

func (c *FilesystemAutorunsCollector) Platform() string {
	return "windows"
}

func (c *FilesystemAutorunsCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

func (c *FilesystemAutorunsCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Use reg query to find autorun entries
	autorunKeys := []struct {
		key   string
		name  string
	}{
		{"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM_Run"},
		{"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM_RunOnce"},
		{"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU_Run"},
		{"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU_RunOnce"},
		{"HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM_Run_Wow64"},
	}

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

			// Parse REG_SZ or REG_EXPAND_SZ entries
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

// FilesystemDownloadsCollector collects recently downloaded files
type FilesystemDownloadsCollector struct{}

func (c *FilesystemDownloadsCollector) Name() string {
	return "filesystem.downloads"
}

func (c *FilesystemDownloadsCollector) Description() string {
	return "Collects recently downloaded files"
}

func (c *FilesystemDownloadsCollector) Platform() string {
	return "all"
}

func (c *FilesystemDownloadsCollector) IsAvailable() bool {
	return true
}

func (c *FilesystemDownloadsCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	var downloadDirs []string
	if runtime.GOOS == "windows" {
		userProfile := os.Getenv("USERPROFILE")
		downloadDirs = []string{
			userProfile + "\\Downloads",
		}
	} else {
		// Check common download locations
		home := os.Getenv("HOME")
		downloadDirs = []string{
			home + "/Downloads",
			home + "/downloads",
			"/tmp",
		}
	}

	// Default: files from last 30 days
	daysBack := 30
	if opts != nil && opts.DaysBack > 0 {
		daysBack = opts.DaysBack
	}
	cutoff := start.AddDate(0, 0, -daysBack)

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

// FilesystemSuidFilesCollector collects SUID/SGID files (Linux)
type FilesystemSuidFilesCollector struct{}

func (c *FilesystemSuidFilesCollector) Name() string {
	return "filesystem.suid_files"
}

func (c *FilesystemSuidFilesCollector) Description() string {
	return "Collects SUID/SGID files (Linux)"
}

func (c *FilesystemSuidFilesCollector) Platform() string {
	return "linux"
}

func (c *FilesystemSuidFilesCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *FilesystemSuidFilesCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Use find command to locate SUID files
	cmd := exec.CommandContext(ctx, "find", "/", "-perm", "-4000", "-o", "-perm", "-2000",
		"-type", "f", "-ls", "2>/dev/null")
	output, err := cmd.Output()
	if err != nil {
		// Fallback: scan common directories
		return c.scanForSuidFiles(ctx, &records)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 11 {
			// Parse find -ls output
			// Format: inode blocks perms links owner group size month day time/year path
			records = append(records, Record{
				Timestamp: time.Now(),
				Source:    "find_suid",
				Data: map[string]interface{}{
					"inode":  fields[0],
					"perms":  fields[2],
					"owner":  fields[4],
					"group":  fields[5],
					"size":   fields[6],
					"path":   fields[len(fields)-1],
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

func (c *FilesystemSuidFilesCollector) scanForSuidFiles(ctx context.Context, records *[]Record) (*Result, error) {
	start := time.Now()

	// Scan common binary directories
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
			if mode&04000 != 0 || mode&02000 != 0 { // SUID or SGID
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

// Helper function to parse file size
func parseSize(sizeStr string) int64 {
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		return 0
	}
	return size
}
