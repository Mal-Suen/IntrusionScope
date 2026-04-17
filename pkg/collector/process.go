// Package collector provides forensic artifact collection capabilities
// This file contains process-related collectors
package collector

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ProcessListCollector collects running process list
type ProcessListCollector struct{}

func (c *ProcessListCollector) Name() string {
	return "process.list"
}

func (c *ProcessListCollector) Description() string {
	return "Collects list of running processes"
}

func (c *ProcessListCollector) Platform() string {
	return "all"
}

func (c *ProcessListCollector) IsAvailable() bool {
	return true
}

func (c *ProcessListCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	result := &Result{
		Collector: c.Name(),
		Timestamp: start,
		Records:   []Record{},
	}

	var records []Record
	var err error

	if runtime.GOOS == "windows" {
		records, err = c.collectWindows(ctx, opts)
	} else {
		records, err = c.collectLinux(ctx, opts)
	}

	if err != nil {
		result.Success = false
		result.Error = err.Error()
		return result, err
	}

	result.Records = records
	result.RecordCount = len(records)
	result.Success = true
	result.Duration = time.Since(start)

	return result, nil
}

func (c *ProcessListCollector) collectLinux(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// Read /proc filesystem
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a process directory
		}

		record, err := c.readLinuxProcessInfo(pid)
		if err != nil {
			if opts != nil && opts.Verbose {
				fmt.Printf("Warning: failed to read process %d: %v\n", pid, err)
			}
			continue
		}

		records = append(records, *record)
	}

	return records, nil
}

func (c *ProcessListCollector) readLinuxProcessInfo(pid int) (*Record, error) {
	procPath := fmt.Sprintf("/proc/%d", pid)

	// Read command line
	cmdline, err := os.ReadFile(procPath + "/cmdline")
	if err != nil {
		return nil, err
	}
	cmdlineStr := strings.ReplaceAll(string(cmdline), "\x00", " ")
	cmdlineStr = strings.TrimSpace(cmdlineStr)

	// Read status
	status, err := os.ReadFile(procPath + "/status")
	if err != nil {
		return nil, err
	}

	// Parse status
	data := make(map[string]interface{})
	data["pid"] = pid

	lines := strings.Split(string(status), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Name":
			data["name"] = value
		case "PPid":
			data["ppid"], _ = strconv.Atoi(value)
		case "Uid":
			uids := strings.Fields(value)
			if len(uids) > 0 {
				data["uid"] = uids[0]
			}
		case "Gid":
			gids := strings.Fields(value)
			if len(gids) > 0 {
				data["gid"] = gids[0]
			}
		case "Threads":
			data["threads"], _ = strconv.Atoi(value)
		}
	}

	data["cmdline"] = cmdlineStr

	// Read exe symlink
	exe, err := os.Readlink(procPath + "/exe")
	if err == nil {
		data["exe"] = exe
		// Extract path from exe (remove deleted suffix)
		if strings.HasSuffix(exe, " (deleted)") {
			data["exe_deleted"] = true
			data["exe"] = strings.TrimSuffix(exe, " (deleted)")
		}
	}

	// Read cwd symlink
	cwd, err := os.Readlink(procPath + "/cwd")
	if err == nil {
		data["cwd"] = cwd
	}

	// Read environment variables (optional)
	env, err := os.ReadFile(procPath + "/environ")
	if err == nil {
		envVars := strings.Split(string(env), "\x00")
		data["env_count"] = len(envVars)
	}

	// Read stat for additional info
	stat, err := os.ReadFile(procPath + "/stat")
	if err == nil {
		statParts := strings.Fields(string(stat))
		if len(statParts) >= 20 {
			data["state"] = statParts[2]
			// Parse start time (field 22, in clock ticks)
			if starttime, err := strconv.ParseInt(statParts[21], 10, 64); err == nil {
				// Convert to seconds since boot
				data["start_time"] = starttime / 100 // Approximate
			}
		}
	}

	return &Record{
		Timestamp: time.Now(),
		Source:    "procfs",
		Data:      data,
	}, nil
}

func (c *ProcessListCollector) collectWindows(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// Use wmic or tasklist for process information
	// Try wmic first for more detailed info
	cmd := exec.CommandContext(ctx, "wmic", "process", "get",
		"ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate",
		"/format:csv")
	output, err := cmd.Output()
	if err != nil {
		// Fallback to tasklist
		return c.collectWindowsTasklist(ctx, opts)
	}

	// Parse CSV output using proper CSV reader to handle quoted fields
	csvReader := csv.NewReader(strings.NewReader(string(output)))
	lineNum := 0
	for {
		fields, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}
		lineNum++

		// Skip header lines (first 2 lines)
		if lineNum <= 2 {
			continue
		}

		// CSV format: Node,CommandLine,CreationDate,ExecutablePath,Name,ParentProcessId,ProcessId
		if len(fields) < 7 {
			continue
		}

		data := make(map[string]interface{})

		// Parse PID
		if pid, err := strconv.Atoi(fields[6]); err == nil {
			data["pid"] = pid
		}

		// Parse PPID
		if ppid, err := strconv.Atoi(fields[5]); err == nil {
			data["ppid"] = ppid
		}

		data["name"] = fields[4]
		data["exe"] = fields[3]
		data["cmdline"] = fields[1]
		data["creation_date"] = fields[2]

		records = append(records, Record{
			Timestamp: time.Now(),
			Source:    "wmic",
			Data:      data,
		})
	}

	return records, nil
}

func (c *ProcessListCollector) collectWindowsTasklist(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	cmd := exec.CommandContext(ctx, "tasklist", "/fo", "csv", "/v")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run tasklist: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 { // Skip header
			continue
		}

		// Parse CSV: "Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name","CPU Time","Window Title"
		fields := strings.Split(line, ",")
		if len(fields) < 4 {
			continue
		}

		data := make(map[string]interface{})

		// Clean up quoted fields
		name := strings.Trim(fields[0], "\"")
		pidStr := strings.Trim(fields[1], "\"")

		data["name"] = name
		if pid, err := strconv.Atoi(pidStr); err == nil {
			data["pid"] = pid
		}

		if len(fields) > 4 {
			memStr := strings.Trim(fields[4], "\"")
			// Parse memory usage (e.g., "123,456 K")
			memStr = strings.ReplaceAll(memStr, ",", "")
			memStr = strings.ReplaceAll(memStr, " K", "")
			if mem, err := strconv.ParseInt(memStr, 10, 64); err == nil {
				data["memory_kb"] = mem
			}
		}

		if len(fields) > 6 {
			data["user"] = strings.Trim(fields[6], "\"")
		}

		records = append(records, Record{
			Timestamp: time.Now(),
			Source:    "tasklist",
			Data:      data,
		})
	}

	return records, nil
}

// ProcessTreeCollector collects process tree structure
type ProcessTreeCollector struct{}

func (c *ProcessTreeCollector) Name() string {
	return "process.tree"
}

func (c *ProcessTreeCollector) Description() string {
	return "Collects process tree structure showing parent-child relationships"
}

func (c *ProcessTreeCollector) Platform() string {
	return "all"
}

func (c *ProcessTreeCollector) IsAvailable() bool {
	return true
}

func (c *ProcessTreeCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()

	// First collect process list
	plc := &ProcessListCollector{}
	plResult, err := plc.Collect(ctx, opts)
	if err != nil {
		return nil, err
	}

	// Build tree structure
	tree := c.buildTree(plResult.Records)

	result := &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     tree,
		RecordCount: len(tree),
		Duration:    time.Since(start),
		Metadata: map[string]interface{}{
			"total_processes": plResult.RecordCount,
		},
	}

	return result, nil
}

func (c *ProcessTreeCollector) buildTree(records []Record) []Record {
	// Build parent-child relationships
	pidMap := make(map[int]map[string]interface{})
	childrenMap := make(map[int][]int)

	for _, r := range records {
		pid, ok := r.Data["pid"].(int)
		if !ok {
			continue
		}
		pidMap[pid] = r.Data

		ppid, ok := r.Data["ppid"].(int)
		if !ok {
			continue
		}
		childrenMap[ppid] = append(childrenMap[ppid], pid)
	}

	// Build tree records
	var tree []Record
	for pid, data := range pidMap {
		ppid, _ := data["ppid"].(int)
		children := childrenMap[pid]

		treeRecord := Record{
			Timestamp: time.Now(),
			Source:    "process_tree",
			Data: map[string]interface{}{
				"pid":         pid,
				"ppid":        ppid,
				"name":        data["name"],
				"exe":         data["exe"],
				"cmdline":     data["cmdline"],
				"children":    children,
				"child_count": len(children),
			},
		}
		tree = append(tree, treeRecord)
	}

	return tree
}

// ProcessOpenFilesCollector collects open files by processes
type ProcessOpenFilesCollector struct{}

func (c *ProcessOpenFilesCollector) Name() string {
	return "process.open_files"
}

func (c *ProcessOpenFilesCollector) Description() string {
	return "Collects list of open files by each process"
}

func (c *ProcessOpenFilesCollector) Platform() string {
	return "linux"
}

func (c *ProcessOpenFilesCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

func (c *ProcessOpenFilesCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdPath := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			linkPath := fdPath + "/" + fd.Name()
			target, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			// Skip anonymous inodes and pipes
			if strings.HasPrefix(target, "pipe:") ||
				strings.HasPrefix(target, "socket:") ||
				strings.HasPrefix(target, "anon_inode:") {
				continue
			}

			records = append(records, Record{
				Timestamp: time.Now(),
				Source:    "procfs_fd",
				Data: map[string]interface{}{
					"pid":    pid,
					"fd":     fd.Name(),
					"target": target,
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

// ProcessModulesCollector collects loaded modules/DLLs by processes (Windows)
type ProcessModulesCollector struct{}

func (c *ProcessModulesCollector) Name() string {
	return "process.modules"
}

func (c *ProcessModulesCollector) Description() string {
	return "Collects loaded modules/DLLs by each process (Windows only)"
}

func (c *ProcessModulesCollector) Platform() string {
	return "windows"
}

func (c *ProcessModulesCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

func (c *ProcessModulesCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Use wmic to get loaded modules
	cmd := exec.CommandContext(ctx, "wmic", "process", "get", "ProcessId,Name,ExecutablePath",
		"/format:csv")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get process list: %w", err)
	}

	// Parse and collect module info
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 4 {
			pidStr := fields[3]
			name := fields[2]
			exePath := fields[1]

			if pidStr == "" || name == "" {
				continue
			}

			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				continue
			}

			records = append(records, Record{
				Timestamp: time.Now(),
				Source:    "wmic_process",
				Data: map[string]interface{}{
					"pid":  pid,
					"name": name,
					"exe":  exePath,
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

// ProcessMemoryCollector collects process memory information
type ProcessMemoryCollector struct{}

func (c *ProcessMemoryCollector) Name() string {
	return "process.memory"
}

func (c *ProcessMemoryCollector) Description() string {
	return "Collects memory usage information for each process"
}

func (c *ProcessMemoryCollector) Platform() string {
	return "all"
}

func (c *ProcessMemoryCollector) IsAvailable() bool {
	return true
}

func (c *ProcessMemoryCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	if runtime.GOOS == "linux" {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return nil, fmt.Errorf("failed to read /proc: %w", err)
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}

			// Read /proc/[pid]/status for memory info
			status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
			if err != nil {
				continue
			}

			data := make(map[string]interface{})
			data["pid"] = pid

			lines := strings.Split(string(status), "\n")
			for _, line := range lines {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) != 2 {
					continue
				}
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])

				switch key {
				case "Name":
					data["name"] = value
				case "VmSize":
					data["vm_size_kb"] = parseMemoryValue(value)
				case "VmRSS":
					data["vm_rss_kb"] = parseMemoryValue(value)
				case "VmData":
					data["vm_data_kb"] = parseMemoryValue(value)
				case "VmStk":
					data["vm_stack_kb"] = parseMemoryValue(value)
				case "VmExe":
					data["vm_exe_kb"] = parseMemoryValue(value)
				case "VmLib":
					data["vm_lib_kb"] = parseMemoryValue(value)
				}
			}

			records = append(records, Record{
				Timestamp: time.Now(),
				Source:    "procfs_status",
				Data:      data,
			})
		}
	} else {
		// Windows: use tasklist
		cmd := exec.CommandContext(ctx, "tasklist", "/fo", "csv")
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("failed to run tasklist: %w", err)
		}

		lines := strings.Split(string(output), "\n")
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || i == 0 {
				continue
			}

			fields := strings.Split(line, ",")
			if len(fields) >= 5 {
				name := strings.Trim(fields[0], "\"")
				pidStr := strings.Trim(fields[1], "\"")
				memStr := strings.Trim(fields[4], "\"")

				pid, _ := strconv.Atoi(pidStr)
				memStr = strings.ReplaceAll(memStr, ",", "")
				memStr = strings.ReplaceAll(memStr, " K", "")
				mem, _ := strconv.ParseInt(memStr, 10, 64)

				records = append(records, Record{
					Timestamp: time.Now(),
					Source:    "tasklist",
					Data: map[string]interface{}{
						"pid":        pid,
						"name":       name,
						"memory_kb":  mem,
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

func parseMemoryValue(value string) int64 {
	// Parse memory values like "12345 kB"
	parts := strings.Fields(value)
	if len(parts) == 0 {
		return 0
	}
	val, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0
	}
	return val
}
