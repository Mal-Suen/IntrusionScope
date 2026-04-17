// Package collector 提供取证工件收集能力
// 本文件包含进程相关的收集器实现
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

// ProcessListCollector 进程列表收集器，用于收集运行中的进程信息
type ProcessListCollector struct{}

// Name 返回收集器名称
func (c *ProcessListCollector) Name() string {
	return "process.list"
}

// Description 返回收集器描述
func (c *ProcessListCollector) Description() string {
	return "Collects list of running processes"
}

// Platform 返回支持的平台，"all" 表示支持所有平台
func (c *ProcessListCollector) Platform() string {
	return "all"
}

// IsAvailable 检查收集器在当前环境是否可用
func (c *ProcessListCollector) IsAvailable() bool {
	return true
}

// Collect 执行进程列表收集，根据操作系统选择不同的收集方法
func (c *ProcessListCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	result := &Result{
		Collector: c.Name(),
		Timestamp: start,
		Records:   []Record{},
	}

	var records []Record
	var err error

	// 根据操作系统选择不同的收集方法
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

// collectLinux 在 Linux 系统上收集进程信息，通过读取 /proc 文件系统
func (c *ProcessListCollector) collectLinux(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// 读取 /proc 目录获取所有进程
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// 尝试将目录名解析为 PID（只有数字目录才是进程目录）
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // 不是进程目录，跳过
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

// readLinuxProcessInfo 读取单个 Linux 进程的详细信息
func (c *ProcessListCollector) readLinuxProcessInfo(pid int) (*Record, error) {
	procPath := fmt.Sprintf("/proc/%d", pid)

	// 读取命令行参数
	cmdline, err := os.ReadFile(procPath + "/cmdline")
	if err != nil {
		return nil, err
	}
	// 命令行参数以空字符分隔，转换为空格分隔
	cmdlineStr := strings.ReplaceAll(string(cmdline), "\x00", " ")
	cmdlineStr = strings.TrimSpace(cmdlineStr)

	// 读取进程状态信息
	status, err := os.ReadFile(procPath + "/status")
	if err != nil {
		return nil, err
	}

	// 解析 status 文件中的关键字段
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
			// Uid 字段包含多个值：真实UID、有效UID、保存UID、文件系统UID
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

	// 读取可执行文件符号链接，获取实际路径
	exe, err := os.Readlink(procPath + "/exe")
	if err == nil {
		data["exe"] = exe
		// 检查可执行文件是否已被删除（恶意软件常见行为）
		if strings.HasSuffix(exe, " (deleted)") {
			data["exe_deleted"] = true
			data["exe"] = strings.TrimSuffix(exe, " (deleted)")
		}
	}

	// 读取当前工作目录
	cwd, err := os.Readlink(procPath + "/cwd")
	if err == nil {
		data["cwd"] = cwd
	}

	// 读取环境变量数量（可选）
	env, err := os.ReadFile(procPath + "/environ")
	if err == nil {
		envVars := strings.Split(string(env), "\x00")
		data["env_count"] = len(envVars)
	}

	// 读取 stat 文件获取额外信息（如进程状态、启动时间）
	stat, err := os.ReadFile(procPath + "/stat")
	if err == nil {
		statParts := strings.Fields(string(stat))
		if len(statParts) >= 20 {
			data["state"] = statParts[2]
			// 解析启动时间（第22个字段，单位为时钟滴答）
			if starttime, err := strconv.ParseInt(statParts[21], 10, 64); err == nil {
				// 转换为自启动以来的秒数
				data["start_time"] = starttime / 100 // 近似值
			}
		}
	}

	return &Record{
		Timestamp: time.Now(),
		Source:    "procfs",
		Data:      data,
	}, nil
}

// collectWindows 在 Windows 系统上收集进程信息，使用 wmic 或 tasklist 命令
func (c *ProcessListCollector) collectWindows(ctx context.Context, opts *Options) ([]Record, error) {
	var records []Record

	// 优先使用 wmic 获取更详细的进程信息
	cmd := exec.CommandContext(ctx, "wmic", "process", "get",
		"ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,CreationDate",
		"/format:csv")
	output, err := cmd.Output()
	if err != nil {
		// 如果 wmic 失败，回退到 tasklist
		return c.collectWindowsTasklist(ctx, opts)
	}

	// 使用 CSV 解析器处理输出，正确处理引号字段
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

		// 跳过前两行标题
		if lineNum <= 2 {
			continue
		}

		// CSV 格式：Node,CommandLine,CreationDate,ExecutablePath,Name,ParentProcessId,ProcessId
		if len(fields) < 7 {
			continue
		}

		data := make(map[string]interface{})

		// 解析 PID
		if pid, err := strconv.Atoi(fields[6]); err == nil {
			data["pid"] = pid
		}

		// 解析父进程 ID
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

// collectWindowsTasklist 使用 tasklist 命令收集进程信息（作为 wmic 的备选方案）
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
		if line == "" || i == 0 { // 跳过标题行
			continue
		}

		// CSV 格式："Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name","CPU Time","Window Title"
		fields := strings.Split(line, ",")
		if len(fields) < 4 {
			continue
		}

		data := make(map[string]interface{})

		// 清理引号包裹的字段
		name := strings.Trim(fields[0], "\"")
		pidStr := strings.Trim(fields[1], "\"")

		data["name"] = name
		if pid, err := strconv.Atoi(pidStr); err == nil {
			data["pid"] = pid
		}

		if len(fields) > 4 {
			memStr := strings.Trim(fields[4], "\"")
			// 解析内存使用量（格式如 "123,456 K"）
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

// ProcessTreeCollector 进程树收集器，用于收集进程的父子关系结构
type ProcessTreeCollector struct{}

// Name 返回收集器名称
func (c *ProcessTreeCollector) Name() string {
	return "process.tree"
}

// Description 返回收集器描述
func (c *ProcessTreeCollector) Description() string {
	return "Collects process tree structure showing parent-child relationships"
}

// Platform 返回支持的平台
func (c *ProcessTreeCollector) Platform() string {
	return "all"
}

// IsAvailable 检查收集器是否可用
func (c *ProcessTreeCollector) IsAvailable() bool {
	return true
}

// Collect 收集进程树结构，展示父子进程关系
func (c *ProcessTreeCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()

	// 首先收集进程列表
	plc := &ProcessListCollector{}
	plResult, err := plc.Collect(ctx, opts)
	if err != nil {
		return nil, err
	}

	// 构建进程树结构
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

// buildTree 根据进程列表构建父子关系树
func (c *ProcessTreeCollector) buildTree(records []Record) []Record {
	// 建立 PID 到进程数据的映射
	pidMap := make(map[int]map[string]interface{})
	// 建立父进程到子进程列表的映射
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

	// 构建进程树记录
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

// ProcessOpenFilesCollector 进程打开文件收集器，收集各进程打开的文件列表
type ProcessOpenFilesCollector struct{}

// Name 返回收集器名称
func (c *ProcessOpenFilesCollector) Name() string {
	return "process.open_files"
}

// Description 返回收集器描述
func (c *ProcessOpenFilesCollector) Description() string {
	return "Collects list of open files by each process"
}

// Platform 返回支持的平台（仅 Linux）
func (c *ProcessOpenFilesCollector) Platform() string {
	return "linux"
}

// IsAvailable 检查收集器是否可用
func (c *ProcessOpenFilesCollector) IsAvailable() bool {
	return runtime.GOOS == "linux"
}

// Collect 收集进程打开的文件信息，通过读取 /proc/[pid]/fd 目录
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

		// 读取进程的文件描述符目录
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

			// 跳过匿名 inode、管道和 socket
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

// ProcessModulesCollector 进程模块收集器，收集进程加载的模块/DLL（仅 Windows）
type ProcessModulesCollector struct{}

// Name 返回收集器名称
func (c *ProcessModulesCollector) Name() string {
	return "process.modules"
}

// Description 返回收集器描述
func (c *ProcessModulesCollector) Description() string {
	return "Collects loaded modules/DLLs by each process (Windows only)"
}

// Platform 返回支持的平台（仅 Windows）
func (c *ProcessModulesCollector) Platform() string {
	return "windows"
}

// IsAvailable 检查收集器是否可用
func (c *ProcessModulesCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// Collect 收集进程模块信息
func (c *ProcessModulesCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 使用 wmic 获取进程信息
	cmd := exec.CommandContext(ctx, "wmic", "process", "get", "ProcessId,Name,ExecutablePath",
		"/format:csv")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get process list: %w", err)
	}

	// 解析输出
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

// ProcessMemoryCollector 进程内存收集器，收集各进程的内存使用信息
type ProcessMemoryCollector struct{}

// Name 返回收集器名称
func (c *ProcessMemoryCollector) Name() string {
	return "process.memory"
}

// Description 返回收集器描述
func (c *ProcessMemoryCollector) Description() string {
	return "Collects memory usage information for each process"
}

// Platform 返回支持的平台
func (c *ProcessMemoryCollector) Platform() string {
	return "all"
}

// IsAvailable 检查收集器是否可用
func (c *ProcessMemoryCollector) IsAvailable() bool {
	return true
}

// Collect 收集进程内存使用信息
func (c *ProcessMemoryCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	if runtime.GOOS == "linux" {
		// Linux: 通过 /proc/[pid]/status 读取内存信息
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

			// 读取进程状态文件获取内存信息
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
		// Windows: 使用 tasklist 获取内存信息
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
						"pid":       pid,
						"name":      name,
						"memory_kb": mem,
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

// parseMemoryValue 解析内存值字符串（如 "12345 kB"）
func parseMemoryValue(value string) int64 {
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
