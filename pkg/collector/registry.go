// Package collector 提供取证工件收集能力
// 本文件包含 Windows 注册表相关的收集器实现
package collector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// RegistryRunKeysCollector Run/RunOnce 注册表键收集器，用于检测持久化机制
type RegistryRunKeysCollector struct{}

// Name 返回收集器名称
func (c *RegistryRunKeysCollector) Name() string {
	return "registry.run_keys"
}

// Description 返回收集器描述
func (c *RegistryRunKeysCollector) Description() string {
	return "Collects Run/RunOnce registry keys for persistence detection"
}

// Platform 返回支持的平台（仅 Windows）
func (c *RegistryRunKeysCollector) Platform() string {
	return "windows"
}

// IsAvailable 检查收集器是否可用
func (c *RegistryRunKeysCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// Collect 收集 Run/RunOnce 注册表键
func (c *RegistryRunKeysCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 需要检查的注册表位置
	runKeys := []struct {
		key  string
		name string
	}{
		{"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM_Run"},
		{"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM_RunOnce"},
		{"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU_Run"},
		{"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU_RunOnce"},
		{"HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM_Run_Wow64"},
		{"HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKLM_RunOnce_Wow64"},
	}

	// 查询每个注册表键
	for _, rk := range runKeys {
		c.queryRegistryKey(ctx, rk.key, rk.name, &records)
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

// queryRegistryKey 查询单个注册表键的值
func (c *RegistryRunKeysCollector) queryRegistryKey(ctx context.Context, key, location string, records *[]Record) {
	cmd := exec.CommandContext(ctx, "reg", "query", key)
	output, err := cmd.Output()
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, key) || strings.HasPrefix(line, "HKEY_") {
			continue
		}

		// 解析注册表值
		if strings.Contains(line, "REG_SZ") || strings.Contains(line, "REG_EXPAND_SZ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				name := fields[0]
				regType := fields[1]
				value := strings.Join(fields[2:], " ")

				*records = append(*records, Record{
					Timestamp: time.Now(),
					Source:    "registry_run",
					Data: map[string]interface{}{
						"location": location,
						"key":      key,
						"name":     name,
						"type":     regType,
						"value":    value,
					},
				})
			}
		}
	}
}

// RegistryServicesCollector Windows 服务注册表收集器，从注册表收集服务配置
type RegistryServicesCollector struct{}

// Name 返回收集器名称
func (c *RegistryServicesCollector) Name() string {
	return "registry.services"
}

// Description 返回收集器描述
func (c *RegistryServicesCollector) Description() string {
	return "Collects Windows services configuration from registry"
}

// Platform 返回支持的平台（仅 Windows）
func (c *RegistryServicesCollector) Platform() string {
	return "windows"
}

// IsAvailable 检查收集器是否可用
func (c *RegistryServicesCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// Collect 收集 Windows 服务配置
func (c *RegistryServicesCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 查询服务注册表键
	servicesKey := "HKLM\\SYSTEM\\CurrentControlSet\\Services"
	cmd := exec.CommandContext(ctx, "reg", "query", servicesKey)
	output, err := cmd.Output()
	if err != nil {
		return &Result{
			Collector: c.Name(),
			Timestamp: start,
			Success:   false,
			Error:     fmt.Sprintf("failed to query services: %v", err),
		}, err
	}

	// 解析服务子键
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, servicesKey+"\\") {
			// 提取服务名称
			serviceName := strings.TrimPrefix(line, servicesKey+"\\")
			if serviceName == "" {
				continue
			}

			// 查询服务详细信息
			serviceRecord := c.queryServiceDetails(ctx, servicesKey+"\\"+serviceName)
			if serviceRecord != nil {
				records = append(records, *serviceRecord)
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

// queryServiceDetails 查询单个服务的详细信息
func (c *RegistryServicesCollector) queryServiceDetails(ctx context.Context, serviceKey string) *Record {
	data := map[string]interface{}{
		"key": serviceKey,
	}

	// 查询服务参数
	params := []string{"Start", "Type", "ImagePath", "DisplayName", "ObjectName", "Description"}
	for _, param := range params {
		cmd := exec.CommandContext(ctx, "reg", "query", serviceKey, "/v", param)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		// 解析值
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.Contains(line, param) {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					data[param] = strings.Join(fields[2:], " ")
				}
			}
		}
	}

	// 从键路径提取服务名称
	parts := strings.Split(serviceKey, "\\")
	if len(parts) > 0 {
		data["name"] = parts[len(parts)-1]
	}

	return &Record{
		Timestamp: time.Now(),
		Source:    "registry_services",
		Data:      data,
	}
}

// RegistryPersistenceCollector 注册表持久化机制收集器，收集各种持久化机制
type RegistryPersistenceCollector struct{}

// Name 返回收集器名称
func (c *RegistryPersistenceCollector) Name() string {
	return "registry.persistence"
}

// Description 返回收集器描述
func (c *RegistryPersistenceCollector) Description() string {
	return "Collects various persistence mechanisms from Windows registry"
}

// Platform 返回支持的平台（仅 Windows）
func (c *RegistryPersistenceCollector) Platform() string {
	return "windows"
}

// IsAvailable 检查收集器是否可用
func (c *RegistryPersistenceCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// Collect 收集各种持久化机制
func (c *RegistryPersistenceCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 各种持久化位置
	persistenceKeys := []struct {
		key  string
		name string
	}{
		// Winlogon 相关
		{"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "winlogon"},
		{"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", "winlogon_notify"},

		// LSA 认证包
		{"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "lsa"},
		{"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", "lsa_osconfig"},

		// Userinit
		{"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\IniFileMapping\\UserIni", "userinit"},

		// Shell 扩展
		{"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", "shell_delay_load"},
		{"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", "shell_delay_load_cu"},

		// 浏览器辅助对象（BHO）
		{"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", "bho"},
		{"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", "bho_wow64"},

		// 打印监视器
		{"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", "print_monitors"},

		// 协议处理器
		{"HKCR\\Protocols\\Handler", "protocol_handlers"},
		{"HKCR\\Protocols\\Filter", "protocol_filters"},

		// Office 插件
		{"HKCU\\SOFTWARE\\Microsoft\\Office\\Word\\Addins", "office_word_addins"},
		{"HKCU\\SOFTWARE\\Microsoft\\Office\\Excel\\Addins", "office_excel_addins"},
		{"HKCU\\SOFTWARE\\Microsoft\\Office\\Outlook\\Addins", "office_outlook_addins"},

		// AppInit DLLs
		{"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "appinit_dlls"},

		// 映像文件执行选项（调试器劫持）
		{"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "ifeo"},

		// 右键菜单
		{"HKCR\\*\\shell", "context_menu_file"},
		{"HKCR\\Directory\\shell", "context_menu_dir"},
		{"HKCR\\Folder\\shell", "context_menu_folder"},

		// Active Setup
		{"HKLM\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components", "active_setup"},
		{"HKCU\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components", "active_setup_cu"},

		// Session Manager
		{"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager", "session_manager"},

		// Boot execute
		{"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\BootExecute", "boot_execute"},
	}

	// 查询每个持久化位置
	for _, pk := range persistenceKeys {
		c.queryPersistenceKey(ctx, pk.key, pk.name, &records)
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

// queryPersistenceKey 查询持久化相关的注册表键
func (c *RegistryPersistenceCollector) queryPersistenceKey(ctx context.Context, key, location string, records *[]Record) {
	// 使用 /s 递归查询
	cmd := exec.CommandContext(ctx, "reg", "query", key, "/s")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var currentSubkey string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// 检查是否为子键行
		if strings.HasPrefix(line, "HKEY_") {
			currentSubkey = line
			continue
		}

		// 检查是否为值行
		if strings.Contains(line, "REG_") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				name := fields[0]
				regType := fields[1]
				value := strings.Join(fields[2:], " ")

				*records = append(*records, Record{
					Timestamp: time.Now(),
					Source:    "registry_persistence",
					Data: map[string]interface{}{
						"location":   location,
						"key":        key,
						"subkey":     currentSubkey,
						"value_name": name,
						"value_type": regType,
						"value_data": value,
					},
				})
			}
		}
	}
}

// RegistryUSBHistoryCollector USB 设备历史收集器，从注册表收集 USB 设备连接历史
type RegistryUSBHistoryCollector struct{}

// Name 返回收集器名称
func (c *RegistryUSBHistoryCollector) Name() string {
	return "registry.usb_history"
}

// Description 返回收集器描述
func (c *RegistryUSBHistoryCollector) Description() string {
	return "Collects USB device connection history from registry"
}

// Platform 返回支持的平台（仅 Windows）
func (c *RegistryUSBHistoryCollector) Platform() string {
	return "windows"
}

// IsAvailable 检查收集器是否可用
func (c *RegistryUSBHistoryCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// Collect 收集 USB 设备连接历史
func (c *RegistryUSBHistoryCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// USBSTOR 设备
	usbstorKey := "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
	c.queryUSBDevices(ctx, usbstorKey, "USBSTOR", &records)

	// USB 设备
	usbKey := "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB"
	c.queryUSBDevices(ctx, usbKey, "USB", &records)

	return &Result{
		Collector:   c.Name(),
		Timestamp:   start,
		Success:     true,
		Records:     records,
		RecordCount: len(records),
		Duration:    time.Since(start),
	}, nil
}

// queryUSBDevices 查询 USB 设备信息
func (c *RegistryUSBHistoryCollector) queryUSBDevices(ctx context.Context, key, source string, records *[]Record) {
	cmd := exec.CommandContext(ctx, "reg", "query", key, "/s")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var currentDevice string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "HKEY_") {
			currentDevice = line
			continue
		}

		if strings.Contains(line, "REG_") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				*records = append(*records, Record{
					Timestamp: time.Now(),
					Source:    "usb_" + source,
					Data: map[string]interface{}{
						"device_key": currentDevice,
						"value_name": fields[0],
						"value_type": fields[1],
						"value_data": strings.Join(fields[2:], " "),
					},
				})
			}
		}
	}
}

// RegistryUserAssistCollector UserAssist 条目收集器，收集程序执行历史
type RegistryUserAssistCollector struct{}

// Name 返回收集器名称
func (c *RegistryUserAssistCollector) Name() string {
	return "registry.userassist"
}

// Description 返回收集器描述
func (c *RegistryUserAssistCollector) Description() string {
	return "Collects UserAssist entries showing program execution history"
}

// Platform 返回支持的平台（仅 Windows）
func (c *RegistryUserAssistCollector) Platform() string {
	return "windows"
}

// IsAvailable 检查收集器是否可用
func (c *RegistryUserAssistCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// Collect 收集 UserAssist 条目
func (c *RegistryUserAssistCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// UserAssist 键位置
	userAssistKeys := []string{
		"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
	}

	for _, key := range userAssistKeys {
		cmd := exec.CommandContext(ctx, "reg", "query", key, "/s")
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		var currentGuid string

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "HKEY_") {
				// 从路径提取 GUID
				parts := strings.Split(line, "\\")
				if len(parts) > 0 {
					currentGuid = parts[len(parts)-1]
				}
				continue
			}

			if strings.Contains(line, "REG_") {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					records = append(records, Record{
						Timestamp: time.Now(),
						Source:    "userassist",
						Data: map[string]interface{}{
							"guid":       currentGuid,
							"value_name": fields[0],
							"value_type": fields[1],
							"value_data": strings.Join(fields[2:], " "),
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

// RegistrySoftwareCollector 已安装软件收集器，从注册表收集已安装软件信息
type RegistrySoftwareCollector struct{}

// Name 返回收集器名称
func (c *RegistrySoftwareCollector) Name() string {
	return "registry.software"
}

// Description 返回收集器描述
func (c *RegistrySoftwareCollector) Description() string {
	return "Collects installed software from registry"
}

// Platform 返回支持的平台（仅 Windows）
func (c *RegistrySoftwareCollector) Platform() string {
	return "windows"
}

// IsAvailable 检查收集器是否可用
func (c *RegistrySoftwareCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// Collect 收集已安装软件信息
func (c *RegistrySoftwareCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 卸载键位置
	uninstallKeys := []string{
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
	}

	for _, key := range uninstallKeys {
		c.queryUninstallKey(ctx, key, &records)
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

// queryUninstallKey 查询卸载键获取软件信息
func (c *RegistrySoftwareCollector) queryUninstallKey(ctx context.Context, key string, records *[]Record) {
	cmd := exec.CommandContext(ctx, "reg", "query", key)
	output, err := cmd.Output()
	if err != nil {
		return
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, key+"\\") {
			// 这是一个子键（软件条目）
			subkey := strings.TrimPrefix(line, key+"\\")

			// 查询详细信息
			data := map[string]interface{}{
				"registry_key": line,
				"name":         subkey,
			}

			// 获取显示名称
			cmd := exec.CommandContext(ctx, "reg", "query", line, "/v", "DisplayName", "2>nul")
			if output, err := cmd.Output(); err == nil {
				if fields := strings.Fields(string(output)); len(fields) >= 3 {
					data["display_name"] = strings.Join(fields[2:], " ")
				}
			}

			// 获取版本号
			cmd = exec.CommandContext(ctx, "reg", "query", line, "/v", "DisplayVersion", "2>nul")
			if output, err := cmd.Output(); err == nil {
				if fields := strings.Fields(string(output)); len(fields) >= 3 {
					data["version"] = strings.Join(fields[2:], " ")
				}
			}

			// 获取发布者
			cmd = exec.CommandContext(ctx, "reg", "query", line, "/v", "Publisher", "2>nul")
			if output, err := cmd.Output(); err == nil {
				if fields := strings.Fields(string(output)); len(fields) >= 3 {
					data["publisher"] = strings.Join(fields[2:], " ")
				}
			}

			// 获取安装日期
			cmd = exec.CommandContext(ctx, "reg", "query", line, "/v", "InstallDate", "2>nul")
			if output, err := cmd.Output(); err == nil {
				if fields := strings.Fields(string(output)); len(fields) >= 3 {
					data["install_date"] = fields[2]
				}
			}

			*records = append(*records, Record{
				Timestamp: time.Now(),
				Source:    "installed_software",
				Data:      data,
			})
		}
	}
}

// RegistryStartupCollector 启动文件夹收集器，收集启动文件夹条目
type RegistryStartupCollector struct{}

// Name 返回收集器名称
func (c *RegistryStartupCollector) Name() string {
	return "registry.startup"
}

// Description 返回收集器描述
func (c *RegistryStartupCollector) Description() string {
	return "Collects startup folder entries"
}

// Platform 返回支持的平台（仅 Windows）
func (c *RegistryStartupCollector) Platform() string {
	return "windows"
}

// IsAvailable 检查收集器是否可用
func (c *RegistryStartupCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

// Collect 收集启动文件夹条目
func (c *RegistryStartupCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// 启动文件夹位置
	startupFolders := []struct {
		path string
		name string
	}{
		{os.Getenv("APPDATA") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "user_startup"},
		{os.Getenv("ProgramData") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "system_startup"},
	}

	// 遍历启动文件夹
	for _, sf := range startupFolders {
		entries, err := os.ReadDir(sf.path)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}

			records = append(records, Record{
				Timestamp: time.Now(),
				Source:    "startup_folder",
				Data: map[string]interface{}{
					"location": sf.name,
					"path":     filepath.Join(sf.path, entry.Name()),
					"name":     entry.Name(),
					"size":     info.Size(),
					"mod_time": info.ModTime().Format("2006-01-02 15:04:05"),
					"is_dir":   entry.IsDir(),
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
