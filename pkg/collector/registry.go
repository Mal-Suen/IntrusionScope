// Package collector provides forensic artifact collection capabilities
// This file contains Windows registry collectors
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

// RegistryRunKeysCollector collects Run/RunOnce registry keys
type RegistryRunKeysCollector struct{}

func (c *RegistryRunKeysCollector) Name() string {
	return "registry.run_keys"
}

func (c *RegistryRunKeysCollector) Description() string {
	return "Collects Run/RunOnce registry keys for persistence detection"
}

func (c *RegistryRunKeysCollector) Platform() string {
	return "windows"
}

func (c *RegistryRunKeysCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

func (c *RegistryRunKeysCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Registry keys to check
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

		// Parse registry value
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
						"location":  location,
						"key":       key,
						"name":      name,
						"type":      regType,
						"value":     value,
					},
				})
			}
		}
	}
}

// RegistryServicesCollector collects Windows services from registry
type RegistryServicesCollector struct{}

func (c *RegistryServicesCollector) Name() string {
	return "registry.services"
}

func (c *RegistryServicesCollector) Description() string {
	return "Collects Windows services configuration from registry"
}

func (c *RegistryServicesCollector) Platform() string {
	return "windows"
}

func (c *RegistryServicesCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

func (c *RegistryServicesCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Query services registry key
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

	// Parse service subkeys
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, servicesKey+"\\") {
			// Extract service name
			serviceName := strings.TrimPrefix(line, servicesKey+"\\")
			if serviceName == "" {
				continue
			}

			// Query service details
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

func (c *RegistryServicesCollector) queryServiceDetails(ctx context.Context, serviceKey string) *Record {
	data := map[string]interface{}{
		"key": serviceKey,
	}

	// Query service parameters
	params := []string{"Start", "Type", "ImagePath", "DisplayName", "ObjectName", "Description"}
	for _, param := range params {
		cmd := exec.CommandContext(ctx, "reg", "query", serviceKey, "/v", param)
		output, err := cmd.Output()
		if err != nil {
			continue
		}

		// Parse the value
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

	// Extract service name from key
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

// RegistryPersistenceCollector collects various persistence mechanisms from registry
type RegistryPersistenceCollector struct{}

func (c *RegistryPersistenceCollector) Name() string {
	return "registry.persistence"
}

func (c *RegistryPersistenceCollector) Description() string {
	return "Collects various persistence mechanisms from Windows registry"
}

func (c *RegistryPersistenceCollector) Platform() string {
	return "windows"
}

func (c *RegistryPersistenceCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

func (c *RegistryPersistenceCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Various persistence locations
	persistenceKeys := []struct {
		key  string
		name string
	}{
		// Winlogon
		{"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "winlogon"},
		{"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", "winlogon_notify"},

		// LSA Authentication packages
		{"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "lsa"},
		{"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig", "lsa_osconfig"},

		// Userinit
		{"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\IniFileMapping\\UserIni", "userinit"},

		// Shell extensions
		{"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", "shell_delay_load"},
		{"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad", "shell_delay_load_cu"},

		// Browser helper objects
		{"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", "bho"},
		{"HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects", "bho_wow64"},

		// Print monitors
		{"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors", "print_monitors"},

		// Protocol handlers
		{"HKCR\\Protocols\\Handler", "protocol_handlers"},
		{"HKCR\\Protocols\\Filter", "protocol_filters"},

		// Office addins
		{"HKCU\\SOFTWARE\\Microsoft\\Office\\Word\\Addins", "office_word_addins"},
		{"HKCU\\SOFTWARE\\Microsoft\\Office\\Excel\\Addins", "office_excel_addins"},
		{"HKCU\\SOFTWARE\\Microsoft\\Office\\Outlook\\Addins", "office_outlook_addins"},

		// AppInit DLLs
		{"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "appinit_dlls"},

		// Image File Execution Options (debugger hijacking)
		{"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "ifeo"},

		// Context menus
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

func (c *RegistryPersistenceCollector) queryPersistenceKey(ctx context.Context, key, location string, records *[]Record) {
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

		// Check if this is a subkey line
		if strings.HasPrefix(line, "HKEY_") {
			currentSubkey = line
			continue
		}

		// Check if this is a value line
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
						"location":     location,
						"key":          key,
						"subkey":       currentSubkey,
						"value_name":   name,
						"value_type":   regType,
						"value_data":   value,
					},
				})
			}
		}
	}
}

// RegistryUSBHistoryCollector collects USB device history
type RegistryUSBHistoryCollector struct{}

func (c *RegistryUSBHistoryCollector) Name() string {
	return "registry.usb_history"
}

func (c *RegistryUSBHistoryCollector) Description() string {
	return "Collects USB device connection history from registry"
}

func (c *RegistryUSBHistoryCollector) Platform() string {
	return "windows"
}

func (c *RegistryUSBHistoryCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

func (c *RegistryUSBHistoryCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// USBSTOR
	usbstorKey := "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"
	c.queryUSBDevices(ctx, usbstorKey, "USBSTOR", &records)

	// USB
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

// RegistryUserAssistCollector collects UserAssist entries (program execution history)
type RegistryUserAssistCollector struct{}

func (c *RegistryUserAssistCollector) Name() string {
	return "registry.userassist"
}

func (c *RegistryUserAssistCollector) Description() string {
	return "Collects UserAssist entries showing program execution history"
}

func (c *RegistryUserAssistCollector) Platform() string {
	return "windows"
}

func (c *RegistryUserAssistCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

func (c *RegistryUserAssistCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// UserAssist keys
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
				// Extract GUID from path
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

// RegistrySoftwareCollector collects installed software information
type RegistrySoftwareCollector struct{}

func (c *RegistrySoftwareCollector) Name() string {
	return "registry.software"
}

func (c *RegistrySoftwareCollector) Description() string {
	return "Collects installed software from registry"
}

func (c *RegistrySoftwareCollector) Platform() string {
	return "windows"
}

func (c *RegistrySoftwareCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

func (c *RegistrySoftwareCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Uninstall keys
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
			// This is a subkey (software entry)
			subkey := strings.TrimPrefix(line, key+"\\")

			// Query details
			data := map[string]interface{}{
				"registry_key": line,
				"name":         subkey,
			}

			// Get DisplayName
			cmd := exec.CommandContext(ctx, "reg", "query", line, "/v", "DisplayName", "2>nul")
			if output, err := cmd.Output(); err == nil {
				if fields := strings.Fields(string(output)); len(fields) >= 3 {
					data["display_name"] = strings.Join(fields[2:], " ")
				}
			}

			// Get DisplayVersion
			cmd = exec.CommandContext(ctx, "reg", "query", line, "/v", "DisplayVersion", "2>nul")
			if output, err := cmd.Output(); err == nil {
				if fields := strings.Fields(string(output)); len(fields) >= 3 {
					data["version"] = strings.Join(fields[2:], " ")
				}
			}

			// Get Publisher
			cmd = exec.CommandContext(ctx, "reg", "query", line, "/v", "Publisher", "2>nul")
			if output, err := cmd.Output(); err == nil {
				if fields := strings.Fields(string(output)); len(fields) >= 3 {
					data["publisher"] = strings.Join(fields[2:], " ")
				}
			}

			// Get InstallDate
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

// RegistryStartupCollector collects startup folder entries
type RegistryStartupCollector struct{}

func (c *RegistryStartupCollector) Name() string {
	return "registry.startup"
}

func (c *RegistryStartupCollector) Description() string {
	return "Collects startup folder entries"
}

func (c *RegistryStartupCollector) Platform() string {
	return "windows"
}

func (c *RegistryStartupCollector) IsAvailable() bool {
	return runtime.GOOS == "windows"
}

func (c *RegistryStartupCollector) Collect(ctx context.Context, opts *Options) (*Result, error) {
	start := time.Now()
	var records []Record

	// Startup folders
	startupFolders := []struct {
		path string
		name string
	}{
		{os.Getenv("APPDATA") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "user_startup"},
		{os.Getenv("ProgramData") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "system_startup"},
	}

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
					"location":  sf.name,
					"path":      filepath.Join(sf.path, entry.Name()),
					"name":      entry.Name(),
					"size":      info.Size(),
					"mod_time":  info.ModTime().Format("2006-01-02 15:04:05"),
					"is_dir":    entry.IsDir(),
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
