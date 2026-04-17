// Package collector 提供取证 artifact 收集功能。
// 此文件包含采集器的注册和初始化逻辑。
package collector

import "runtime"

// init 注册所有内置采集器
func init() {
	registry = NewRegistry()

	// 进程采集器
	registry.Register(&ProcessListCollector{})
	registry.Register(&ProcessTreeCollector{})
	registry.Register(&ProcessOpenFilesCollector{})
	registry.Register(&ProcessMemoryCollector{})
	registry.Register(&ProcessModulesCollector{})

	// 网络采集器
	registry.Register(&NetworkConnectionsCollector{})
	registry.Register(&DNSCacheCollector{})
	registry.Register(&ListeningPortsCollector{})
	registry.Register(&ArpCacheCollector{})
	registry.Register(&HostsFileCollector{})

	// 文件系统采集器
	registry.Register(&FilesystemRecentFilesCollector{})
	registry.Register(&FilesystemDownloadsCollector{})
	registry.Register(&FilesystemCronJobsCollector{})
	registry.Register(&FilesystemScheduledTasksCollector{})
	registry.Register(&FilesystemSystemdServicesCollector{})
	registry.Register(&FilesystemBashHistoryCollector{})
	registry.Register(&FilesystemSuidFilesCollector{})
	registry.Register(&FilesystemAutorunsCollector{})

	// 用户采集器
	registry.Register(&LoggedInUsersCollector{})
	registry.Register(&SudoHistoryCollector{})
	registry.Register(&BashHistoryCollector{})

	// 注册表采集器（仅 Windows）
	if runtime.GOOS == "windows" {
		registry.Register(&RegistryRunKeysCollector{})
		registry.Register(&RegistryServicesCollector{})
		registry.Register(&RegistryPersistenceCollector{})
		registry.Register(&RegistryUSBHistoryCollector{})
		registry.Register(&RegistryUserAssistCollector{})
		registry.Register(&RegistryStartupCollector{})
		registry.Register(&RegistrySoftwareCollector{})
	}

	// 日志采集器
	registry.Register(&LogAuthCollector{})
	registry.Register(&LogSyslogCollector{})
	registry.Register(&LogWtmpCollector{})
	registry.Register(&LogAuditCollector{})
	registry.Register(&LogJournalCollector{})
	registry.Register(&LogWindowsEventCollector{})
	registry.Register(&LogWebServerCollector{})
}

// registry 全局采集器注册表实例
var registry *Registry

// GetRegistry 返回全局采集器注册表
func GetRegistry() *Registry {
	return registry
}
