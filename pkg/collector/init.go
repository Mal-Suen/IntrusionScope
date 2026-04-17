// Package collector provides forensic artifact collection capabilities
// This file contains the registry initialization
package collector

import "runtime"

// init registers all built-in collectors
func init() {
	registry = NewRegistry()

	// Process collectors
	registry.Register(&ProcessListCollector{})
	registry.Register(&ProcessTreeCollector{})
	registry.Register(&ProcessOpenFilesCollector{})
	registry.Register(&ProcessMemoryCollector{})
	registry.Register(&ProcessModulesCollector{})

	// Network collectors
	registry.Register(&NetworkConnectionsCollector{})
	registry.Register(&DNSCacheCollector{})
	registry.Register(&ListeningPortsCollector{})
	registry.Register(&ArpCacheCollector{})
	registry.Register(&HostsFileCollector{})

	// Filesystem collectors
	registry.Register(&FilesystemRecentFilesCollector{})
	registry.Register(&FilesystemDownloadsCollector{})
	registry.Register(&FilesystemCronJobsCollector{})
	registry.Register(&FilesystemScheduledTasksCollector{})
	registry.Register(&FilesystemSystemdServicesCollector{})
	registry.Register(&FilesystemBashHistoryCollector{})
	registry.Register(&FilesystemSuidFilesCollector{})
	registry.Register(&FilesystemAutorunsCollector{})

	// User collectors
	registry.Register(&LoggedInUsersCollector{})
	registry.Register(&SudoHistoryCollector{})
	registry.Register(&BashHistoryCollector{})

	// Registry collectors (Windows only)
	if runtime.GOOS == "windows" {
		registry.Register(&RegistryRunKeysCollector{})
		registry.Register(&RegistryServicesCollector{})
		registry.Register(&RegistryPersistenceCollector{})
		registry.Register(&RegistryUSBHistoryCollector{})
		registry.Register(&RegistryUserAssistCollector{})
		registry.Register(&RegistryStartupCollector{})
		registry.Register(&RegistrySoftwareCollector{})
	}

	// Log collectors
	registry.Register(&LogAuthCollector{})
	registry.Register(&LogSyslogCollector{})
	registry.Register(&LogWtmpCollector{})
	registry.Register(&LogAuditCollector{})
	registry.Register(&LogJournalCollector{})
	registry.Register(&LogWindowsEventCollector{})
	registry.Register(&LogWebServerCollector{})
}

// Global registry instance
var registry *Registry

// GetRegistry returns the global collector registry
func GetRegistry() *Registry {
	return registry
}
