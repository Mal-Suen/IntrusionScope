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

	// Network collectors
	registry.Register(&NetworkConnectionsCollector{})
	registry.Register(&DNSCacheCollector{})
	registry.Register(&ListeningPortsCollector{})
	registry.Register(&ArpCacheCollector{})

	// Filesystem collectors
	registry.Register(&FilesystemRecentFilesCollector{})
	registry.Register(&FilesystemDownloadsCollector{})
	registry.Register(&FilesystemCronJobsCollector{})
	registry.Register(&FilesystemScheduledTasksCollector{})
	registry.Register(&FilesystemSystemdServicesCollector{})

	// User collectors
	registry.Register(&LoggedInUsersCollector{})
	registry.Register(&SudoHistoryCollector{})
	registry.Register(&BashHistoryCollector{})

	// Registry collectors (Windows only)
	if runtime.GOOS == "windows" {
		registry.Register(&RegistryRunKeysCollector{})
		registry.Register(&RegistryServicesCollector{})
		registry.Register(&RegistryPersistenceCollector{})
	}

	// Log collectors
	registry.Register(&LogAuthCollector{})
	registry.Register(&LogWindowsEventCollector{})
	registry.Register(&LogSyslogCollector{})
}

// Global registry instance
var registry *Registry

// GetRegistry returns the global collector registry
func GetRegistry() *Registry {
	return registry
}
