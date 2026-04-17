// Package collector provides forensic artifact collection capabilities
package collector

import (
	"context"
	"time"
)

// Collector is the interface for artifact collectors
type Collector interface {
	// Name returns the collector name
	Name() string

	// Description returns a brief description
	Description() string

	// Platform returns supported platforms (linux, windows, all)
	Platform() string

	// Collect performs the collection
	Collect(ctx context.Context, opts *Options) (*Result, error)

	// IsAvailable checks if the collector is available on this system
	IsAvailable() bool
}

// Options contains collection options
type Options struct {
	Preset      string            // quick, standard, deep
	Timeout     time.Duration     // collection timeout
	MaxFileSize int64             // maximum file size to collect
	Parameters  map[string]string // artifact-specific parameters
	Verbose     bool              // verbose output
	DaysBack    int               // days to look back for recent files
	TargetFiles []string          // specific files to process
}

// Result contains collection results
type Result struct {
	Collector   string                 `json:"collector"`
	Timestamp   time.Time              `json:"timestamp"`
	Success     bool                   `json:"success"`
	Error       string                 `json:"error,omitempty"`
	Records     []Record               `json:"records"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Duration    time.Duration          `json:"duration"`
	RecordCount int                    `json:"record_count"`
}

// Record represents a single collected record
type Record struct {
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Data      map[string]interface{} `json:"data"`
	Raw       []byte                 `json:"raw,omitempty"`
}

// Registry manages all collectors
type Registry struct {
	collectors map[string]Collector
	byPlatform map[string][]string
}

// NewRegistry creates a new collector registry
func NewRegistry() *Registry {
	return &Registry{
		collectors: make(map[string]Collector),
		byPlatform: map[string][]string{
			"linux":   {},
			"windows": {},
			"all":     {},
		},
	}
}

// Register registers a collector
func (r *Registry) Register(c Collector) {
	name := c.Name()
	r.collectors[name] = c

	platform := c.Platform()
	r.byPlatform[platform] = append(r.byPlatform[platform], name)
}

// Get retrieves a collector by name
func (r *Registry) Get(name string) (Collector, bool) {
	c, ok := r.collectors[name]
	return c, ok
}

// List returns all collector names
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.collectors))
	for name := range r.collectors {
		names = append(names, name)
	}
	return names
}

// ListByPlatform returns collectors for a specific platform
func (r *Registry) ListByPlatform(platform string) []string {
	return r.byPlatform[platform]
}

// PresetArtifacts defines artifacts for each preset
var PresetArtifacts = map[string][]string{
	"quick": {
		"process.list",
		"network.connections",
		"network.dns_cache",
		"users.logged_in",
	},
	"standard": {
		"process.list",
		"process.tree",
		"network.connections",
		"network.dns_cache",
		"network.listening_ports",
		"users.logged_in",
		"users.sudo_history",
		"filesystem.recent_files",
		"registry.run_keys",       // Windows
		"filesystem.cron_jobs",    // Linux
		"filesystem.scheduled_tasks", // Windows
	},
	"deep": {
		"process.list",
		"process.tree",
		"process.open_files",
		"process.memory_info",
		"network.connections",
		"network.dns_cache",
		"network.listening_ports",
		"network.arp_cache",
		"network.hosts",
		"users.logged_in",
		"users.sudo_history",
		"users.bash_history",
		"filesystem.recent_files",
		"filesystem.suid_files",
		"filesystem.bash_history",
		"registry.run_keys",
		"registry.services",
		"registry.persistence",
		"registry.usb_history",
		"registry.userassist",
		"filesystem.cron_jobs",
		"filesystem.scheduled_tasks",
		"filesystem.systemd_services",
		"log.auth",
		"log.syslog",
		"log.wtmp",
		"log.windows_event",
	},
}
