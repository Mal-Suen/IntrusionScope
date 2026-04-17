// Package collector 提供取证 artifact 收集功能
// 该包定义了收集器接口、选项结构和结果类型，用于从系统中收集各类取证数据
package collector

import (
	"context"
	"time"
)

// Collector 是 artifact 收集器的接口定义
// 所有具体的收集器都需要实现该接口
type Collector interface {
	// Name 返回收集器的名称标识
	Name() string

	// Description 返回收集器的简要描述
	Description() string

	// Platform 返回支持的操作系统平台 (linux, windows, all)
	Platform() string

	// Collect 执行收集操作，返回收集结果
	Collect(ctx context.Context, opts *Options) (*Result, error)

	// IsAvailable 检查收集器在当前系统上是否可用
	IsAvailable() bool
}

// Options 包含收集操作的配置选项
type Options struct {
	Preset      string            // 预设模式: quick(快速), standard(标准), deep(深度)
	Timeout     time.Duration     // 收集操作的超时时间
	MaxFileSize int64             // 最大可收集文件大小
	Parameters  map[string]string // artifact 特定的参数配置
	Verbose     bool              // 是否输出详细信息
	DaysBack    int               // 查找最近文件时回溯的天数
	TargetFiles []string          // 指定要处理的目标文件列表
}

// Result 包含收集操作的结果
type Result struct {
	Collector   string                 `json:"collector"`     // 收集器名称
	Timestamp   time.Time              `json:"timestamp"`    // 收集时间戳
	Success     bool                   `json:"success"`      // 是否成功
	Error       string                 `json:"error,omitempty"` // 错误信息
	Records     []Record               `json:"records"`     // 收集到的记录
	Metadata    map[string]interface{} `json:"metadata,omitempty"` // 元数据
	Duration    time.Duration          `json:"duration"`    // 耗时
	RecordCount int                    `json:"record_count"` // 记录数量
}

// Record 表示单条收集记录
type Record struct {
	Timestamp time.Time              `json:"timestamp"` // 记录时间戳
	Source    string                 `json:"source"`   // 数据来源
	Data      map[string]interface{} `json:"data"`     // 记录数据
	Raw       []byte                 `json:"raw,omitempty"` // 原始数据
}

// Registry 管理所有收集器的注册和查询
type Registry struct {
	collectors map[string]Collector      // 收集器映射表
	byPlatform map[string][]string       // 按平台分组的收集器名称
}

// NewRegistry 创建一个新的收集器注册表
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

// Register 注册一个收集器到注册表
func (r *Registry) Register(c Collector) {
	name := c.Name()
	r.collectors[name] = c

	// 按平台分组存储
	platform := c.Platform()
	r.byPlatform[platform] = append(r.byPlatform[platform], name)
}

// Get 根据名称获取收集器
func (r *Registry) Get(name string) (Collector, bool) {
	c, ok := r.collectors[name]
	return c, ok
}

// List 返回所有收集器的名称列表
func (r *Registry) List() []string {
	names := make([]string, 0, len(r.collectors))
	for name := range r.collectors {
		names = append(names, name)
	}
	return names
}

// ListByPlatform 返回指定平台的收集器名称列表
func (r *Registry) ListByPlatform(platform string) []string {
	return r.byPlatform[platform]
}

// PresetArtifacts 定义每种预设模式对应的 artifact 列表
var PresetArtifacts = map[string][]string{
	"quick": { // 快速模式：收集最基本的信息
		"process.list",
		"network.connections",
		"network.dns_cache",
		"users.logged_in",
	},
	"standard": { // 标准模式：收集常用取证信息
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
	"deep": { // 深度模式：收集全面的取证信息
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
}            // quick, standard, deep
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
