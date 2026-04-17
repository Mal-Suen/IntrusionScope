// Package config 提供 IntrusionScope 的配置管理功能。
// 支持 INI/YAML 格式配置文件、环境变量覆盖和默认值设置。
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/viper"
)

// Config IntrusionScope 完整配置结构
type Config struct {
	General   GeneralConfig   `mapstructure:"general"`   // 通用设置
	Collector CollectorConfig `mapstructure:"collector"` // 采集器设置
	Detector  DetectorConfig  `mapstructure:"detector"`  // 检测器设置
	Sync      SyncConfig      `mapstructure:"sync"`      // 同步设置
	Output    OutputConfig    `mapstructure:"output"`    // 输出设置
	Logging   LoggingConfig   `mapstructure:"logging"`   // 日志设置
}

// GeneralConfig 通用配置
type GeneralConfig struct {
	TempDir     string `mapstructure:"temp_dir"`     // 临时目录
	MaxWorkers  int    `mapstructure:"max_workers"`  // 最大工作线程数
	Timeout     int    `mapstructure:"timeout"`      // 超时时间（秒）
	OfflineMode bool   `mapstructure:"offline_mode"` // 离线模式
}

// CollectorConfig 采集器配置
type CollectorConfig struct {
	DefaultPreset string   `mapstructure:"default_preset"` // 默认预设
	MaxFileSize   int64    `mapstructure:"max_file_size"`  // 最大文件大小（字节）
	HashAlgorithms []string `mapstructure:"hash_algorithms"` // 哈希算法列表
}

// DetectorConfig 检测器配置
type DetectorConfig struct {
	MinSeverity    string `mapstructure:"min_severity"` // 最低严重级别
	EnableYARA     bool   `mapstructure:"enable_yara"`  // 启用 YARA 检测
	EnableSigma    bool   `mapstructure:"enable_sigma"` // 启用 Sigma 检测
	EnableIOC      bool   `mapstructure:"enable_ioc"`   // 启用 IOC 检测
	MaxMemoryMB    int    `mapstructure:"max_memory_mb"` // 最大内存使用（MB）
}

// SyncConfig 签名同步配置
type SyncConfig struct {
	Enabled       bool     `mapstructure:"enabled"`        // 是否启用同步
	UpdateInterval int      `mapstructure:"update_interval"` // 更新间隔（小时）
	Sources       []string `mapstructure:"sources"`        // 同步源列表
	CacheDir      string   `mapstructure:"cache_dir"`      // 缓存目录
}

// OutputConfig 输出配置
type OutputConfig struct {
	DefaultFormat string `mapstructure:"default_format"` // 默认输出格式
	OutputDir     string `mapstructure:"output_dir"`     // 输出目录
	Compress      bool   `mapstructure:"compress"`       // 是否压缩
}

// LoggingConfig 日志配置
type LoggingConfig struct {
	Level    string `mapstructure:"level"`     // 日志级别
	Format   string `mapstructure:"format"`    // 日志格式：json 或 text
	FilePath string `mapstructure:"file_path"` // 日志文件路径
	MaxSize  int    `mapstructure:"max_size"`  // 日志文件最大大小（MB）
}

// Load 从文件和环境变量加载配置
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// 设置默认值
	setDefaults(v)

	// 设置配置文件
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// 在标准位置查找配置文件
		v.SetConfigName(".intrusionscope")
		v.SetConfigType("ini")
		v.AddConfigPath(".")
		v.AddConfigPath(getConfigDir())
		v.AddConfigPath("/etc/intrusionscope")
	}

	// 读取环境变量
	v.SetEnvPrefix("IS")
	v.AutomaticEnv()

	// 读取配置文件（忽略未找到的情况）
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// 配置文件未找到，使用默认值
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// 应用后处理
	applyDefaults(&cfg)

	return &cfg, nil
}

// setDefaults 设置配置默认值
func setDefaults(v *viper.Viper) {
	v.SetDefault("general.temp_dir", "")
	v.SetDefault("general.max_workers", runtime.NumCPU())
	v.SetDefault("general.timeout", 3600)
	v.SetDefault("general.offline_mode", false)

	v.SetDefault("collector.default_preset", "standard")
	v.SetDefault("collector.max_file_size", 100*1024*1024) // 100MB
	v.SetDefault("collector.hash_algorithms", []string{"md5", "sha1", "sha256"})

	v.SetDefault("detector.min_severity", "medium")
	v.SetDefault("detector.enable_yara", true)
	v.SetDefault("detector.enable_sigma", true)
	v.SetDefault("detector.enable_ioc", true)
	v.SetDefault("detector.max_memory_mb", 256)

	v.SetDefault("sync.enabled", true)
	v.SetDefault("sync.update_interval", 24)
	v.SetDefault("sync.sources", []string{"malwarebazaar", "urlhaus", "threatfox", "dshield", "spamhaus", "sigmahq", "yarahq"})
	v.SetDefault("sync.cache_dir", "")

	v.SetDefault("output.default_format", "json")
	v.SetDefault("output.output_dir", "./output")
	v.SetDefault("output.compress", false)

	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.file_path", "")
	v.SetDefault("logging.max_size", 100)
}

// applyDefaults 应用运行时默认值
func applyDefaults(cfg *Config) {
	if cfg.Sync.CacheDir == "" {
		cfg.Sync.CacheDir = filepath.Join(getDataDir(), "signatures")
	}
	if cfg.General.TempDir == "" {
		cfg.General.TempDir = os.TempDir()
	}
}

// getConfigDir 获取配置文件目录
func getConfigDir() string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "IntrusionScope")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "intrusionscope")
}

// getDataDir 获取数据目录
func getDataDir() string {
	if runtime.GOOS == "windows" {
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			return filepath.Join(localAppData, "IntrusionScope", "data")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "intrusionscope")
}

// Save 保存配置到文件
func (c *Config) Save(path string) error {
	v := viper.New()
	v.SetConfigFile(path)

	// 设置所有值
	v.Set("general", c.General)
	v.Set("collector", c.Collector)
	v.Set("detector", c.Detector)
	v.Set("sync", c.Sync)
	v.Set("output", c.Output)
	v.Set("logging", c.Logging)

	return v.WriteConfig()
}
