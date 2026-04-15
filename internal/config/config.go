// Package config provides configuration management for IntrusionScope
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/viper"
)

// Config holds all configuration for IntrusionScope
type Config struct {
	General   GeneralConfig   `mapstructure:"general"`
	Collector CollectorConfig `mapstructure:"collector"`
	Detector  DetectorConfig  `mapstructure:"detector"`
	Sync      SyncConfig      `mapstructure:"sync"`
	Output    OutputConfig    `mapstructure:"output"`
	Logging   LoggingConfig   `mapstructure:"logging"`
}

// GeneralConfig holds general settings
type GeneralConfig struct {
	TempDir     string `mapstructure:"temp_dir"`
	MaxWorkers  int    `mapstructure:"max_workers"`
	Timeout     int    `mapstructure:"timeout"` // seconds
	OfflineMode bool   `mapstructure:"offline_mode"`
}

// CollectorConfig holds collector settings
type CollectorConfig struct {
	DefaultPreset string `mapstructure:"default_preset"`
	MaxFileSize   int64  `mapstructure:"max_file_size"` // bytes
	HashAlgorithms []string `mapstructure:"hash_algorithms"`
}

// DetectorConfig holds detector settings
type DetectorConfig struct {
	MinSeverity    string `mapstructure:"min_severity"`
	EnableYARA     bool   `mapstructure:"enable_yara"`
	EnableSigma    bool   `mapstructure:"enable_sigma"`
	EnableIOC      bool   `mapstructure:"enable_ioc"`
	MaxMemoryMB    int    `mapstructure:"max_memory_mb"`
}

// SyncConfig holds signature sync settings
type SyncConfig struct {
	Enabled       bool     `mapstructure:"enabled"`
	UpdateInterval int      `mapstructure:"update_interval"` // hours
	Sources       []string `mapstructure:"sources"`
	CacheDir      string   `mapstructure:"cache_dir"`
}

// OutputConfig holds output settings
type OutputConfig struct {
	DefaultFormat string `mapstructure:"default_format"`
	OutputDir     string `mapstructure:"output_dir"`
	Compress      bool   `mapstructure:"compress"`
}

// LoggingConfig holds logging settings
type LoggingConfig struct {
	Level    string `mapstructure:"level"`
	Format   string `mapstructure:"format"` // json or text
	FilePath string `mapstructure:"file_path"`
	MaxSize  int    `mapstructure:"max_size"` // MB
}

// Load loads configuration from file and environment
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Set config file
	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Look for config in standard locations
		v.SetConfigName(".intrusionscope")
		v.SetConfigType("ini")
		v.AddConfigPath(".")
		v.AddConfigPath(getConfigDir())
		v.AddConfigPath("/etc/intrusionscope")
	}

	// Read environment variables
	v.SetEnvPrefix("IS")
	v.AutomaticEnv()

	// Read config file (ignore if not found)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found, use defaults
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Apply post-processing
	applyDefaults(&cfg)

	return &cfg, nil
}

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

func applyDefaults(cfg *Config) {
	if cfg.Sync.CacheDir == "" {
		cfg.Sync.CacheDir = filepath.Join(getDataDir(), "signatures")
	}
	if cfg.General.TempDir == "" {
		cfg.General.TempDir = os.TempDir()
	}
}

func getConfigDir() string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "IntrusionScope")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "intrusionscope")
}

func getDataDir() string {
	if runtime.GOOS == "windows" {
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			return filepath.Join(localAppData, "IntrusionScope", "data")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "share", "intrusionscope")
}

// Save saves configuration to file
func (c *Config) Save(path string) error {
	v := viper.New()
	v.SetConfigFile(path)

	// Set all values
	v.Set("general", c.General)
	v.Set("collector", c.Collector)
	v.Set("detector", c.Detector)
	v.Set("sync", c.Sync)
	v.Set("output", c.Output)
	v.Set("logging", c.Logging)

	return v.WriteConfig()
}
