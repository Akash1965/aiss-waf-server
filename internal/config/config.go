// Package config loads AISS agent configuration from file and environment.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all runtime configuration for the AISS security agent.
type Config struct {
	// Identity
	AgentID   string `mapstructure:"agent_id"`
	ServerURL string `mapstructure:"server_url"`
	APIKey    string `mapstructure:"api_key"`

	// IPC
	SocketPath string `mapstructure:"socket_path"`

	// Storage
	DBPath string `mapstructure:"db_path"`

	// ML / Rules
	ModelPath    string  `mapstructure:"model_path"`
	RulesDir     string  `mapstructure:"rules_dir"`
	PatternsFile string  `mapstructure:"patterns_file"`
	MLThreshold  float64 `mapstructure:"ml_block_threshold"`

	// Behaviour
	LogLevel string `mapstructure:"log_level"`
	Mode     string `mapstructure:"mode"` // enforce | shadow

	// Tuning
	VerdictCacheTTL      time.Duration `mapstructure:"verdict_cache_ttl"`
	TelemetryBatchSize   int           `mapstructure:"telemetry_batch_size"`
	TelemetryFlushSec    float64       `mapstructure:"telemetry_flush_interval"`
	CVESyncIntervalSec   int           `mapstructure:"cve_sync_interval"`
	ModelCheckIntervalSec int          `mapstructure:"model_check_interval"`
	ContentFullScanLimit  int          `mapstructure:"content_full_scan_limit"`
	ContentSampleLimit    int          `mapstructure:"content_sample_scan_limit"`
	SocketTimeoutMs       int          `mapstructure:"socket_timeout_ms"`
	MaxWorkers            int          `mapstructure:"max_workers"`
}

// Load reads configuration from the given path (or defaults), then overlays
// any AISS_* environment variables.
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// ── Defaults ────────────────────────────────────────────────────────────
	v.SetDefault("agent_id", "")
	v.SetDefault("server_url", "http://localhost:8080")
	v.SetDefault("api_key", "")
	v.SetDefault("socket_path", "/tmp/aiss.sock")
	v.SetDefault("db_path", "/var/lib/aiss/aiss.db")
	v.SetDefault("model_path", "/var/lib/aiss/model.onnx")
	v.SetDefault("log_level", "info")
	v.SetDefault("mode", "enforce")
	v.SetDefault("ml_block_threshold", 0.85)
	v.SetDefault("verdict_cache_ttl", 60)
	v.SetDefault("telemetry_batch_size", 1000)
	v.SetDefault("telemetry_flush_interval", 1.0)
	v.SetDefault("cve_sync_interval", 3600)
	v.SetDefault("model_check_interval", 21600)
	v.SetDefault("content_full_scan_limit", 10*1024)
	v.SetDefault("content_sample_scan_limit", 1*1024*1024)
	v.SetDefault("socket_timeout_ms", 10)
	v.SetDefault("max_workers", runtime.NumCPU()*32)

	// ── Rules paths relative to binary location ──────────────────────────
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	v.SetDefault("rules_dir", filepath.Join(exeDir, "rules", "yara"))
	v.SetDefault("patterns_file", filepath.Join(exeDir, "rules", "hyperscan", "cve_patterns.json"))

	// ── Config file ─────────────────────────────────────────────────────
	candidates := []string{configPath, "/etc/aiss/aiss.conf", "./aiss.conf"}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			v.SetConfigFile(p)
			v.SetConfigType("toml")
			if err := v.ReadInConfig(); err != nil {
				return nil, fmt.Errorf("reading config %s: %w", p, err)
			}
			break
		}
	}

	// ── Environment overrides (AISS_<KEY>=value) ──────────────────────
	v.SetEnvPrefix("AISS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling config: %w", err)
	}

	// Convert raw int TTL to duration
	if cfg.VerdictCacheTTL == 0 {
		cfg.VerdictCacheTTL = time.Duration(v.GetInt("verdict_cache_ttl")) * time.Second
	}

	// Generate agent ID if missing
	if cfg.AgentID == "" {
		cfg.AgentID = generateID()
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.Mode != "enforce" && c.Mode != "shadow" {
		return fmt.Errorf("invalid mode %q: must be 'enforce' or 'shadow'", c.Mode)
	}
	if c.MLThreshold < 0 || c.MLThreshold > 1 {
		return fmt.Errorf("ml_block_threshold must be between 0.0 and 1.0")
	}
	return nil
}

func generateID() string {
	b := make([]byte, 8)
	// Simple deterministic ID based on hostname
	host, _ := os.Hostname()
	copy(b, []byte(host))
	return fmt.Sprintf("aiss-%x", b)
}
