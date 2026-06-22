// Package config layers file, env, flags.
package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds engine-level settings.
type Config struct {
	ListenAddr string      `json:"listen_addr"`
	Pools      PoolSizes   `json:"pools"`
	Serve      ServeConfig `json:"serve"`
	// InternalAssessment allows blocked IP ranges.
	InternalAssessment bool `json:"internal_assessment"`
}

// PoolSizes caps workers per pool.
type PoolSizes struct {
	HTTPReplay int `json:"http_replay"`
	Timing     int `json:"timing"`
	Browser    int `json:"browser"`
	OAST       int `json:"oast"`
}

// ServeConfig holds HTTP server timeouts.
type ServeConfig struct {
	ReadHeaderTimeout time.Duration `json:"read_header_timeout"`
	ReadTimeout       time.Duration `json:"read_timeout"`
	WriteTimeout      time.Duration `json:"write_timeout"`
	IdleTimeout       time.Duration `json:"idle_timeout"`
}

// Defaults returns a Config with safe defaults.
func Defaults() Config {
	return Config{
		ListenAddr: ":8080",
		Pools: PoolSizes{
			HTTPReplay: 5,
			Timing:     1,
			Browser:    2,
			OAST:       8,
		},
		Serve: ServeConfig{
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
	}
}

// LoadFile reads JSON config; Defaults() on error.
func LoadFile(path string) Config {
	cfg := Defaults()
	if path == "" {
		return cfg
	}
	data, err := os.ReadFile(path) //nolint:gosec // CLI config path
	if err != nil {
		return cfg
	}
	_ = json.Unmarshal(data, &cfg)
	cfg = cfg.withDefaults()
	return cfg
}

// ApplyEnv overlays env vars on c (env > file).
func (c Config) ApplyEnv() Config {
	if v := os.Getenv("NOCAPSEC_LISTEN_ADDR"); v != "" {
		c.ListenAddr = v
	}
	c.Pools.HTTPReplay = envInt("NOCAPSEC_POOL_HTTP_REPLAY", c.Pools.HTTPReplay)
	c.Pools.Timing = envInt("NOCAPSEC_POOL_TIMING", c.Pools.Timing)
	c.Pools.Browser = envInt("NOCAPSEC_POOL_BROWSER", c.Pools.Browser)
	c.Pools.OAST = envInt("NOCAPSEC_POOL_OAST", c.Pools.OAST)
	if v := os.Getenv("NOCAPSEC_INTERNAL_ASSESSMENT"); v != "" {
		c.InternalAssessment = strings.EqualFold(v, "true") || v == "1"
	}
	return c
}

// envInt reads a positive int env, else fallback.
func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// ApplyFlags overlays flags (flags > env > file).
func (c Config) ApplyFlags(addr string, poolHTTP, poolTiming, poolBrowser, poolOAST int, internal *bool) Config {
	if addr != "" {
		c.ListenAddr = addr
	}
	if poolHTTP > 0 {
		c.Pools.HTTPReplay = poolHTTP
	}
	if poolTiming > 0 {
		c.Pools.Timing = poolTiming
	}
	if poolBrowser > 0 {
		c.Pools.Browser = poolBrowser
	}
	if poolOAST > 0 {
		c.Pools.OAST = poolOAST
	}
	if internal != nil {
		c.InternalAssessment = *internal
	}
	return c
}

// withDefaults fills zero fields from Defaults().
func (c Config) withDefaults() Config {
	d := Defaults()
	if c.ListenAddr == "" {
		c.ListenAddr = d.ListenAddr
	}
	if c.Pools.HTTPReplay == 0 {
		c.Pools.HTTPReplay = d.Pools.HTTPReplay
	}
	if c.Pools.Timing == 0 {
		c.Pools.Timing = d.Pools.Timing
	}
	if c.Pools.Browser == 0 {
		c.Pools.Browser = d.Pools.Browser
	}
	if c.Pools.OAST == 0 {
		c.Pools.OAST = d.Pools.OAST
	}
	if c.Serve.ReadHeaderTimeout == 0 {
		c.Serve.ReadHeaderTimeout = d.Serve.ReadHeaderTimeout
	}
	if c.Serve.ReadTimeout == 0 {
		c.Serve.ReadTimeout = d.Serve.ReadTimeout
	}
	if c.Serve.WriteTimeout == 0 {
		c.Serve.WriteTimeout = d.Serve.WriteTimeout
	}
	if c.Serve.IdleTimeout == 0 {
		c.Serve.IdleTimeout = d.Serve.IdleTimeout
	}
	return c
}
