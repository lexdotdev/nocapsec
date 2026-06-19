package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaults(t *testing.T) {
	d := Defaults()
	if d.ListenAddr != ":8080" {
		t.Fatalf("ListenAddr = %q", d.ListenAddr)
	}
	if d.Pools.HTTPReplay != 5 {
		t.Fatalf("HTTPReplay = %d", d.Pools.HTTPReplay)
	}
	if d.Pools.Timing != 1 {
		t.Fatalf("Timing = %d", d.Pools.Timing)
	}
	if d.Serve.ReadHeaderTimeout == 0 {
		t.Fatal("ReadHeaderTimeout zero")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(path, []byte(`{"listen_addr":":9090","pools":{"http_replay":10}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	c := LoadFile(path)
	if c.ListenAddr != ":9090" {
		t.Fatalf("ListenAddr = %q", c.ListenAddr)
	}
	if c.Pools.HTTPReplay != 10 {
		t.Fatalf("HTTPReplay = %d", c.Pools.HTTPReplay)
	}
	// Unset fields get defaults.
	if c.Pools.Timing != 1 {
		t.Fatalf("Timing = %d, want 1", c.Pools.Timing)
	}
}

func TestLoadFileMissing(t *testing.T) {
	c := LoadFile("/nonexistent")
	if c.ListenAddr != ":8080" {
		t.Fatalf("missing file should return defaults, got %q", c.ListenAddr)
	}
}

func TestApplyEnv(t *testing.T) {
	t.Setenv("NOCAPSEC_LISTEN_ADDR", ":3000")
	t.Setenv("NOCAPSEC_POOL_HTTP_REPLAY", "20")
	t.Setenv("NOCAPSEC_INTERNAL_ASSESSMENT", "true")

	c := Defaults().ApplyEnv()
	if c.ListenAddr != ":3000" {
		t.Fatalf("ListenAddr = %q", c.ListenAddr)
	}
	if c.Pools.HTTPReplay != 20 {
		t.Fatalf("HTTPReplay = %d", c.Pools.HTTPReplay)
	}
	if !c.InternalAssessment {
		t.Fatal("InternalAssessment not set from env")
	}
}

func TestApplyFlags(t *testing.T) {
	internal := true
	c := Defaults().ApplyFlags(":4000", 15, 0, 0, 0, &internal)
	if c.ListenAddr != ":4000" {
		t.Fatalf("ListenAddr = %q", c.ListenAddr)
	}
	if c.Pools.HTTPReplay != 15 {
		t.Fatalf("HTTPReplay = %d", c.Pools.HTTPReplay)
	}
	// Zero flags leave defaults.
	if c.Pools.Timing != 1 {
		t.Fatalf("Timing = %d", c.Pools.Timing)
	}
	if !c.InternalAssessment {
		t.Fatal("InternalAssessment not set from flags")
	}
}

func TestPrecedence_FlagOverridesEnv(t *testing.T) {
	t.Setenv("NOCAPSEC_LISTEN_ADDR", ":3000")
	c := Defaults().ApplyEnv().ApplyFlags(":5000", 0, 0, 0, 0, nil)
	if c.ListenAddr != ":5000" {
		t.Fatalf("flag should override env, got %q", c.ListenAddr)
	}
}

func TestLookupTarget(t *testing.T) {
	c := Config{
		Targets: TargetConfigs{
			"acme-prod": {
				ScopeID:        "acme-prod",
				AllowedSchemes: []string{"https"},
				AllowedHosts:   []string{"app.acme.com"},
			},
		},
	}
	tc, ok := c.LookupTarget("acme-prod")
	if !ok {
		t.Fatal("target not found")
	}
	if tc.AllowedHosts[0] != "app.acme.com" {
		t.Fatalf("host = %q", tc.AllowedHosts[0])
	}
	_, ok = c.LookupTarget("missing")
	if ok {
		t.Fatal("missing target found")
	}
}
