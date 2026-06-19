package browser

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveExecPath_Precedence(t *testing.T) {
	t.Setenv(chromeEnvVar, "/from/env/chrome")

	if got := resolveExecPath("/explicit/chrome"); got != "/explicit/chrome" {
		t.Fatalf("explicit path: got %q, want /explicit/chrome", got)
	}
	if got := resolveExecPath(""); got != "/from/env/chrome" {
		t.Fatalf("env override: got %q, want /from/env/chrome", got)
	}
}

func TestResolveExecPath_FallsThrough(t *testing.T) {
	t.Setenv(chromeEnvVar, "")
	// With no explicit path, no env var, and (most likely) no browser present in
	// the test environment, resolution returns "" to defer to chromedp. We only
	// assert it does not panic and yields an absolute path or empty string.
	got := resolveExecPath("")
	if got != "" && !filepath.IsAbs(got) {
		t.Fatalf("expected absolute path or empty, got %q", got)
	}
}

func TestIsExecutableFile(t *testing.T) {
	dir := t.TempDir()

	exe := filepath.Join(dir, "browser")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !isExecutableFile(exe) {
		t.Errorf("executable file reported as non-executable")
	}

	if isExecutableFile(dir) {
		t.Errorf("directory reported as executable file")
	}
	if isExecutableFile(filepath.Join(dir, "missing")) {
		t.Errorf("missing file reported as executable")
	}

	if runtime.GOOS != "windows" { // mode bits are advisory on Windows
		plain := filepath.Join(dir, "notes.txt")
		if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if isExecutableFile(plain) {
			t.Errorf("non-executable file reported as executable")
		}
	}
}

func TestChromeInstallPaths(t *testing.T) {
	paths := chromeInstallPaths()
	switch runtime.GOOS {
	case "darwin", "linux":
		if len(paths) == 0 {
			t.Fatalf("expected install candidates for %s", runtime.GOOS)
		}
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			t.Errorf("install path not absolute: %q", p)
		}
	}
}
