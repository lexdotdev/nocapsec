package browser

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/chromedp/chromedp"
)

// ephemeralContext creates a chromedp allocator with an ephemeral user-data-dir
// that is destroyed when cleanup is called. proxyURL routes all browser egress
// through the policy CONNECT proxy; execPath pins the browser binary.
func ephemeralContext(parent context.Context, proxyURL, execPath string) (ctx context.Context, cleanup func(), err error) {
	dir, err := os.MkdirTemp("", "nocapsec-browser-*")
	if err != nil {
		return nil, nil, err
	}

	opts := append(
		chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserDataDir(dir),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("disable-sync", true),
		chromedp.Flag("disable-translate", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("no-first-run", true),
	)

	if path := resolveExecPath(execPath); path != "" {
		opts = append(opts, chromedp.ExecPath(path))
	}
	if proxyURL != "" {
		opts = append(opts, chromedp.ProxyServer(proxyURL))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(parent, opts...)
	taskCtx, taskCancel := chromedp.NewContext(allocCtx)

	cleanup = func() {
		taskCancel()
		allocCancel()
		os.RemoveAll(dir) //nolint:errcheck // best-effort cleanup of temp dir
	}

	return taskCtx, cleanup, nil
}

// chromeEnvVar pins the browser binary without a flag (handy in containers/CI).
const chromeEnvVar = "NOCAPSEC_CHROME_PATH"

// chromeCommands are Chrome/Chromium executable names looked up on PATH.
var chromeCommands = []string{
	"google-chrome",
	"google-chrome-stable",
	"chromium",
	"chromium-browser",
	"chrome",
}

// resolveExecPath locates the browser binary in precedence order: explicit path,
// NOCAPSEC_CHROME_PATH, a command on PATH, then a known per-OS install location.
// Returns "" to defer to chromedp's own detection.
func resolveExecPath(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv(chromeEnvVar); env != "" {
		return env
	}
	for _, name := range chromeCommands {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	for _, path := range chromeInstallPaths() {
		if isExecutableFile(path) {
			return path
		}
	}
	return ""
}

// chromeInstallPaths is a HACK: it lists well-known install locations for the host OS, where
// the browser is commonly absent from PATH (notably macOS app bundles).
func chromeInstallPaths() []string {
	switch runtime.GOOS {
	case "darwin":
		paths := []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Google Chrome Beta.app/Contents/MacOS/Google Chrome Beta",
			"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
		}
		if home, err := os.UserHomeDir(); err == nil {
			paths = append(paths,
				filepath.Join(home, "Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
				filepath.Join(home, "Applications/Chromium.app/Contents/MacOS/Chromium"),
			)
		}
		return paths
	case "windows":
		var paths []string
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			if dir := os.Getenv(env); dir != "" {
				paths = append(paths,
					filepath.Join(dir, `Google\Chrome\Application\chrome.exe`),
					filepath.Join(dir, `Chromium\Application\chrome.exe`),
				)
			}
		}
		return paths
	default: // linux and other unix
		return []string{
			"/usr/bin/google-chrome",
			"/usr/bin/google-chrome-stable",
			"/usr/bin/chromium",
			"/usr/bin/chromium-browser",
			"/snap/bin/chromium",
			"/usr/local/bin/chrome",
		}
	}
}

// isExecutableFile reports whether path is a regular file runnable by the OS.
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true // mode bits are not meaningful on Windows
	}
	return info.Mode()&0o111 != 0
}
