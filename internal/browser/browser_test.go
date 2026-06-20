package browser

import (
	"context"
	"net/http"
	"os/exec"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/evidence"
)

func chromiumAvailable() bool {
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable"} {
		if _, err := exec.LookPath(name); err == nil {
			return true
		}
	}
	return false
}

func skipWithoutChromium(t *testing.T) {
	t.Helper()
	if !chromiumAvailable() {
		t.Skip("chromium not installed")
	}
}

func TestOriginFromFrameURL(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"https://example.com/path?q=1", "https://example.com"},
		{"https://example.com:8443/", "https://example.com:8443"},
		{"http://localhost/foo", "http://localhost"},
		{"about:blank", "about:blank"},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got := originFromFrameURL(tc.raw)
			if got != tc.want {
				t.Fatalf("originFromFrameURL(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestHasProofSignal(t *testing.T) {
	cases := []struct {
		name    string
		signals []string
		dialogs []DialogEvent
		console []ConsoleEvent
		want    bool
	}{
		{
			"dialog from page",
			[]string{"javascript_dialog"},
			[]DialogEvent{{Type: "alert", Message: "xss"}},
			nil,
			true,
		},
		{
			"dialog from verifier hook excluded",
			[]string{"javascript_dialog"},
			[]DialogEvent{{Type: "alert", Message: "xss", FromVerifierHook: true}},
			nil,
			false,
		},
		{
			"console log signal",
			[]string{"console_log"},
			nil,
			[]ConsoleEvent{{Text: "nonce"}},
			true,
		},
		{
			"no signals configured",
			nil,
			[]DialogEvent{{Type: "alert", Message: "xss"}},
			[]ConsoleEvent{{Text: "nonce"}},
			false,
		},
		{
			"empty events",
			[]string{"javascript_dialog", "console_log"},
			nil,
			nil,
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := BrowserJob{AcceptSignals: tc.signals}
			got := hasProofSignal(job, tc.dialogs, tc.console)
			if got != tc.want {
				t.Fatalf("hasProofSignal() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEventCollector_Snapshot(t *testing.T) {
	ec := &eventCollector{}
	ec.navs = append(ec.navs, NavEvent{URL: "https://a.com/", Origin: "https://a.com"})
	ec.dialogs = append(ec.dialogs, DialogEvent{Type: "alert", Message: "hi"})
	ec.console = append(ec.console, ConsoleEvent{Text: "log"})
	ec.netEvts = append(ec.netEvts, NetEvent{URL: "https://a.com/", Method: http.MethodGet})

	navs, dialogs, console, netEvts := ec.snapshot()
	if len(navs) != 1 || navs[0].URL != "https://a.com/" {
		t.Fatalf("navs = %v", navs)
	}
	if len(dialogs) != 1 || dialogs[0].Message != "hi" {
		t.Fatalf("dialogs = %v", dialogs)
	}
	if len(console) != 1 || console[0].Text != "log" {
		t.Fatalf("console = %v", console)
	}
	if len(netEvts) != 1 || netEvts[0].Method != http.MethodGet {
		t.Fatalf("netEvts = %v", netEvts)
	}
}

func TestRunnerInterface(t *testing.T) {
	r := NewRunner()
	if r == nil {
		t.Fatal("NewRunner returned nil")
	}

	skipWithoutChromium(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately canceled
	_, err := r.Run(ctx, BrowserJob{
		Entrypoint: evidence.Request{URL: "about:blank"},
		TimeoutMS:  1000,
	})
	if err == nil {
		t.Fatal("expected error on canceled context")
	}
}

func TestWaitAction(t *testing.T) {
	t.Parallel()
	_ = waitAction("load_or_network_idle")
	_ = waitAction("unknown")
	_ = waitAction("")
}

func TestRunAction_UnknownKind(t *testing.T) {
	act := Action{Kind: "nonexistent"}
	action := runAction(act)
	err := action.Do(context.Background())
	if err == nil {
		t.Fatal("expected error for unknown action kind")
	}
}
