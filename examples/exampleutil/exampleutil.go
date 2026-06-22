// Package exampleutil runs examples.
package exampleutil

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/authstate"
	"github.com/lexdotdev/nocapsec/internal/browser"
	"github.com/lexdotdev/nocapsec/internal/oast"
	"github.com/lexdotdev/nocapsec/pkg/nocapsec"
)

type Options struct {
	Browser            bool
	OAST               bool
	InternalAssessment bool
	Timeout            time.Duration
	// AuthStateFile mirrors -authstate.
	AuthStateFile string
	// OASTDNSAddr fixes DNS listen address.
	OASTDNSAddr string
	// OASTHTTPAddr fixes the HTTP callback address.
	OASTHTTPAddr string
	// OASTAdvertiseHost sets DNS A replies.
	OASTAdvertiseHost string
	// OASTCallbackHost sets callback host.
	OASTCallbackHost string
	// EvidenceHook patches runtime evidence.
	EvidenceHook func(ctx context.Context, evidence []byte) ([]byte, error)
}

// Run verifies one example.
func Run(ctx context.Context, exampleDir string, opts Options) error {
	defaultTimeout := opts.Timeout
	if defaultTimeout == 0 {
		defaultTimeout = 2 * time.Minute
	}

	evidencePath := flag.String("evidence", filepath.Join(exampleDir, "evidence.json"), "finding evidence")
	chromePath := flag.String("chrome-path", os.Getenv("NOCAPSEC_CHROME_PATH"), "Chrome/Chromium path")
	timeout := flag.Duration("timeout", defaultTimeout, "verification timeout")
	flag.Parse()

	data, err := os.ReadFile(*evidencePath)
	if err != nil {
		return fmt.Errorf("read evidence: %w", err)
	}

	if opts.EvidenceHook != nil {
		data, err = opts.EvidenceHook(ctx, data)
		if err != nil {
			return fmt.Errorf("evidence hook: %w", err)
		}
	}

	store := artifacts.NewStore()
	cfg := nocapsec.Config{
		Store:              store,
		InternalAssessment: opts.InternalAssessment,
	}

	if opts.AuthStateFile != "" {
		as, err := loadAuthStore(opts.AuthStateFile) //nolint:contextcheck // file read, no ctx
		if err != nil {
			return fmt.Errorf("load auth state: %w", err)
		}
		cfg.AuthStore = as
	}

	if opts.OAST {
		recv, err := startOASTReceiver(opts)
		if err != nil {
			return err
		}
		defer recv.Stop()
		cfg.OAST = recv
		fmt.Fprintf(os.Stderr, "OAST HTTP receiver: http://%s  DNS: %s\n", recv.HTTPAddr(), recv.DNSAddr())
	}

	if opts.Browser {
		cfg.Browser = browser.NewRunner(
			browser.WithArtifactStore(store),
			browser.WithExecPath(*chromePath),
		)
	}

	eng, err := nocapsec.New(cfg)
	if err != nil {
		return fmt.Errorf("new engine: %w", err)
	}
	defer func() { _ = eng.Close() }()

	verifyCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	report, err := eng.Verify(verifyCtx, data)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	out, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	fmt.Println(string(out))

	if report.Verdict != nocapsec.Verified {
		return fmt.Errorf("verdict %s", report.Verdict)
	}
	return nil
}

// startOASTReceiver builds, starts, and configures
// the embedded OAST receiver from opts (advertise
// host, DNS address, callback host).
func startOASTReceiver(opts Options) (*oast.Receiver, error) {
	advertise := opts.OASTAdvertiseHost
	if advertise == "" {
		advertise = "127.0.0.1"
	}
	dnsAddr := opts.OASTDNSAddr
	if dnsAddr == "" {
		dnsAddr = "127.0.0.1:0"
	}
	httpAddr := opts.OASTHTTPAddr
	if httpAddr == "" {
		httpAddr = "127.0.0.1:0"
	}
	recv := oast.NewReceiver("oast.test", advertise)
	if err := recv.Start(httpAddr, dnsAddr); err != nil {
		return nil, fmt.Errorf("start oast: %w", err)
	}
	if opts.OASTCallbackHost != "" {
		recv.SetCallbackHost(opts.OASTCallbackHost)
	}
	return recv, nil
}

// loadAuthStore mirrors -authstate.
func loadAuthStore(path string) (authstate.Store, error) {
	data, err := os.ReadFile(path) //nolint:gosec // example file
	if err != nil {
		return nil, err
	}
	var entries []struct {
		State       authstate.AuthState   `json:"state"`
		Credentials authstate.Credentials `json:"credentials"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	store, err := authstate.NewStore(key, nil)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		st, cr := entries[i].State, entries[i].Credentials
		if err := store.Put(context.Background(), &st, &cr); err != nil {
			return nil, err
		}
	}
	return store, nil
}
