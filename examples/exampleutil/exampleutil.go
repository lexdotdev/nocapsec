// Package exampleutil is the shared harness that
// runs each nocapsec example: it loads the
// example's evidence.json, wires the optional
// browser/OAST/auth dependencies, and prints the
// verification report.
package exampleutil

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
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
	ExternalHTTPAddr   string
	Timeout            time.Duration
	// AuthStateFile, when set, loads an auth-state
	// JSON array (same shape as the nocapsec
	// -authstate flag) into an encrypted in-memory
	// store for auth-backed validators such as
	// idor.read.
	AuthStateFile string
	// OASTDNSAddr fixes the embedded OAST receiver's
	// UDP DNS listen address (default 127.0.0.1:0).
	// Set a fixed port when an external resolver
	// must forward a zone to the receiver (e.g.
	// command_injection.oast).
	OASTDNSAddr string
	// OASTAdvertiseHost is the A-record reply /
	// callback host (default 127.0.0.1).
	OASTAdvertiseHost string
	// OASTCallbackHost overrides the host in the
	// receiver's HTTP callback URL (port preserved).
	// Set a loopback-resolving name such as
	// oast.localtest.me when the target rejects
	// raw-IP callback URLs (e.g. an SSRF guard).
	OASTCallbackHost string
	// EvidenceHook, when set, transforms the raw
	// evidence JSON before it is verified. Use it to
	// fill in values only known at run time, such as
	// a fresh session cookie obtained by logging
	// into the target.
	EvidenceHook func(ctx context.Context, evidence []byte) ([]byte, error)
}

// Run loads the example's evidence, wires the
// requested dependencies, verifies, and prints the
// report.
//
//nolint:gocyclo // linear setup: one branch per optional dependency
func Run(ctx context.Context, exampleDir string, opts Options) error {
	defaultTimeout := opts.Timeout
	if defaultTimeout == 0 {
		defaultTimeout = 2 * time.Minute
	}

	evidencePath := flag.String("evidence", filepath.Join(exampleDir, "evidence.json"), "finding evidence")
	chromePath := flag.String("chrome-path", os.Getenv("NOCAPSEC_CHROME_PATH"), "Chrome/Chromium path")
	timeout := flag.Duration("timeout", defaultTimeout, "verification timeout")
	flag.Parse()

	if opts.ExternalHTTPAddr != "" {
		stop, err := startExternalHTTP(opts.ExternalHTTPAddr) //nolint:contextcheck // example listener, no ctx
		if err != nil {
			return err
		}
		defer stop()
	}

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
	recv := oast.NewReceiver("oast.test", advertise)
	if err := recv.Start("127.0.0.1:0", dnsAddr); err != nil {
		return nil, fmt.Errorf("start oast: %w", err)
	}
	if opts.OASTCallbackHost != "" {
		recv.SetCallbackHost(opts.OASTCallbackHost)
	}
	return recv, nil
}

// loadAuthStore reads an auth-state JSON array into
// an encrypted in-memory store, mirroring
// cmd/nocapsec's -authstate loader.
func loadAuthStore(path string) (authstate.Store, error) {
	data, err := os.ReadFile(path) //nolint:gosec // example reads its own sibling file
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

func startExternalHTTP(addr string) (func(), error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("external listener: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte("nocapsec redirect landing\n"))
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	fmt.Fprintf(os.Stderr, "redirect landing: http://%s\n", ln.Addr())

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}
