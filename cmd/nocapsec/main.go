// Command nocapsec is the single binary for the nocapsec proof engine: a CLI
// that serves the HTTP API and runs a one-shot verification.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/authstate"
	"github.com/lexdotdev/nocapsec/internal/browser"
	"github.com/lexdotdev/nocapsec/internal/config"
	"github.com/lexdotdev/nocapsec/internal/engine"
	"github.com/lexdotdev/nocapsec/internal/oast"
	"github.com/lexdotdev/nocapsec/pkg/nocapsec"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: nocapsec <serve|verify>")
	fmt.Fprintln(os.Stderr, "  serve            run the HTTP API + in-process worker pools")
	fmt.Fprintln(os.Stderr, "  verify <file>    one-shot: verify a single finding and print the report")
}

// wiring holds the injected-dependency flags shared by serve and verify.
type wiring struct {
	oast              bool
	oastHTTPAddr      string
	oastDNSAddr       string
	oastDomain        string
	oastAdvertiseHost string
	authFile          string
	browser           bool
	chromePath        string
}

// loadConfig builds a Config from file < env < flags, plus dependency wiring.
func loadConfig(fs *flag.FlagSet, args []string) (config.Config, wiring) {
	var (
		cfgFile     string
		addr        string
		poolHTTP    int
		poolTiming  int
		poolBrowser int
		poolOAST    int
		internal    bool
		hasInternal bool
		w           wiring
	)

	fs.StringVar(&cfgFile, "config", "", "path to config JSON file")
	fs.StringVar(&addr, "addr", "", "listen address (overrides config/env)")
	fs.IntVar(&poolHTTP, "pool-http", 0, "HTTP replay pool size")
	fs.IntVar(&poolTiming, "pool-timing", 0, "timing pool size")
	fs.IntVar(&poolBrowser, "pool-browser", 0, "browser pool size")
	fs.IntVar(&poolOAST, "pool-oast", 0, "OAST pool size")
	fs.BoolVar(&internal, "internal", false, "allow internal IP ranges")
	fs.BoolVar(&w.oast, "oast", false, "run the embedded OAST receiver (enables OAST validators)")
	fs.StringVar(&w.oastHTTPAddr, "oast-http-addr", "127.0.0.1:0", "embedded OAST HTTP listen address")
	fs.StringVar(&w.oastDNSAddr, "oast-dns-addr", "127.0.0.1:0", "embedded OAST DNS listen address")
	fs.StringVar(&w.oastDomain, "oast-domain", "oast.test", "OAST callback domain suffix")
	fs.StringVar(&w.oastAdvertiseHost, "oast-advertise-host", "127.0.0.1", "host advertised in OAST callbacks/DNS replies")
	fs.StringVar(&w.authFile, "authstate", "", "auth-state JSON file (enables auth-backed validators)")
	fs.BoolVar(&w.browser, "browser", false, "enable the headless browser runner")
	fs.StringVar(&w.chromePath, "chrome-path", "", "browser binary path (default: auto-detect; or set NOCAPSEC_CHROME_PATH)")
	_ = fs.Parse(args)

	// Detect whether -internal was explicitly set.
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "internal" {
			hasInternal = true
		}
	})

	cfg := config.LoadFile(cfgFile).ApplyEnv()

	var internalPtr *bool
	if hasInternal {
		internalPtr = &internal
	}
	cfg = cfg.ApplyFlags(addr, poolHTTP, poolTiming, poolBrowser, poolOAST, internalPtr)
	return cfg, w
}

// newEngine builds a nocapsec.Engine from config + wiring, with optional logger.
// When the embedded OAST receiver is enabled it is started here and returned so
// the caller can stop its listeners on shutdown; otherwise the receiver is nil.
func newEngine(cfg config.Config, w wiring, logger engine.Logger) (*nocapsec.Engine, *oast.Receiver, error) {
	store := artifacts.NewStore()

	var br browser.BrowserRunner
	if w.browser {
		br = browser.NewRunner(browser.WithArtifactStore(store), browser.WithExecPath(w.chromePath))
	}

	var ot oast.OAST
	var recv *oast.Receiver
	if w.oast {
		recv = oast.NewReceiver(w.oastDomain, w.oastAdvertiseHost)
		if err := recv.Start(w.oastHTTPAddr, w.oastDNSAddr); err != nil {
			return nil, nil, fmt.Errorf("start oast receiver: %w", err)
		}
		ot = recv
	}

	var as authstate.Store
	if w.authFile != "" {
		s, err := loadAuthStore(w.authFile)
		if err != nil {
			if recv != nil {
				recv.Stop()
			}
			return nil, nil, fmt.Errorf("load auth state: %w", err)
		}
		as = s
	}

	eng, err := nocapsec.New(nocapsec.Config{
		Limits: engine.Limits{
			HTTPReplay: cfg.Pools.HTTPReplay,
			Timing:     cfg.Pools.Timing,
			Browser:    cfg.Pools.Browser,
			OAST:       cfg.Pools.OAST,
		},
		Store:              store,
		AuthStore:          as,
		Browser:            br,
		OAST:               ot,
		InternalAssessment: cfg.InternalAssessment,
		Logger:             logger,
	})
	if err != nil {
		if recv != nil {
			recv.Stop()
		}
		return nil, nil, err
	}
	return eng, recv, nil
}

// loadAuthStore reads an auth-state JSON file into an encrypted in-memory store.
func loadAuthStore(path string) (authstate.Store, error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path
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

	key := make([]byte, 32) // per-process key: states are written and read here
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	store, err := authstate.NewStore(key, nil)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for i := range entries {
		st, cr := entries[i].State, entries[i].Credentials
		if st.ID == "" {
			return nil, fmt.Errorf("auth state %d has empty id", i)
		}
		if seen[st.ID] {
			return nil, fmt.Errorf("duplicate auth state id %q", st.ID)
		}
		seen[st.ID] = true
		if err := store.Put(context.Background(), &st, &cr); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// serve runs the HTTP API backed by an in-process engine.
func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfg, w := loadConfig(fs, args)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	eng, recv, err := newEngine(cfg, w, engine.SlogLogger{L: logger})
	if err != nil {
		log.Fatalf("nocapsec serve: %v", err)
	}
	if recv != nil {
		logger.Info("oast_listening", "http", recv.HTTPAddr(), "dns", recv.DNSAddr())
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           eng.Handler(),
		ReadHeaderTimeout: cfg.Serve.ReadHeaderTimeout,
		ReadTimeout:       cfg.Serve.ReadTimeout,
		WriteTimeout:      cfg.Serve.WriteTimeout,
		IdleTimeout:       cfg.Serve.IdleTimeout,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("listening", "addr", cfg.ListenAddr)
		if listenErr := srv.ListenAndServe(); listenErr != nil && listenErr != http.ErrServerClosed {
			log.Fatalf("nocapsec serve: %v", listenErr)
		}
	}()

	<-stop
	logger.Info("shutting_down")

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Serve.WriteTimeout)
	defer cancel()
	_ = srv.Shutdown(ctx)
	_ = eng.Close()
	if recv != nil {
		recv.Stop()
	}
}

// verify runs the full pipeline for one finding in-process, then exits.
func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	cfg, w := loadConfig(fs, args)

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "usage: nocapsec verify <finding.json>")
		os.Exit(2)
	}
	filePath := fs.Args()[0]

	finding, err := os.ReadFile(filePath) //nolint:gosec // CLI tool reads user-specified file
	if err != nil {
		log.Fatalf("nocapsec verify: %v", err)
	}

	eng, recv, err := newEngine(cfg, w, nil)
	if err != nil {
		log.Fatalf("nocapsec verify: %v", err)
	}
	defer func() {
		_ = eng.Close()
		if recv != nil {
			recv.Stop()
		}
	}()

	report, err := eng.Verify(context.Background(), finding)
	if err != nil {
		log.Fatalf("nocapsec verify: %v", err)
	}

	out, err := json.Marshal(report)
	if err != nil {
		log.Fatalf("nocapsec verify: %v", err)
	}
	fmt.Println(string(out))
}
