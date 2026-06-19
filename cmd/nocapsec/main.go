// Command nocapsec is the single binary for the nocapsec proof engine: a CLI
// that serves the HTTP API and runs a one-shot verification.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/lexdotdev/nocapsec/internal/config"
	"github.com/lexdotdev/nocapsec/internal/engine"
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

// loadConfig builds a Config from file < env < flags.
func loadConfig(fs *flag.FlagSet, args []string) config.Config {
	var (
		cfgFile     string
		addr        string
		poolHTTP    int
		poolTiming  int
		poolBrowser int
		poolOAST    int
		internal    bool
		hasInternal bool
	)

	fs.StringVar(&cfgFile, "config", "", "path to config JSON file")
	fs.StringVar(&addr, "addr", "", "listen address (overrides config/env)")
	fs.IntVar(&poolHTTP, "pool-http", 0, "HTTP replay pool size")
	fs.IntVar(&poolTiming, "pool-timing", 0, "timing pool size")
	fs.IntVar(&poolBrowser, "pool-browser", 0, "browser pool size")
	fs.IntVar(&poolOAST, "pool-oast", 0, "OAST pool size")
	fs.BoolVar(&internal, "internal", false, "allow internal IP ranges")
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
	return cfg
}

// newEngine builds a nocapsec.Engine from config, with optional logger.
func newEngine(cfg config.Config, logger engine.Logger) (*nocapsec.Engine, error) {
	return nocapsec.New(nocapsec.Config{
		Limits: engine.Limits{
			HTTPReplay: cfg.Pools.HTTPReplay,
			Timing:     cfg.Pools.Timing,
			Browser:    cfg.Pools.Browser,
			OAST:       cfg.Pools.OAST,
		},
		InternalAssessment: cfg.InternalAssessment,
		Logger:             logger,
	})
}

// serve runs the HTTP API backed by an in-process engine.
func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfg := loadConfig(fs, args)

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	eng, err := newEngine(cfg, engine.SlogLogger{L: logger})
	if err != nil {
		log.Fatalf("nocapsec serve: %v", err)
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
}

// verify runs the full pipeline for one finding in-process, then exits.
func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	cfg := loadConfig(fs, args)

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "usage: nocapsec verify <finding.json>")
		os.Exit(2)
	}
	filePath := fs.Args()[0]

	finding, err := os.ReadFile(filePath) //nolint:gosec // CLI tool reads user-specified file
	if err != nil {
		log.Fatalf("nocapsec verify: %v", err)
	}

	eng, err := newEngine(cfg, nil)
	if err != nil {
		log.Fatalf("nocapsec verify: %v", err)
	}
	defer func() { _ = eng.Close() }()

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
