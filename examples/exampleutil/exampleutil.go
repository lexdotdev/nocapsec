package exampleutil

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
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
}

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
		stop, err := startExternalHTTP(opts.ExternalHTTPAddr)
		if err != nil {
			return err
		}
		defer stop()
	}

	data, err := os.ReadFile(*evidencePath)
	if err != nil {
		return fmt.Errorf("read evidence: %w", err)
	}

	store := artifacts.NewStore()
	cfg := nocapsec.Config{
		Store:              store,
		InternalAssessment: opts.InternalAssessment,
	}

	var recv *oast.Receiver
	if opts.OAST {
		recv = oast.NewReceiver("oast.test", "127.0.0.1")
		if err := recv.Start("127.0.0.1:0", "127.0.0.1:0"); err != nil {
			return fmt.Errorf("start oast: %w", err)
		}
		defer recv.Stop()
		cfg.OAST = recv
		fmt.Fprintf(os.Stderr, "OAST HTTP receiver: http://%s\n", recv.HTTPAddr())
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

func startExternalHTTP(addr string) (func(), error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("external listener: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
