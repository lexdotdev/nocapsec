// Command nocapsec is the single binary for the nocapsec proof engine: a CLI
// that serves the HTTP API and runs a one-shot verification.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/lexdotdev/nocapsec/pkg/nocapsec"
)

// addr is the verifier API listen address in serve mode.
//
// TODO: make configurable.
const addr = ":8080"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "serve":
		serve()
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

// serve runs the HTTP API backed by an in-process engine.
func serve() {
	eng, err := nocapsec.New(nocapsec.Config{})
	if err != nil {
		log.Fatalf("nocapsec serve: %v", err)
	}
	defer func() { _ = eng.Close() }()

	log.Printf("nocapsec serve: listening on %s (stub: all routes return 501)", addr)
	log.Fatal(http.ListenAndServe(addr, eng.Handler())) //nolint:gosec // G114: serve timeouts added in hardening phase
}

// verify runs the full pipeline for one finding in-process, then exits.
func verify(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: nocapsec verify <finding.json>")
		os.Exit(2)
	}

	finding, err := os.ReadFile(args[0]) //nolint:gosec // G703: CLI intentionally reads the user-supplied finding path
	if err != nil {
		log.Fatalf("nocapsec verify: %v", err)
	}

	eng, err := nocapsec.New(nocapsec.Config{})
	if err != nil {
		log.Fatalf("nocapsec verify: %v", err)
	}
	defer func() { _ = eng.Close() }()

	report, err := eng.Verify(context.Background(), finding)
	if err != nil {
		log.Fatalf("nocapsec verify: %v", err)
	}

	out, err := report.JSON()
	if err != nil {
		log.Fatalf("nocapsec verify: %v", err)
	}
	fmt.Println(string(out))
}
