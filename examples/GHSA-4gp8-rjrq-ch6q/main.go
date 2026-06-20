package main

import (
	"context"
	"log"
	"path/filepath"
	"runtime"
	"time"

	"github.com/lexdotdev/nocapsec/examples/exampleutil"
)

func main() {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("resolve example path")
	}

	// link-preview-js refuses to fetch raw-IP / localhost URLs (its SSRF regex),
	// but happily fetches any TLD'd hostname -- including one that resolves to
	// loopback. oast.localtest.me resolves to 127.0.0.1 via public DNS, so the
	// receiver advertises its callback under that name and the library's own
	// fetch lands on the local receiver. This is exactly the advisory's bug:
	// a hostname-fronted internal target is fetched server-side.
	err := exampleutil.Run(context.Background(), filepath.Dir(file), exampleutil.Options{
		OAST:               true,
		OASTCallbackHost:   "oast.localtest.me",
		InternalAssessment: true,
		Timeout:            90 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
}
