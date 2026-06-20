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

	// OAST: the engine starts an embedded receiver, rewrites the placeholder
	// SYSTEM URL in the MathML DOCTYPE to its own callback, posts it to the
	// import endpoint, and waits for the parser's out-of-band fetch.
	err := exampleutil.Run(context.Background(), filepath.Dir(file), exampleutil.Options{
		OAST:               true,
		InternalAssessment: true,
		Timeout:            90 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
}
