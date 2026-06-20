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

	// Pure HTTP: replay the traversal request and a benign control, then compare
	// the leaked marker. InternalAssessment allows the loopback target.
	err := exampleutil.Run(context.Background(), filepath.Dir(file), exampleutil.Options{
		InternalAssessment: true,
		Timeout:            30 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
}
