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

	// Pure HTTP: replay baseline / true (1=1) /
	// false (1=2) and compare the response
	// fingerprints. baseline and true must match;
	// false must differ.
	err := exampleutil.Run(context.Background(), filepath.Dir(file), exampleutil.Options{
		InternalAssessment: true,
		Timeout:            30 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
}
