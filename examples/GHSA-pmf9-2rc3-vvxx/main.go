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

	// Timing proof: control / SLEEP(0) / SLEEP(5) replayed in randomized,
	// repeated order against the real MySQL-backed endpoint.
	err := exampleutil.Run(context.Background(), filepath.Dir(file), exampleutil.Options{
		InternalAssessment: true,
		Timeout:            120 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
}
