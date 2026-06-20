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

	// The timing proof replays
	// control/sleep-0/sleep-5 several times, so the
	// run holds for the accumulated sleeps; give it
	// a generous timeout.
	err := exampleutil.Run(context.Background(), filepath.Dir(file), exampleutil.Options{
		InternalAssessment: true,
		Timeout:            120 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
}
