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

	err := exampleutil.Run(context.Background(), filepath.Dir(file), exampleutil.Options{
		Browser:            true,
		InternalAssessment: true,
		Timeout:            45 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
}
