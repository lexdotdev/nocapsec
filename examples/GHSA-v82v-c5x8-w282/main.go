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

	// Browser: the setup POST stores the payload, then a fresh Chrome context
	// navigates /note where NiceGUI binds the stored markdown to innerHTML and the
	// <img onerror> fires automatically -- captured as a javascript_dialog.
	err := exampleutil.Run(context.Background(), filepath.Dir(file), exampleutil.Options{
		Browser:            true,
		InternalAssessment: true,
		Timeout:            60 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
}
