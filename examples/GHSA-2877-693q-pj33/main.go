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

	// OAST over DNS: the engine writes its callback host (<id>.oast.test) into the
	// `host` body field; the app pings it, the OS resolver looks it up, and the
	// query lands on the receiver's DNS listener -- attributed to the target
	// because it arrives from loopback. The DNS listener is pinned to a fixed
	// port so /etc/resolver/oast.test can forward the zone to it (see README).
	err := exampleutil.Run(context.Background(), filepath.Dir(file), exampleutil.Options{
		OAST:               true,
		OASTDNSAddr:        "127.0.0.1:15353",
		InternalAssessment: true,
		Timeout:            60 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
}
