package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lexdotdev/nocapsec/internal/verdict"
)

func TestDispatchRunsTaskOnItsPool(t *testing.T) {
	d := newDispatcher(DefaultLimits())
	defer d.Close()

	ran := false
	err := d.Dispatch(context.Background(), Task{
		Capability: CapHTTPReplay,
		Target:     "app.example.com",
		Run:        func(context.Context) error { ran = true; return nil },
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !ran {
		t.Fatal("task did not run")
	}
}

func TestDispatchUnknownCapability(t *testing.T) {
	d := newDispatcher(DefaultLimits())
	defer d.Close()

	err := d.Dispatch(context.Background(), Task{
		Capability: "nope",
		Target:     "app.example.com",
		Run:        func(context.Context) error { return nil },
	})
	if err == nil {
		t.Fatal("expected error for unknown capability")
	}
}

// A finding with no Run wired (the current scaffold state) surfaces
// ErrNotImplemented rather than running nothing silently.
func TestDispatchNilRunIsNotImplemented(t *testing.T) {
	d := newDispatcher(DefaultLimits())
	defer d.Close()

	err := d.Dispatch(context.Background(), Task{Capability: CapOAST, Target: "t"})
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v, want ErrNotImplemented", err)
	}
}

// The per-target limiter must cap concurrency before dispatch: with Browser=2,
// only two jobs for one target run at once; the rest block on the semaphore.
func TestDispatchEnforcesPerTargetLimit(t *testing.T) {
	d := newDispatcher(Limits{Browser: 2})
	defer d.Close()

	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.Dispatch(context.Background(), Task{
				Capability: CapBrowser,
				Target:     "app.example.com",
				Run: func(context.Context) error {
					entered <- struct{}{}
					<-release
					return nil
				},
			})
		}()
	}

	<-entered
	<-entered
	select {
	case <-entered:
		t.Fatal("a third task entered; per-target limit not enforced")
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	wg.Wait()
}

// A panic in one task fails only that job; the worker keeps serving the pool.
func TestPoolRecoversFromPanic(t *testing.T) {
	d := newDispatcher(Limits{HTTPReplay: 1})
	defer d.Close()

	err := d.Dispatch(context.Background(), Task{
		Capability: CapHTTPReplay,
		Target:     "t",
		Run:        func(context.Context) error { panic("boom") },
	})
	if err == nil {
		t.Fatal("expected error from panicking task")
	}

	ran := false
	err = d.Dispatch(context.Background(), Task{
		Capability: CapHTTPReplay,
		Target:     "t",
		Run:        func(context.Context) error { ran = true; return nil },
	})
	if err != nil {
		t.Fatalf("dispatch after panic: %v", err)
	}
	if !ran {
		t.Fatal("pool stopped serving after a panic")
	}
}

func TestDispatchHonorsContextCancellation(t *testing.T) {
	d := newDispatcher(DefaultLimits())
	defer d.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := d.Dispatch(ctx, Task{
		Capability: CapHTTPReplay,
		Target:     "t",
		Run:        func(context.Context) error { return nil },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestJobStorePutGet(t *testing.T) {
	s := newJobStore()
	if _, ok := s.get("missing"); ok {
		t.Fatal("empty store returned a job")
	}

	want := verdict.NewReport("f1", "xss_reflected", verdict.Inconclusive)
	s.put("f1", want)
	got, ok := s.get("f1")
	if !ok || got.FindingID != "f1" {
		t.Fatalf("get = %+v, %v", got, ok)
	}
}

// The HTTP surface matches specs/contracts/verifier-api.md: an unknown job is
// 404, and the not-yet-wired routes return 501.
func TestHandlerRoutes(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close()

	srv := httptest.NewServer(e.Handler())
	defer srv.Close()

	cases := []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/verify/unknown-id", http.StatusNotFound},
		{http.MethodPost, "/verify", http.StatusNotImplemented},
		{http.MethodGet, "/verify/unknown-id/artifacts", http.StatusNotImplemented},
	}
	for _, c := range cases {
		req, err := http.NewRequest(c.method, srv.URL+c.path, http.NoBody)
		if err != nil {
			t.Fatalf("new request %s %s: %v", c.method, c.path, err)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", c.method, c.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s %s: status = %d, want %d", c.method, c.path, resp.StatusCode, c.want)
		}
	}
}

func TestEngineVerifyNotImplemented(t *testing.T) {
	e, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Close()

	if _, err := e.Verify(context.Background(), []byte(`{}`)); !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("Verify err = %v, want ErrNotImplemented", err)
	}
}
