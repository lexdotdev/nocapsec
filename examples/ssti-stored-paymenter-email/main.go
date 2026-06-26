package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/lexdotdev/nocapsec/examples/exampleutil"
)

func main() {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("resolve example path")
	}

	srv := httptest.NewServer(newPaymenterLikeApp())
	defer srv.Close()

	err := exampleutil.Run(context.Background(), filepath.Dir(file), exampleutil.Options{
		InternalAssessment: true,
		Timeout:            30 * time.Second,
		EvidenceHook:       patchOrigin(srv.URL),
	})
	if err != nil {
		log.Fatal(err)
	}
}

func patchOrigin(origin string) func(context.Context, []byte) ([]byte, error) {
	return func(_ context.Context, data []byte) ([]byte, error) {
		u, err := url.Parse(origin)
		if err != nil {
			return nil, err
		}
		_, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			return nil, err
		}
		data = bytes.ReplaceAll(data, []byte("http://127.0.0.1:0"), []byte(origin))
		data = bytes.Replace(data, []byte(`"allowed_ports": [0]`), []byte(fmt.Sprintf(`"allowed_ports": [%s]`, port)), 1)
		return data, nil
	}
}

type paymenterLikeApp struct {
	mu            sync.Mutex
	emailTemplate string
	latestEmail   string
}

func newPaymenterLikeApp() http.Handler {
	app := &paymenterLikeApp{}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/products/42", app.updateProduct)
	mux.HandleFunc("/admin/services/99/actions/create", app.activateService)
	mux.HandleFunc("/admin/email-logs/latest", app.latestLog)
	return mux
}

func (a *paymenterLikeApp) updateProduct(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	a.emailTemplate = vals.Get("email_template")
	a.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (a *paymenterLikeApp) activateService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	a.latestEmail = renderBlade(a.emailTemplate)
	a.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (a *paymenterLikeApp) latestLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, _ = w.Write([]byte(a.latestEmail))
}

var bladeArithmetic = regexp.MustCompile(`\{\{\s*(\d+)\*(\d+)\s*\}\}`)

func renderBlade(template string) string {
	return bladeArithmetic.ReplaceAllStringFunc(template, func(expr string) string {
		m := bladeArithmetic.FindStringSubmatch(expr)
		left, _ := strconv.ParseInt(m[1], 10, 64)
		right, _ := strconv.ParseInt(m[2], 10, 64)
		return strconv.FormatInt(left*right, 10)
	})
}
