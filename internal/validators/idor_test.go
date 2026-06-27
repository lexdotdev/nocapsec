package validators_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/authstate"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

func testAuthKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// idorAuthStore creates owner and attacker.
func idorAuthStore(t *testing.T) authstate.Store {
	t.Helper()
	clock := fixedClock{now: time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)}
	store, err := authstate.NewStore(testAuthKey(), clock)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	ctx := context.Background()

	owner := &authstate.AuthState{
		ID:             "owner-session",
		Kind:           "http_cookie_jar",
		AllowedOrigins: []string{"http://app.example.com"},
		Role:           "admin",
		ExpiresAt:      time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	ownerCreds := &authstate.Credentials{
		Headers: map[string]string{"X-Owner-Token": "owner-secret"},
	}
	if err := store.Put(ctx, owner, ownerCreds); err != nil {
		t.Fatalf("Put owner: %v", err)
	}

	attacker := &authstate.AuthState{
		ID:             "attacker-session",
		Kind:           "http_cookie_jar",
		AllowedOrigins: []string{"http://app.example.com"},
		Role:           "viewer",
		ExpiresAt:      time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	attackerCreds := &authstate.Credentials{
		Headers: map[string]string{"X-Attacker-Token": "attacker-secret"},
	}
	if err := store.Put(ctx, attacker, attackerCreds); err != nil {
		t.Fatalf("Put attacker: %v", err)
	}
	return store
}

func buildIDORJob(t *testing.T, port int, nonce string) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps

	ev, _ := json.Marshal(map[string]any{
		"resource_owner_auth_state_id": "owner-session",
		"attacker_auth_state_id":       "attacker-session",
		"setup_resource": map[string]string{
			"method": "POST",
			"url":    base + "/api/documents",
			"body":   `{"title":"canary-{{nonce}}"}`,
		},
		"attack_request": map[string]string{
			"method": "GET",
			"url":    base + "/api/documents/{{created_resource_id}}",
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker":       "canary-{{nonce}}",
		"require_owner_control": true,
	})

	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-idor",
			Type:      "idor.read",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: nonce,
	}
}

func idorEnv(t *testing.T, srv *httptest.Server, authStore authstate.Store) validators.Env {
	t.Helper()
	return validators.Env{
		Policy:    testEnforcer(t, srv),
		Artifacts: artifacts.NewStore(),
		AuthStore: authStore,
		Clock:     validators.WallClock{},
	}
}

// idorHandler exposes cross-user reads.
func idorHandler() http.Handler {
	docs := map[string]string{} // id -> body
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/documents":
			// Owner creates the document.
			var body struct {
				Title string `json:"title"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			docID := "doc-42"
			docs[docID] = body.Title
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": docID})

		case r.Method == http.MethodGet && len(r.URL.Path) > len("/api/documents/"):
			// Anyone can read -> IDOR.
			docID := r.URL.Path[len("/api/documents/"):]
			title, ok := docs[docID]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]string{"title": title})

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func TestIDORReadVerified(t *testing.T) {
	srv := httptest.NewServer(idorHandler())
	defer srv.Close()

	_, port := serverAddr(t, srv)
	store := idorAuthStore(t)

	job := buildIDORJob(t, port, "abc123")
	env := idorEnv(t, srv, store)

	res := runValidate(t, "idor.read", job, env)
	result := res.Verdict
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
}

// Missing canary is not_reproduced.
func TestIDORReadNotReproduced(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/documents":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "doc-99"})
		case r.Method == http.MethodGet:
			// Access denied: attacker gets a generic message.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"error":"forbidden"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	_, port := serverAddr(t, srv)
	store := idorAuthStore(t)

	job := buildIDORJob(t, port, "nonce456")
	env := idorEnv(t, srv, store)

	res := runValidate(t, "idor.read", job, env)
	result := res.Verdict
	if result != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", result)
	}
}

// Setup fails (4xx) -> inconclusive.
func TestIDORReadSetupFails(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	_, port := serverAddr(t, srv)
	store := idorAuthStore(t)

	job := buildIDORJob(t, port, "nonce789")
	env := idorEnv(t, srv, store)

	res := runValidate(t, "idor.read", job, env)
	result := res.Verdict
	if result != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", result)
	}
}

// Same auth state for both roles -> invalid.
func TestIDORReadSameAuthInvalid(t *testing.T) {
	ev, _ := json.Marshal(map[string]any{
		"resource_owner_auth_state_id": "same-id",
		"attacker_auth_state_id":       "same-id",
		"setup_resource":               map[string]string{"method": "POST", "url": "http://a/x"},
		"attack_request":               map[string]string{"method": "GET", "url": "http://a/y"},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker":       "canary",
		"require_owner_control": true,
	})

	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-same-auth",
			Type:      "idor.read",
			Evidence:  ev,
			Proof:     proof,
		},
	}
	env := validators.Env{Clock: validators.WallClock{}}

	res := runValidate(t, "idor.read", job, env)
	result := res.Verdict
	if result != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", result)
	}
}

// Missing auth store -> inconclusive.
func TestIDORReadNoAuthStore(t *testing.T) {
	ev, _ := json.Marshal(map[string]any{
		"resource_owner_auth_state_id": "owner",
		"attacker_auth_state_id":       "attacker",
		"setup_resource":               map[string]string{"method": "POST", "url": "http://a/x"},
		"attack_request":               map[string]string{"method": "GET", "url": "http://a/y"},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker":       "canary",
		"require_owner_control": true,
	})

	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-no-store",
			Type:      "idor.read",
			Evidence:  ev,
			Proof:     proof,
		},
	}
	env := validators.Env{Clock: validators.WallClock{}}

	res := runValidate(t, "idor.read", job, env)
	result := res.Verdict
	if result != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", result)
	}
}

// Bad evidence JSON -> invalid.
func TestIDORReadBadEvidence(t *testing.T) {
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-bad-ev",
			Type:      "idor.read",
			Evidence:  json.RawMessage(`{"not":"valid"}`),
			Proof:     json.RawMessage(`{}`),
		},
	}
	env := validators.Env{Clock: validators.WallClock{}}

	res := runValidate(t, "idor.read", job, env)
	result := res.Verdict
	if result != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid", result)
	}
}

// Expired owner auth -> inconclusive.
func TestIDORReadExpiredAuth(t *testing.T) {
	clock := fixedClock{now: time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)}
	store, err := authstate.NewStore(testAuthKey(), clock)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	ctx := context.Background()

	// Store an already-expired auth state.
	owner := &authstate.AuthState{
		ID:        "owner-session",
		ExpiresAt: time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
	}
	if err := store.Put(ctx, owner, &authstate.Credentials{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	attacker := &authstate.AuthState{
		ID:        "attacker-session",
		ExpiresAt: time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC),
	}
	if err := store.Put(ctx, attacker, &authstate.Credentials{}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	ev, _ := json.Marshal(map[string]any{
		"resource_owner_auth_state_id": "owner-session",
		"attacker_auth_state_id":       "attacker-session",
		"setup_resource":               map[string]string{"method": "POST", "url": "http://a/x"},
		"attack_request":               map[string]string{"method": "GET", "url": "http://a/y"},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker":       "canary",
		"require_owner_control": true,
	})

	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-expired",
			Type:      "idor.read",
			Evidence:  ev,
			Proof:     proof,
		},
	}
	env := validators.Env{
		AuthStore: store,
		Clock:     validators.WallClock{},
	}

	res := runValidate(t, "idor.read", job, env)
	result := res.Verdict
	if result != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive", result)
	}
}

// Resource ID extraction from JSON response.
func TestIDORReadResourceIDExtraction(t *testing.T) {
	// JSON id extraction flow.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"res-abc"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/documents/res-abc":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"title":"canary-testnonce"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	_, port := serverAddr(t, srv)
	store := idorAuthStore(t)

	job := buildIDORJob(t, port, "testnonce")
	env := idorEnv(t, srv, store)

	res := runValidate(t, "idor.read", job, env)
	result := res.Verdict
	if result != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", result)
	}
}

// created_id_pointer reads nested ids.
func TestIDORReadNestedCreatedIDPointer(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			// Nested resource id.
			_, _ = w.Write([]byte(`{"status":"ok","data":{"id":"res-nested-7"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/documents/res-nested-7":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"title":"canary-testnonce"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	_, port := serverAddr(t, srv)
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	store := idorAuthStore(t)

	ev, _ := json.Marshal(map[string]any{
		"resource_owner_auth_state_id": "owner-session",
		"attacker_auth_state_id":       "attacker-session",
		"created_id_pointer":           "/data/id",
		"setup_resource": map[string]string{
			"method": "POST",
			"url":    base + "/api/documents",
			"body":   `{"title":"canary-{{nonce}}"}`,
		},
		"attack_request": map[string]string{
			"method": "GET",
			"url":    base + "/api/documents/{{created_resource_id}}",
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker":       "canary-{{nonce}}",
		"require_owner_control": true,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-idor-nested",
			Type:      "idor.read",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: "testnonce",
	}

	res := runValidate(t, "idor.read", job, idorEnv(t, srv, store))
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified (nested id via created_id_pointer)", res.Verdict)
	}
}

// Missing pointer is inconclusive.
func TestIDORReadUnresolvedPointerInconclusive(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			// No data.id path.
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	_, port := serverAddr(t, srv)
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	store := idorAuthStore(t)

	ev, _ := json.Marshal(map[string]any{
		"resource_owner_auth_state_id": "owner-session",
		"attacker_auth_state_id":       "attacker-session",
		"created_id_pointer":           "/data/id",
		"setup_resource": map[string]string{
			"method": "POST",
			"url":    base + "/api/documents",
			"body":   `{"title":"canary-{{nonce}}"}`,
		},
		"attack_request": map[string]string{
			"method": "GET",
			"url":    base + "/api/documents/{{created_resource_id}}",
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"expected_marker":       "canary-{{nonce}}",
		"require_owner_control": true,
	})
	job := validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-idor-unresolved-pointer",
			Type:      "idor.read",
			Target: evidence.Target{
				ExpectedOrigin: base,
				AllowedHosts:   []string{"app.example.com"},
				AllowedSchemes: []string{"http"},
				AllowedPorts:   []int{port},
			},
			Evidence: ev,
			Proof:    proof,
		},
		Nonce: "testnonce",
	}

	res := runValidate(t, "idor.read", job, idorEnv(t, srv, store))
	if res.Verdict != verdict.Inconclusive {
		t.Fatalf("verdict = %q, want inconclusive (unresolved pointer is authoring error)", res.Verdict)
	}
}

// Auth headers match setup and attack roles.
func TestIDORReadInjectsAuthHeaders(t *testing.T) {
	var setupAuth, attackAuth string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/documents":
			setupAuth = r.Header.Get("X-Owner-Token")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "doc-1"})
		case r.Method == http.MethodGet:
			attackAuth = r.Header.Get("X-Attacker-Token")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"title":"canary-auth-nonce"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	srv := httptest.NewServer(handler)
	defer srv.Close()

	_, port := serverAddr(t, srv)
	store := idorAuthStore(t)

	job := buildIDORJob(t, port, "auth-nonce")
	env := idorEnv(t, srv, store)

	runValidate(t, "idor.read", job, env)
	if setupAuth != "owner-secret" {
		t.Fatalf("setup auth = %q, want owner-secret", setupAuth)
	}
	if attackAuth != "attacker-secret" {
		t.Fatalf("attack auth = %q, want attacker-secret", attackAuth)
	}
}
