package validators_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/lexdotdev/nocapsec/internal/artifacts"
	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/validators"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

func buildNoSQLiJob(t *testing.T, port int, marker string) validators.Job {
	t.Helper()
	ps := strconv.Itoa(port)
	base := "http://app.example.com:" + ps
	ev, _ := json.Marshal(map[string]any{
		"base_request": map[string]any{
			"method":  "POST",
			"url":     base + "/user/login",
			"headers": []map[string]string{{"name": "content-type", "value": "application/json"}},
			"body":    `{"username":"admin","password":"x"}`,
		},
		"injection": map[string]any{
			"location": map[string]string{"kind": "json_operator", "json_pointer": "/password"},
			"payloads": map[string]string{
				"candidate": `{"$ne":1}`,
				"control":   `"nocapsec_wrong_zzz"`,
			},
		},
	})
	proof, _ := json.Marshal(map[string]any{
		"success_marker": marker,
		"repetitions":    2,
	})
	return validators.Job{
		Finding: evidence.Finding{
			FindingID: "test-nosqli",
			Type:      "nosqli.auth_bypass",
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
}

func nosqliEnv(t *testing.T, srv *httptest.Server) validators.Env {
	t.Helper()
	return validators.Env{
		Policy:    testEnforcer(t, srv),
		Artifacts: artifacts.NewStore(),
		Clock:     validators.WallClock{},
	}
}

// loginHandler: Mongo login sink stub.
// Operator password logs in; string does not.
func loginHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		w.WriteHeader(http.StatusOK)
		if _, isStr := m["password"].(string); isStr {
			_, _ = w.Write([]byte(`{"role":"invalid","msg":"Invalid username or password."}`))
			return
		}
		_, _ = w.Write([]byte(`{"role":"admin","username":"admin","msg":"Logged in as user admin with role admin"}`))
	})
}

func TestNoSQLiAuthBypassVerified(t *testing.T) {
	srv := httptest.NewServer(loginHandler())
	defer srv.Close()

	_, port := serverAddr(t, srv)
	res := runValidate(t, "nosqli.auth_bypass", buildNoSQLiJob(t, port, "Logged in as user"), nosqliEnv(t, srv))
	if res.Verdict != verdict.Verified {
		t.Fatalf("verdict = %q, want verified", res.Verdict)
	}
}

// marker in sent request -> invalid (reflection).
func TestNoSQLiAuthBypassReflectionGuard(t *testing.T) {
	srv := httptest.NewServer(loginHandler())
	defer srv.Close()

	_, port := serverAddr(t, srv)
	// "admin" is in the request body: bad marker.
	res := runValidate(t, "nosqli.auth_bypass", buildNoSQLiJob(t, port, "admin"), nosqliEnv(t, srv))
	if res.Verdict != verdict.Invalid {
		t.Fatalf("verdict = %q, want invalid (marker reflected in request)", res.Verdict)
	}
}

// never authenticates -> not_reproduced.
func TestNoSQLiAuthBypassNotReproduced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"role":"invalid","msg":"Invalid username or password."}`))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	res := runValidate(t, "nosqli.auth_bypass", buildNoSQLiJob(t, port, "Logged in as user"), nosqliEnv(t, srv))
	if res.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced", res.Verdict)
	}
}

// control also logs in -> not_reproduced.
func TestNoSQLiAuthBypassControlAlsoSucceeds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"role":"admin","msg":"Logged in as user admin with role admin"}`))
	}))
	defer srv.Close()

	_, port := serverAddr(t, srv)
	res := runValidate(t, "nosqli.auth_bypass", buildNoSQLiJob(t, port, "Logged in as user"), nosqliEnv(t, srv))
	if res.Verdict != verdict.NotReproduced {
		t.Fatalf("verdict = %q, want not_reproduced (control also authenticates)", res.Verdict)
	}
}
