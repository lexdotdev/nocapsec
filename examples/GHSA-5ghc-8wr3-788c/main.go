// Example GHSA-5ghc-8wr3-788c: IDOR read in RomM's collections API.
//
// idor.read needs two distinct authenticated sessions. RomM issues short-lived
// bearer tokens, so this harness bootstraps the two users and mints their tokens
// at run time, writes them into a temp auth-state file (the same shape as the
// nocapsec -authstate flag), and then runs the verification. The engine has the
// owner create a private collection and the attacker read it by id.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/lexdotdev/nocapsec/examples/exampleutil"
)

const base = "http://127.0.0.1:8001"

func main() {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		log.Fatal("resolve example path")
	}
	dir := filepath.Dir(file)

	ownerTok, attackerTok, err := setupSessions()
	if err != nil {
		log.Fatalf("setup sessions: %v", err)
	}

	authFile, cleanup, err := writeAuthState(ownerTok, attackerTok)
	if err != nil {
		log.Fatalf("write auth state: %v", err)
	}
	defer cleanup()

	err = exampleutil.Run(context.Background(), dir, exampleutil.Options{
		InternalAssessment: true,
		AuthStateFile:      authFile,
		Timeout:            30 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
}

// setupSessions bootstraps the owner (first admin) and attacker (viewer) users —
// idempotently — and returns a collections token for each.
func setupSessions() (ownerTok, attackerTok string, err error) {
	// 1. Bootstrap the first admin (unauthenticated when zero admins exist).
	//    On a non-fresh instance this 403/400s; that's fine, the user exists.
	_ = createUser("", "owner", "owner@x.test", "OwnerPass123!", "admin")

	// 2. An admin-scoped owner token is needed to create the attacker.
	ownerAdmin, err := mintToken("owner", "OwnerPass123!", "users.write users.read collections.read collections.write me.read")
	if err != nil {
		return "", "", fmt.Errorf("owner admin token: %w", err)
	}
	_ = createUser(ownerAdmin, "attacker", "attacker@x.test", "AttackPass123!", "viewer")

	// 3. Scoped tokens for the two verification sessions.
	if ownerTok, err = mintToken("owner", "OwnerPass123!", "collections.read collections.write me.read"); err != nil {
		return "", "", fmt.Errorf("owner token: %w", err)
	}
	if attackerTok, err = mintToken("attacker", "AttackPass123!", "collections.read me.read"); err != nil {
		return "", "", fmt.Errorf("attacker token: %w", err)
	}
	return ownerTok, attackerTok, nil
}

func createUser(bearer, username, email, password, role string) error {
	body, _ := json.Marshal(map[string]string{
		"username": username, "email": email, "password": password, "role": role,
	})
	req, _ := http.NewRequest(http.MethodPost, base+"/api/users", bytes.NewReader(body))
	req.Header.Set("content-type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil // existence (4xx) is expected on re-runs
}

func mintToken(username, password, scope string) (string, error) {
	form := url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
		"scope":      {scope},
	}
	resp, err := http.PostForm(base+"/api/token", form)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("empty access token")
	}
	return out.AccessToken, nil
}

// writeAuthState emits a temp -authstate file binding the two bearer tokens to
// the owner-session / attacker-session ids referenced by evidence.json.
func writeAuthState(ownerTok, attackerTok string) (path string, cleanup func(), err error) {
	type state struct {
		ID             string   `json:"id"`
		Kind           string   `json:"kind"`
		AllowedOrigins []string `json:"allowed_origins"`
		Role           string   `json:"role"`
	}
	type creds struct {
		Headers map[string]string `json:"headers"`
	}
	type entry struct {
		State       state `json:"state"`
		Credentials creds `json:"credentials"`
	}
	origins := []string{base}
	entries := []entry{
		{state{"owner-session", "http_bearer", origins, "admin"}, creds{map[string]string{"Authorization": "Bearer " + ownerTok}}},
		{state{"attacker-session", "http_bearer", origins, "viewer"}, creds{map[string]string{"Authorization": "Bearer " + attackerTok}}},
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", nil, err
	}
	f, err := os.CreateTemp("", "romm-authstate-*.json")
	if err != nil {
		return "", nil, err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return "", nil, err
	}
	_ = f.Close()
	return f.Name(), func() { _ = os.Remove(f.Name()) }, nil
}
