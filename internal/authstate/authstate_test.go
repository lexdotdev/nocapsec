package authstate

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http/cookiejar"
	"testing"
	"time"
)

// testKey returns an AES-256 key.
func testKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

func TestEncryptedStoreCopiesState(t *testing.T) {
	store, err := NewStore(testKey(), nil)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	state := &AuthState{
		ID:             "as-copy",
		AllowedOrigins: []string{"https://app.example.com"},
		Contains:       []string{"cookies"},
	}
	if err := store.Put(context.Background(), state, &Credentials{}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	state.AllowedOrigins[0] = "https://evil.example.com"
	state.Contains[0] = "headers"

	got, err := store.Get(context.Background(), "as-copy")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	got.AllowedOrigins[0] = "https://mutated.example.com"
	got.Contains[0] = "localStorage"

	again, err := store.Get(context.Background(), "as-copy")
	if err != nil {
		t.Fatalf("Get again: %v", err)
	}
	if again.AllowedOrigins[0] != "https://app.example.com" {
		t.Fatalf("AllowedOrigins aliased: %v", again.AllowedOrigins)
	}
	if again.Contains[0] != "cookies" {
		t.Fatalf("Contains aliased: %v", again.Contains)
	}
}

type fakeClock struct{ now time.Time }

func (c fakeClock) Now() time.Time { return c.now }

func TestEncryptedStorePutGet(t *testing.T) {
	clock := fakeClock{now: time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)}
	store, err := NewStore(testKey(), clock)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	state := &AuthState{
		ID:             "as-1",
		Kind:           "http_cookie_jar",
		AllowedOrigins: []string{"https://app.example.com"},
		Role:           "user",
		ExpiresAt:      time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC),
		Contains:       []string{"cookies"},
	}
	creds := &Credentials{
		Cookies: []Cookie{{Name: "session", Value: "secret123", Domain: "app.example.com", Path: "/"}},
		Headers: map[string]string{"Authorization": "Bearer tok"},
	}

	if err := store.Put(context.Background(), state, creds); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Get(context.Background(), "as-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "as-1" || got.Role != "user" {
		t.Fatalf("state mismatch: %+v", got)
	}

	gotCreds, err := store.GetCredentials(context.Background(), "as-1")
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if len(gotCreds.Cookies) != 1 || gotCreds.Cookies[0].Value != "secret123" {
		t.Fatalf("credentials mismatch: %+v", gotCreds)
	}
	if gotCreds.Headers["Authorization"] != "Bearer tok" {
		t.Fatalf("headers mismatch: %+v", gotCreds.Headers)
	}
}

func TestEncryptedStoreExpired(t *testing.T) {
	clock := fakeClock{now: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)}
	store, err := NewStore(testKey(), clock)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	state := &AuthState{
		ID:             "as-expired",
		AllowedOrigins: []string{"https://app.example.com"},
		ExpiresAt:      time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
	}
	creds := &Credentials{}
	if err := store.Put(context.Background(), state, creds); err != nil {
		t.Fatalf("Put: %v", err)
	}

	_, err = store.Get(context.Background(), "as-expired")
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}

	_, err = store.GetCredentials(context.Background(), "as-expired")
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("GetCredentials: expected ErrExpired, got %v", err)
	}
}

func TestEncryptedStoreNotFound(t *testing.T) {
	store, err := NewStore(testKey(), nil)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	_, err = store.Get(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestEncryptedStoreWrongKeyFails(t *testing.T) {
	key1 := testKey()
	key2 := testKey()

	store1, _ := NewStore(key1, nil)
	store2, _ := NewStore(key2, nil)

	state := &AuthState{ID: "as-cross", AllowedOrigins: []string{"https://x.com"}}
	creds := &Credentials{Headers: map[string]string{"X": "Y"}}
	if err := store1.Put(context.Background(), state, creds); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Manually copy encrypted blob to the other store.
	s1, ok := store1.(*encryptedStore)
	if !ok {
		t.Fatal("unexpected store type")
	}
	s2, ok := store2.(*encryptedStore)
	if !ok {
		t.Fatal("unexpected store type")
	}
	s1.mu.RLock()
	s2.mu.Lock()
	s2.states["as-cross"] = s1.states["as-cross"]
	s2.blobs["as-cross"] = s1.blobs["as-cross"]
	s2.mu.Unlock()
	s1.mu.RUnlock()

	_, err := store2.GetCredentials(context.Background(), "as-cross")
	if !errors.Is(err, ErrDecrypt) {
		t.Fatalf("expected ErrDecrypt, got %v", err)
	}
}

func TestInjectHeadersAllowedOrigin(t *testing.T) {
	state := &AuthState{
		ID:             "as-h1",
		AllowedOrigins: []string{"https://app.example.com"},
	}
	creds := &Credentials{
		Headers: map[string]string{"Authorization": "Bearer tok"},
	}

	headers, err := InjectHeaders(state, creds, "https://app.example.com")
	if err != nil {
		t.Fatalf("InjectHeaders: %v", err)
	}
	if headers["Authorization"] != "Bearer tok" {
		t.Fatalf("header mismatch: %v", headers)
	}
}

func TestInjectHeadersRefusedOrigin(t *testing.T) {
	state := &AuthState{
		ID:             "as-h2",
		AllowedOrigins: []string{"https://app.example.com"},
	}
	creds := &Credentials{
		Headers: map[string]string{"Authorization": "Bearer tok"},
	}

	_, err := InjectHeaders(state, creds, "https://evil.com")
	if !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("expected ErrOriginNotAllowed, got %v", err)
	}
}

func TestInjectCookieJarAllowedOrigin(t *testing.T) {
	state := &AuthState{
		ID:             "as-c1",
		AllowedOrigins: []string{"https://app.example.com"},
	}
	creds := &Credentials{
		Cookies: []Cookie{{Name: "sess", Value: "val", Domain: "app.example.com", Path: "/"}},
	}

	jar, _ := cookiejar.New(nil)
	if err := InjectCookieJar(state, creds, jar, "https://app.example.com"); err != nil {
		t.Fatalf("InjectCookieJar: %v", err)
	}
}

func TestInjectCookieJarRefusedOrigin(t *testing.T) {
	state := &AuthState{
		ID:             "as-c2",
		AllowedOrigins: []string{"https://app.example.com"},
	}
	creds := &Credentials{
		Cookies: []Cookie{{Name: "sess", Value: "val"}},
	}

	jar, _ := cookiejar.New(nil)
	err := InjectCookieJar(state, creds, jar, "https://evil.com")
	if !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("expected ErrOriginNotAllowed, got %v", err)
	}
}

func TestInjectHeadersPortMismatch(t *testing.T) {
	state := &AuthState{
		ID:             "as-port",
		AllowedOrigins: []string{"https://app.example.com:8443"},
	}
	creds := &Credentials{Headers: map[string]string{"X": "Y"}}

	_, err := InjectHeaders(state, creds, "https://app.example.com")
	if !errors.Is(err, ErrOriginNotAllowed) {
		t.Fatalf("expected ErrOriginNotAllowed for port mismatch, got %v", err)
	}
}
