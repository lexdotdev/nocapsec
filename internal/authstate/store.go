// Package authstate stores credentials
// AES-256-GCM at rest.
package authstate

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

var (
	ErrNotFound = errors.New("authstate: not found")
	ErrExpired  = errors.New("authstate: expired")
	ErrDecrypt  = errors.New("authstate: decryption failed")
)

// Healthcheck probes that a session is still valid.
type Healthcheck struct {
	Method               string `json:"method"`
	URL                  string `json:"url"`
	ExpectedStatus       int    `json:"expected_status"`
	ExpectedBodyContains string `json:"expected_body_contains"`
}

// AuthState is non-secret metadata;
// secrets in encrypted blob.
type AuthState struct {
	ID             string      `json:"id"`
	Kind           string      `json:"kind"`
	AllowedOrigins []string    `json:"allowed_origins"`
	Role           string      `json:"role"`
	ExpiresAt      time.Time   `json:"expires_at"`
	Contains       []string    `json:"contains"`
	Healthcheck    Healthcheck `json:"healthcheck"`
}

// Credentials holds secrets, encrypted at rest.
type Credentials struct {
	Cookies []Cookie          `json:"cookies,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Cookie is one cookie entry for injection.
type Cookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

// Store looks up auth state and credentials by ID.
type Store interface {
	Get(ctx context.Context, id string) (*AuthState, error)
	GetCredentials(ctx context.Context, id string) (*Credentials, error)
	Put(ctx context.Context, state *AuthState, creds *Credentials) error
}

// Clock abstracts time for expiry.
type Clock interface {
	Now() time.Time
}

// wallClock is the real clock.
type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// encryptedStore: in-memory, AES-256-GCM at rest.
type encryptedStore struct {
	gcm   cipher.AEAD
	clock Clock

	mu     sync.RWMutex
	states map[string]*AuthState // id -> state (not secret)
	blobs  map[string][]byte     // id -> encrypted credentials
}

// NewStore returns an encrypted store;
// key 32 bytes (AES-256).
func NewStore(key []byte, clock Clock) (Store, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if clock == nil {
		clock = wallClock{}
	}
	return &encryptedStore{
		gcm:    gcm,
		clock:  clock,
		states: map[string]*AuthState{},
		blobs:  map[string][]byte{},
	}, nil
}

// lookupState returns state for id, checks expiry.
func (s *encryptedStore) lookupState(id string) (*AuthState, error) {
	st, ok := s.states[id]
	if !ok {
		return nil, ErrNotFound
	}
	if !st.ExpiresAt.IsZero() && s.clock.Now().After(st.ExpiresAt) {
		return nil, ErrExpired
	}
	return st, nil
}

func (s *encryptedStore) Get(_ context.Context, id string) (*AuthState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, err := s.lookupState(id)
	if err != nil {
		return nil, err
	}
	cp := *st
	return &cp, nil
}

func (s *encryptedStore) GetCredentials(_ context.Context, id string) (*Credentials, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, err := s.lookupState(id); err != nil {
		return nil, err
	}
	blob, ok := s.blobs[id]
	if !ok {
		return nil, ErrNotFound
	}
	plain, err := s.decrypt(blob)
	if err != nil {
		return nil, ErrDecrypt
	}
	var creds Credentials
	if err := json.Unmarshal(plain, &creds); err != nil {
		return nil, ErrDecrypt
	}
	return &creds, nil
}

func (s *encryptedStore) Put(_ context.Context, state *AuthState, creds *Credentials) error {
	plain, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	enc, err := s.encrypt(plain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state.ID] = state
	s.blobs[state.ID] = enc
	return nil
}

func (s *encryptedStore) encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, s.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return s.gcm.Seal(nonce, nonce, plain, nil), nil
}

func (s *encryptedStore) decrypt(blob []byte) ([]byte, error) {
	ns := s.gcm.NonceSize()
	if len(blob) < ns {
		return nil, ErrDecrypt
	}
	return s.gcm.Open(nil, blob[:ns], blob[ns:], nil)
}
