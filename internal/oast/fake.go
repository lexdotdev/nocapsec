package oast

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Fake is an in-process backend.
type Fake struct {
	clock  Clock
	domain string

	mu           sync.Mutex
	tokens       map[string]*OASTToken
	interactions map[string][]Interaction // by correlationID
	nextID       int
	closed       map[string]bool
}

// NewFake builds a fake backend.
func NewFake(clock Clock, domain string) *Fake {
	return &Fake{
		clock:        clock,
		domain:       domain,
		tokens:       make(map[string]*OASTToken),
		interactions: make(map[string][]Interaction),
		closed:       make(map[string]bool),
	}
}

func (f *Fake) NewInteraction(_ context.Context, purpose string) (*OASTToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.nextID++
	corrID := fmt.Sprintf("fake-%04d", f.nextID)
	now := f.clock.Now()
	ttl := tokenTTL(purpose)
	tok := &OASTToken{
		CorrelationID:     corrID,
		Domain:            corrID + "." + f.domain,
		URLHTTP:           "http://" + corrID + "." + f.domain,
		URLHTTPS:          "https://" + corrID + "." + f.domain,
		URLRedirect:       "http://" + corrID + "." + f.domain + "/r",
		Purpose:           purpose,
		ExpectedProtocols: expectedProtocols(purpose),
		CreatedAt:         now,
		ExpiresAt:         now.Add(ttl),
	}
	f.tokens[corrID] = tok
	return tok, nil
}

func (f *Fake) Poll(_ context.Context, tokenID string, since time.Time) ([]Interaction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.closed[tokenID] {
		return nil, ErrTokenUnknown
	}
	if _, ok := f.tokens[tokenID]; !ok {
		return nil, ErrTokenUnknown
	}

	var result []Interaction
	for _, ix := range f.interactions[tokenID] {
		if !ix.Timestamp.Before(since) {
			result = append(result, ix)
		}
	}
	return result, nil
}

func (f *Fake) Close(_ context.Context, tokenID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if _, ok := f.tokens[tokenID]; !ok {
		return ErrTokenUnknown
	}
	f.closed[tokenID] = true
	delete(f.tokens, tokenID)
	delete(f.interactions, tokenID)
	return nil
}

// AddInteraction injects a callback for tests.
func (f *Fake) AddInteraction(tokenID string, ix Interaction) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ix.CorrelationID = tokenID
	f.interactions[tokenID] = append(f.interactions[tokenID], ix)
}
