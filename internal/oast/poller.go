package oast

import (
	"context"
	"time"
)

// Poll drives the polling loop for one token, returning callbacks observed
// since the given time. Source attribution and proof evaluation live in the
// consuming validators.
//
// TODO: implement the poll window, backoff, and token lifecycle.
func Poll(context.Context, OAST, string, time.Time) ([]Interaction, error) {
	return nil, ErrNotImplemented
}
