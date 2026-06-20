package validators

import "time"

// WallClock is a Clock backed by time.Now.
type WallClock struct{}

func (WallClock) Now() time.Time                  { return time.Now() }
func (WallClock) Since(t time.Time) time.Duration { return time.Since(t) }
